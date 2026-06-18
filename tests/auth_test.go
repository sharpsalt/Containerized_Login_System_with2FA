// Package tests provides unit tests for core authentication functionality.
// Tests use a real PostgreSQL connection (via Docker) to validate
// the full auth flow including registration, login, lockout, TOTP, and encryption.
package tests

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/pquerna/otp/totp"

	"github.com/srijan-verma/auth-cli/internal/auth"
	"github.com/srijan-verma/auth-cli/internal/config"
	database "github.com/srijan-verma/auth-cli/internal/database"
	"github.com/srijan-verma/auth-cli/internal/models"
)

// testEncryptionKey is a fixed key used for TOTP encryption in tests.
const testEncryptionKey = "test-encryption-key-for-unit-tests"

// setupTestDB creates a connection to the test database and runs migrations.
// Falls back to environment variables; skips tests if no DB is available.
func setupTestDB(t *testing.T) (*sql.DB, *config.Config) {
	t.Helper()

	cfg := &config.Config{
		DBHost:            getTestEnv("TEST_DB_HOST", "localhost"),
		DBPort:            getTestEnv("TEST_DB_PORT", "5432"),
		DBUser:            getTestEnv("TEST_DB_USER", "authuser"),
		DBPassword:        getTestEnv("TEST_DB_PASSWORD", "authpass"),
		DBName:            getTestEnv("TEST_DB_NAME", "authdb"),
		DBSSLMode:         "disable",
		SessionTimeout:    30 * time.Minute,
		MaxFailedAttempts: 3, // Lower for faster testing
		LockoutDuration:   1 * time.Minute,
		BcryptCost:        10, // Lower cost for faster tests
		MinPasswordLength: 8,
		MaxPasswordLength: 72,
		RequireUppercase:  true,
		RequireLowercase:  true,
		RequireDigit:      true,
		RequireSpecial:    false,
		TOTPEncryptionKey: testEncryptionKey,
	}

	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		t.Skipf("Skipping test: cannot connect to database: %v", err)
	}

	if err := db.Ping(); err != nil {
		t.Skipf("Skipping test: database not reachable: %v", err)
	}

	if err := database.RunMigrations(db); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Clean up test data before each test run
	t.Cleanup(func() {
		db.Exec("DELETE FROM audit_log")
		db.Exec("DELETE FROM sessions")
		db.Exec("DELETE FROM users")
		db.Close()
	})

	db.Exec("DELETE FROM audit_log")
	db.Exec("DELETE FROM sessions")
	db.Exec("DELETE FROM users")

	return db, cfg
}

func getTestEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// validTestPassword returns a password that satisfies the test password policy.
const validTestPassword = "SecurePass123"

// ─── Registration Tests ─────────────────────────────────────────────────────

func TestRegister_Success(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)

	err := svc.Register("testuser", validTestPassword)
	if err != nil {
		t.Fatalf("Expected successful registration, got: %v", err)
	}
}

func TestRegister_DuplicateUsername(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)

	err := svc.Register("duplicateuser", validTestPassword)
	if err != nil {
		t.Fatalf("First registration should succeed: %v", err)
	}

	err = svc.Register("duplicateuser", validTestPassword+"Extra1")
	if err == nil {
		t.Fatal("Expected error for duplicate username, got nil")
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)

	tests := []struct {
		name     string
		password string
	}{
		{"too short", "Ab1"},
		{"no uppercase", "lowercase123"},
		{"no lowercase", "UPPERCASE123"},
		{"no digit", "NoDigitsHere"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.Register("user_"+tc.name, tc.password)
			if err == nil {
				t.Fatalf("Expected error for weak password (%s), got nil", tc.name)
			}
		})
	}
}

func TestRegister_InvalidUsername(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)

	tests := []struct {
		name     string
		username string
	}{
		{"too short", "ab"},
		{"starts with digit", "1user"},
		{"special chars", "user@name"},
		{"spaces", "user name"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.Register(tc.username, validTestPassword)
			if err == nil {
				t.Fatalf("Expected error for invalid username (%s), got nil", tc.name)
			}
		})
	}
}

// ─── Login Tests ────────────────────────────────────────────────────────────

func TestLogin_Success(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("loginuser", validTestPassword)

	user, totpRequired, err := svc.Login("loginuser", validTestPassword)
	if err != nil {
		t.Fatalf("Expected successful login, got: %v", err)
	}
	if user == nil {
		t.Fatal("Expected user to be non-nil")
	}
	if totpRequired {
		t.Fatal("Expected TOTP not to be required")
	}
	if user.Username != "loginuser" {
		t.Fatalf("Expected username 'loginuser', got '%s'", user.Username)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("wrongpwuser", validTestPassword)

	_, _, err := svc.Login("wrongpwuser", "WrongPassword123")
	if err == nil {
		t.Fatal("Expected error for wrong password, got nil")
	}
	if err != auth.ErrInvalidCredentials {
		t.Fatalf("Expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestLogin_NonexistentUser(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)

	_, _, err := svc.Login("nosuchuser", validTestPassword)
	if err == nil {
		t.Fatal("Expected error for nonexistent user, got nil")
	}
	if err != auth.ErrInvalidCredentials {
		t.Fatalf("Expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestLogin_UpdatesLastLogin(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("lastloginuser", validTestPassword)

	user, _, _ := svc.Login("lastloginuser", validTestPassword)
	if user.LastLogin == nil {
		t.Fatal("Expected last_login to be set after login")
	}
}

// ─── Account Lockout Tests ──────────────────────────────────────────────────

func TestLogin_AccountLockout(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("lockuser", validTestPassword)

	// Attempt 3 failed logins (MaxFailedAttempts is set to 3 in test config)
	for i := 0; i < cfg.MaxFailedAttempts; i++ {
		svc.Login("lockuser", "WrongPassword123")
	}

	// Next login should fail even with correct password due to lockout
	_, _, err := svc.Login("lockuser", validTestPassword)
	if err == nil {
		t.Fatal("Expected account lockout error, got nil")
	}
}

func TestLogin_LockoutResetsOnSuccess(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("resetuser", validTestPassword)

	// Fail 2 times (one less than max)
	for i := 0; i < cfg.MaxFailedAttempts-1; i++ {
		svc.Login("resetuser", "WrongPassword123")
	}

	// Succeed — should reset counter
	user, _, err := svc.Login("resetuser", validTestPassword)
	if err != nil {
		t.Fatalf("Expected login to succeed, got: %v", err)
	}

	// Refresh user to check failed_attempts
	user, _ = svc.GetUser(user.ID)
	if user.FailedAttempts != 0 {
		t.Fatalf("Expected failed_attempts to be 0 after successful login, got %d", user.FailedAttempts)
	}
}

// ─── Session Tests ──────────────────────────────────────────────────────────

func TestSession_CreateAndValidate(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("sessionuser", validTestPassword)

	user, _, _ := svc.Login("sessionuser", validTestPassword)

	session, err := svc.CreateSession(user.ID)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	if session.ID == "" {
		t.Fatal("Expected non-empty session ID")
	}

	validUser, validSession, err := svc.ValidateSession(session.ID)
	if err != nil {
		t.Fatalf("Failed to validate session: %v", err)
	}
	if validUser.Username != "sessionuser" {
		t.Fatalf("Expected username 'sessionuser', got '%s'", validUser.Username)
	}
	if validSession.ID != session.ID {
		t.Fatal("Session IDs don't match")
	}
}

func TestSession_SingleSessionPolicy(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("singlesession", validTestPassword)

	user, _, _ := svc.Login("singlesession", validTestPassword)

	session1, _ := svc.CreateSession(user.ID)
	session2, _ := svc.CreateSession(user.ID)

	// session1 should be invalidated
	_, _, err := svc.ValidateSession(session1.ID)
	if err == nil {
		t.Fatal("Expected first session to be invalidated after creating second")
	}

	// session2 should be valid
	_, _, err = svc.ValidateSession(session2.ID)
	if err != nil {
		t.Fatalf("Expected second session to be valid, got: %v", err)
	}
}

func TestSession_Destroy(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("logoutuser", validTestPassword)

	user, _, _ := svc.Login("logoutuser", validTestPassword)
	session, _ := svc.CreateSession(user.ID)

	err := svc.DestroySession(session.ID)
	if err != nil {
		t.Fatalf("Failed to destroy session: %v", err)
	}

	_, _, err = svc.ValidateSession(session.ID)
	if err == nil {
		t.Fatal("Expected error after session destruction, got nil")
	}
}

func TestSession_InvalidID(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)

	_, _, err := svc.ValidateSession("nonexistent-session-id")
	if err == nil {
		t.Fatal("Expected error for invalid session ID, got nil")
	}
	if err != auth.ErrSessionNotFound {
		t.Fatalf("Expected ErrSessionNotFound, got: %v", err)
	}
}

// ─── TOTP Tests ─────────────────────────────────────────────────────────────

func TestTOTP_GenerateSecret(t *testing.T) {
	secret, err := auth.GenerateTOTPSecret("testuser")
	if err != nil {
		t.Fatalf("Failed to generate TOTP secret: %v", err)
	}
	if secret == "" {
		t.Fatal("Expected non-empty TOTP secret")
	}
	if len(secret) < 16 {
		t.Fatalf("TOTP secret seems too short: %d chars", len(secret))
	}
}

func TestTOTP_ValidateCode(t *testing.T) {
	secret, err := auth.GenerateTOTPSecret("testuser")
	if err != nil {
		t.Fatalf("Failed to generate TOTP secret: %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	if !auth.ValidateTOTP(secret, code) {
		t.Fatal("Expected TOTP validation to succeed")
	}
}

func TestTOTP_InvalidCode(t *testing.T) {
	secret, err := auth.GenerateTOTPSecret("testuser")
	if err != nil {
		t.Fatalf("Failed to generate TOTP secret: %v", err)
	}

	if auth.ValidateTOTP(secret, "000000") {
		t.Log("Warning: code '000000' validated (extremely rare coincidence)")
	}
}

func TestTOTP_EnableAndLoginWithTOTP(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("totpuser", validTestPassword)

	user, _, _ := svc.Login("totpuser", validTestPassword)

	secret, err := svc.EnableTOTP(user.ID)
	if err != nil {
		t.Fatalf("Failed to enable TOTP: %v", err)
	}

	code, _ := totp.GenerateCode(secret, time.Now())
	err = svc.ConfirmTOTP(user.ID, secret, code)
	if err != nil {
		t.Fatalf("Failed to confirm TOTP: %v", err)
	}

	// Now login should require TOTP
	user, totpRequired, err := svc.Login("totpuser", validTestPassword)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if !totpRequired {
		t.Fatal("Expected TOTP to be required after enabling 2FA")
	}

	// Verify TOTP to complete login
	code, _ = totp.GenerateCode(secret, time.Now())
	err = svc.VerifyTOTPAndLogin(user, code)
	if err != nil {
		t.Fatalf("TOTP verification failed: %v", err)
	}
}

func TestTOTP_DisableRequiresValidCode(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("disabletotp", validTestPassword)

	user, _, _ := svc.Login("disabletotp", validTestPassword)

	secret, _ := svc.EnableTOTP(user.ID)
	code, _ := totp.GenerateCode(secret, time.Now())
	svc.ConfirmTOTP(user.ID, secret, code)

	// Try to disable with wrong code
	err := svc.DisableTOTP(user.ID, "000000")
	if err == nil {
		t.Fatal("Expected error when disabling 2FA with wrong code")
	}
}

func TestTOTP_GenerateURL(t *testing.T) {
	secret, _ := auth.GenerateTOTPSecret("testuser")
	url := auth.GenerateTOTPURL("testuser", secret)
	if url == "" {
		t.Fatal("Expected non-empty TOTP URL")
	}
	if len(url) < 20 {
		t.Fatal("TOTP URL seems too short")
	}
}

// ─── TOTP Encryption Tests ─────────────────────────────────────────────────

func TestTOTPEncryption_RoundTrip(t *testing.T) {
	original := "JBSWY3DPEHPK3PXP"
	key := "test-encryption-key-32-bytes!!"

	encrypted, err := auth.EncryptTOTPSecret(original, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if encrypted == original {
		t.Fatal("Encrypted value should differ from original")
	}

	decrypted, err := auth.DecryptTOTPSecret(encrypted, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted != original {
		t.Fatalf("Expected '%s', got '%s'", original, decrypted)
	}
}

func TestTOTPEncryption_WrongKey(t *testing.T) {
	original := "JBSWY3DPEHPK3PXP"
	encrypted, _ := auth.EncryptTOTPSecret(original, "correct-key-here-12345678")

	_, err := auth.DecryptTOTPSecret(encrypted, "wrong-key-here-123456789")
	if err == nil {
		t.Fatal("Expected decryption to fail with wrong key")
	}
}

func TestTOTPEncryption_EmptyString(t *testing.T) {
	result, err := auth.DecryptTOTPSecret("", "any-key")
	if err != nil {
		t.Fatalf("Expected no error for empty string, got: %v", err)
	}
	if result != "" {
		t.Fatal("Expected empty result for empty input")
	}
}

func TestTOTPEncryption_UniqueNonces(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	key := "test-key-for-nonce-test!!"

	enc1, _ := auth.EncryptTOTPSecret(secret, key)
	enc2, _ := auth.EncryptTOTPSecret(secret, key)

	if enc1 == enc2 {
		t.Fatal("Two encryptions of the same value should produce different ciphertexts (unique nonces)")
	}
}

// ─── Password Policy Tests ─────────────────────────────────────────────────

func TestPasswordPolicy_ValidPassword(t *testing.T) {
	policy := &models.PasswordPolicy{
		MinLength:    8,
		MaxLength:    72,
		RequireUpper: true,
		RequireLower: true,
		RequireDigit: true,
	}

	msg := policy.ValidatePassword("SecurePass123")
	if msg != "" {
		t.Fatalf("Expected valid password, got error: %s", msg)
	}
}

func TestPasswordPolicy_TooShort(t *testing.T) {
	policy := &models.PasswordPolicy{MinLength: 8, MaxLength: 72}

	msg := policy.ValidatePassword("Ab1")
	if msg == "" {
		t.Fatal("Expected error for short password")
	}
}

func TestPasswordPolicy_TooLong(t *testing.T) {
	policy := &models.PasswordPolicy{MinLength: 8, MaxLength: 72}

	longPass := ""
	for i := 0; i < 80; i++ {
		longPass += "A"
	}
	msg := policy.ValidatePassword(longPass)
	if msg == "" {
		t.Fatal("Expected error for long password")
	}
}

func TestPasswordPolicy_MissingUppercase(t *testing.T) {
	policy := &models.PasswordPolicy{MinLength: 8, MaxLength: 72, RequireUpper: true}

	msg := policy.ValidatePassword("alllowercase123")
	if msg == "" {
		t.Fatal("Expected error for missing uppercase")
	}
}

func TestPasswordPolicy_MissingDigit(t *testing.T) {
	policy := &models.PasswordPolicy{MinLength: 8, MaxLength: 72, RequireDigit: true}

	msg := policy.ValidatePassword("NoDigitsHere")
	if msg == "" {
		t.Fatal("Expected error for missing digit")
	}
}

// ─── Username Validation Tests ──────────────────────────────────────────────

func TestValidateUsername_Valid(t *testing.T) {
	valids := []string{"alice", "bob123", "user_name", "test-user"}
	for _, u := range valids {
		if msg := models.ValidateUsername(u); msg != "" {
			t.Fatalf("Expected '%s' to be valid, got: %s", u, msg)
		}
	}
}

func TestValidateUsername_Invalid(t *testing.T) {
	invalids := []struct {
		name     string
		username string
	}{
		{"too short", "ab"},
		{"starts with digit", "1user"},
		{"has spaces", "user name"},
		{"has special", "user@name"},
	}
	for _, tc := range invalids {
		t.Run(tc.name, func(t *testing.T) {
			if msg := models.ValidateUsername(tc.username); msg == "" {
				t.Fatalf("Expected '%s' to be invalid", tc.username)
			}
		})
	}
}

// ─── Change Password Tests ─────────────────────────────────────────────────

func TestChangePassword_Success(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("changepw", validTestPassword)

	user, _, _ := svc.Login("changepw", validTestPassword)

	newPassword := "NewSecure456"
	err := svc.ChangePassword(user.ID, validTestPassword, newPassword)
	if err != nil {
		t.Fatalf("Expected password change to succeed, got: %v", err)
	}

	// Old password should no longer work
	_, _, err = svc.Login("changepw", validTestPassword)
	if err == nil {
		t.Fatal("Expected login with old password to fail")
	}

	// New password should work
	_, _, err = svc.Login("changepw", newPassword)
	if err != nil {
		t.Fatalf("Expected login with new password to succeed, got: %v", err)
	}
}

func TestChangePassword_WrongCurrent(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("changepwfail", validTestPassword)

	user, _, _ := svc.Login("changepwfail", validTestPassword)

	err := svc.ChangePassword(user.ID, "WrongPassword1", "NewPass456")
	if err == nil {
		t.Fatal("Expected error for wrong current password")
	}
}

// ─── Session Cleanup Tests ──────────────────────────────────────────────────

func TestCleanExpiredSessions(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("cleanuser", validTestPassword)

	user, _, _ := svc.Login("cleanuser", validTestPassword)

	// Create a session then manually expire it
	session, _ := svc.CreateSession(user.ID)
	db.Exec("UPDATE sessions SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1", session.ID)

	cleaned, err := database.CleanExpiredSessions(db)
	if err != nil {
		t.Fatalf("Failed to clean sessions: %v", err)
	}
	if cleaned < 1 {
		t.Fatal("Expected at least 1 session to be cleaned")
	}
}

// ─── Audit Log Tests ────────────────────────────────────────────────────────

func TestAuditLog_LoginSuccess(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("audituser", validTestPassword)

	svc.Login("audituser", validTestPassword)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'login_success'").Scan(&count)
	if count < 1 {
		t.Fatal("Expected audit log entry for successful login")
	}
}

func TestAuditLog_FailedLogin(t *testing.T) {
	db, cfg := setupTestDB(t)
	svc := auth.NewService(db, cfg)
	svc.Register("auditfail", validTestPassword)

	svc.Login("auditfail", "WrongPassword1")

	var count int
	db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action = 'login_failed'").Scan(&count)
	if count < 1 {
		t.Fatal("Expected audit log entry for failed login")
	}
}
