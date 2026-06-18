// Package auth implements the core authentication logic including user registration,
// login verification, session management, account lockout policies, and audit logging.
//
// Security measures implemented:
//   - Constant-time password comparison to prevent timing attacks
//   - Atomic registration to prevent race conditions
//   - Encrypted TOTP secrets at rest (AES-256-GCM)
//   - Audit logging for all security-relevant events
//   - Context-aware database operations with timeouts
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/srijan-verma/auth-cli/internal/config"
	database "github.com/srijan-verma/auth-cli/internal/database"
	"github.com/srijan-verma/auth-cli/internal/models"
)

// Common errors returned by the auth service.
var (
	ErrUserExists         = errors.New("username already exists")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is locked due to too many failed attempts")
	ErrSessionExpired     = errors.New("session has expired")
	ErrSessionNotFound    = errors.New("session not found")
	ErrUserNotFound       = errors.New("user not found")
	ErrTOTPRequired       = errors.New("TOTP verification required")
	ErrInvalidTOTP        = errors.New("invalid TOTP code")
	ErrTOTPAlreadyEnabled = errors.New("2FA is already enabled")
	ErrTOTPNotEnabled     = errors.New("2FA is not enabled")
)

// defaultQueryTimeout is the timeout for individual database queries.
const defaultQueryTimeout=10*time.Second

// Service provides authentication operations backed by a PostgreSQL database.
type Service struct {
	db             *sql.DB //for database conncetion 
	cfg            *config.Config//for configurations like bcrypt cost,session timeout,lockout duration,max failed attempts,ect
	passwordPolicy *models.PasswordPolicy//password rrles
}

// NewService creates a new authentication service instance.
func NewService(db *sql.DB, cfg *config.Config) *Service{
	return &Service{
		db:  db,
		cfg: cfg,
		passwordPolicy: &models.PasswordPolicy{
			MinLength:      cfg.MinPasswordLength,
			MaxLength:      cfg.MaxPasswordLength,
			RequireUpper:   cfg.RequireUppercase,
			RequireLower:   cfg.RequireLowercase,
			RequireDigit:   cfg.RequireDigit,
			RequireSpecial: cfg.RequireSpecial,
		},
	}
}

// GetPasswordPolicy returns the current password policy for UI display.
func (s *Service)GetPasswordPolicy() *models.PasswordPolicy{
	return s.passwordPolicy
}

// Register creates a new user account with a bcrypt-hashed password.
// Uses INSERT ... ON CONFLICT to atomically prevent duplicate usernames
// (eliminates the SELECT-then-INSERT race condition).
func (s *Service)Register(username, password string) error{
	// Validate username format
	if msg:=models.ValidateUsername(username);msg!=""{
		return fmt.Errorf("%s",msg)
	}

	// Validate password against policy
	if msg := s.passwordPolicy.ValidatePassword(password); msg != "" {
		return fmt.Errorf("%s", msg)
	}

	// Hash password with configurable bcrypt cost
	hash,err:=bcrypt.GenerateFromPassword([]byte(password), s.cfg.BcryptCost)
	if err!=nil{
		return fmt.Errorf("failed to hash password: %w", err)
	}
	//Go ka context package ka sbse common use-case
	//means this operation can run atmax this time, and if it goes beyond that simply do cancel it
	ctx,cancel := context.WithTimeout(context.Background(),defaultQueryTimeout)
	defer cancel()

	// Atomic insert — ON CONFLICT returns 0 affected rows instead of an error
	result,err:=s.db.ExecContext(ctx,
		"INSERT INTO users (username, password_hash) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING",
		username,string(hash),
	)
	/*
	Why Atomic insert is important here?

	->Look if 100, or maybe 10000, or basiclly more than 1 ppl do register simultaneously with 
	same username then at that time 
	SELECT INSERT will give us race condition

	kaise race condition hoga:
	 THREAD A: SELECT chalaya, koi row nahi mili
	 THREAD B: SELECT chalaya, koi row nahi mili
	now,both will think that okay so username is free so both will create 
	since UNIQUE constraint is not on username, so this will cause duplicate contraint
	if we have UNIQUE constaint then first process will succeed,while 2nd one will throw error

	that's why using SELECT+INSERT on application level is unsafe

	but this 
	INSERT ON CONFLICT is atomic
	Yahan database internally:
                            UNIQUE index check karta hai
                            Insert attempt karta hai
                            Conflict hua to handle karta hai
	ye single atomic operation hai

	so even if 10000 concurrent request do came for Signup then,
	only 1 row will be created


	In most simple word: Database will handle concurrency on its own.
	*/
	if err!=nil{
		return fmt.Errorf("failed to create user: %w", err)
	}

	rowsAffected,_:=result.RowsAffected() //checking that rows is affected or not 
	if rowsAffected==0{
		return ErrUserExists
	}
	database.LogAuditEvent(s.db,nil,"register", "New user registered: "+username)
	slog.Info("User registered successfully", "username", username)
	return nil
}

// Login authenticates a user with username and password.
// Returns the user and a flag indicating if TOTP verification is still needed.
//
// Security: performs a dummy bcrypt comparison for nonexistent users to prevent
// timing-based username enumeration attacks.
func (s *Service) Login(username, password string) (*models.User, bool, error) {
	user,err:=s.getUserByUsername(username)
	if err!=nil{
		if errors.Is(err, ErrUserNotFound) {
			// Perform a dummy bcrypt comparison to prevent timing attacks.
			// Without this, an attacker could distinguish "user doesn't exist"
			// (fast return) from "wrong password" (slow bcrypt comparison).
			dummyHash := "$2a$12$LJ3m4ys3Lg2VBe5E/Y5HpOxfBGNI1sM7VG8.fA5MybKV9l4PmFVKa"
			bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
			database.LogAuditEvent(s.db, nil, "login_failed", "Unknown user: "+username)
			return nil, false, ErrInvalidCredentials
		}
		return nil, false, err
	}

	// Check if account is locked
	if user.IsLocked() {
		remaining := time.Until(*user.LockedUntil).Round(time.Second)
		database.LogAuditEvent(s.db, &user.ID, "login_blocked", "Account locked")
		return nil, false, fmt.Errorf("%w: try again in %s", ErrAccountLocked, remaining)
	}

	// Verify password against bcrypt hash
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		s.recordFailedAttempt(user)
		database.LogAuditEvent(s.db, &user.ID, "login_failed", "Wrong password")
		return nil, false, ErrInvalidCredentials
	}

	// If TOTP is enabled, signal that verification is still needed
	// (do NOT complete login yet — wait for 2FA)
	if user.TOTPEnabled {
		return user, true, nil
	}

	// Password correct and no TOTP required — complete the login
	if err := s.completeLogin(user); err != nil {
		return nil, false, err
	}

	return user, false, nil
}

// VerifyTOTPAndLogin completes login after successful TOTP verification.
func (s *Service) VerifyTOTPAndLogin(user *models.User, code string) error {
	// Decrypt the stored TOTP secret before validation
	secret, err := DecryptTOTPSecret(user.TOTPSecret, s.cfg.TOTPEncryptionKey)
	if err != nil {
		slog.Error("Failed to decrypt TOTP secret", "user_id", user.ID, "error", err)
		return fmt.Errorf("internal error during 2FA verification")
	}

	if !ValidateTOTP(secret, code) {
		s.recordFailedAttempt(user)
		database.LogAuditEvent(s.db, &user.ID, "totp_failed", "Invalid TOTP code during login")
		return ErrInvalidTOTP
	}

	return s.completeLogin(user)
}

// CreateSession generates a new session token for the authenticated user.
// Invalidates any existing sessions for the same user (single active session policy).
func (s *Service) CreateSession(userID int) (*models.Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultQueryTimeout)
	defer cancel()

	// Invalidate existing sessions for this user (enforce single session)
	s.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = $1", userID)

	sessionID := uuid.New().String()
	expiresAt := time.Now().Add(s.cfg.SessionTimeout)

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)",
		sessionID, userID, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	database.LogAuditEvent(s.db, &userID, "session_created", "New session: "+sessionID[:8]+"...")
	return &models.Session{
		ID:        sessionID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}, nil
}

// ValidateSession checks if a session token is valid and not expired.
// Returns the associated user if the session is valid.
func (s *Service) ValidateSession(sessionID string) (*models.User, *models.Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultQueryTimeout)
	defer cancel()

	var session models.Session
	err := s.db.QueryRowContext(ctx,
		"SELECT id, user_id, expires_at, created_at FROM sessions WHERE id = $1",
		sessionID,
	).Scan(&session.ID, &session.UserID, &session.ExpiresAt, &session.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrSessionNotFound
		}
		return nil, nil, fmt.Errorf("database error: %w", err)
	}

	if session.IsExpired() {
		s.DestroySession(sessionID)
		return nil, nil, ErrSessionExpired
	}

	user, err := s.getUserByID(session.UserID)
	if err != nil {
		return nil, nil, err
	}

	return user, &session, nil
}

// DestroySession removes a session from the database (logout).
func (s *Service) DestroySession(sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultQueryTimeout)
	defer cancel()
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = $1", sessionID)
	return err
}

// GetUser retrieves a user by ID (refreshes from DB).
func (s *Service) GetUser(userID int) (*models.User, error) {
	return s.getUserByID(userID)
}

// ChangePassword updates the user's password after verifying the current one.
func (s *Service) ChangePassword(userID int, currentPassword, newPassword string) error {
	user, err := s.getUserByID(userID)
	if err != nil {
		return err
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
		database.LogAuditEvent(s.db, &userID, "password_change_failed", "Wrong current password")
		return ErrInvalidCredentials
	}

	// Validate new password against policy
	if msg := s.passwordPolicy.ValidatePassword(newPassword); msg != "" {
		return fmt.Errorf("%s", msg)
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.cfg.BcryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultQueryTimeout)
	defer cancel()

	_, err = s.db.ExecContext(ctx,
		"UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
		string(hash), userID,
	)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	database.LogAuditEvent(s.db, &userID, "password_changed", "Password changed successfully")
	slog.Info("Password changed", "user_id", userID)
	return nil
}

// EnableTOTP generates a new TOTP secret for the user.
// The secret is NOT stored until ConfirmTOTP is called with a valid code.
func (s *Service) EnableTOTP(userID int) (string, error) {
	user, err := s.getUserByID(userID)
	if err != nil {
		return "", err
	}

	if user.TOTPEnabled {
		return "", ErrTOTPAlreadyEnabled
	}

	secret, err := GenerateTOTPSecret(user.Username)
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	return secret, nil
}

// ConfirmTOTP verifies a TOTP code and activates 2FA for the user.
// The secret is encrypted with AES-256-GCM before being stored in the database.
func (s *Service) ConfirmTOTP(userID int, secret, code string) error {
	if !ValidateTOTP(secret, code) {
		return ErrInvalidTOTP
	}

	// Encrypt the secret before storing
	encrypted, err := EncryptTOTPSecret(secret, s.cfg.TOTPEncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultQueryTimeout)
	defer cancel()

	_, err = s.db.ExecContext(ctx,
		"UPDATE users SET totp_secret = $1, totp_enabled = TRUE, updated_at = NOW() WHERE id = $2",
		encrypted, userID,
	)
	if err != nil {
		return fmt.Errorf("failed to enable 2FA: %w", err)
	}

	database.LogAuditEvent(s.db, &userID, "2fa_enabled", "TOTP 2FA enabled")
	slog.Info("2FA enabled", "user_id", userID)
	return nil
}

// DisableTOTP removes the TOTP secret and disables 2FA for the user.
// Requires a valid TOTP code as a security measure.
func (s *Service) DisableTOTP(userID int, code string) error {
	user, err := s.getUserByID(userID)
	if err != nil {
		return err
	}

	if !user.TOTPEnabled {
		return ErrTOTPNotEnabled
	}

	// Decrypt the stored secret for validation
	secret, err := DecryptTOTPSecret(user.TOTPSecret, s.cfg.TOTPEncryptionKey)
	if err != nil {
		return fmt.Errorf("internal error during 2FA verification")
	}

	if !ValidateTOTP(secret, code) {
		return ErrInvalidTOTP
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultQueryTimeout)
	defer cancel()

	_, err = s.db.ExecContext(ctx,
		"UPDATE users SET totp_secret = '', totp_enabled = FALSE, updated_at = NOW() WHERE id = $1",
		userID,
	)
	if err != nil {
		return fmt.Errorf("failed to disable 2FA: %w", err)
	}

	database.LogAuditEvent(s.db, &userID, "2fa_disabled", "TOTP 2FA disabled")
	slog.Info("2FA disabled", "user_id", userID)
	return nil
}

// completeLogin resets failed attempts, updates last_login, and records a successful login.
func (s *Service) completeLogin(user *models.User) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultQueryTimeout)
	defer cancel()

	_, err := s.db.ExecContext(ctx,
		"UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = NOW(), updated_at = NOW() WHERE id = $1",
		user.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update login state: %w", err)
	}

	now := time.Now()
	user.LastLogin = &now
	user.FailedAttempts = 0
	user.LockedUntil = nil

	database.LogAuditEvent(s.db, &user.ID, "login_success", "Successful login")
	slog.Info("User logged in", "username", user.Username)
	return nil
}

// recordFailedAttempt increments the failed attempt counter and locks the account
// if the threshold is reached. Logs the event for audit purposes.
func (s *Service) recordFailedAttempt(user *models.User) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultQueryTimeout)
	defer cancel()

	user.FailedAttempts++
	remaining := s.cfg.MaxFailedAttempts - user.FailedAttempts

	if user.FailedAttempts >= s.cfg.MaxFailedAttempts {
		lockUntil := time.Now().Add(s.cfg.LockoutDuration)
		s.db.ExecContext(ctx,
			"UPDATE users SET failed_attempts = $1, locked_until = $2, updated_at = NOW() WHERE id = $3",
			user.FailedAttempts, lockUntil, user.ID,
		)
		database.LogAuditEvent(s.db, &user.ID, "account_locked",
			fmt.Sprintf("Account locked after %d failed attempts", user.FailedAttempts))
		slog.Warn("Account locked", "username", user.Username, "failed_attempts", user.FailedAttempts)
	} else {
		s.db.ExecContext(ctx,
			"UPDATE users SET failed_attempts = $1, updated_at = NOW() WHERE id = $2",
			user.FailedAttempts, user.ID,
		)
		slog.Warn("Failed login attempt",
			"username", user.Username,
			"failed_attempts", user.FailedAttempts,
			"remaining_before_lockout", remaining,
		)
	}
}

// getUserByUsername retrieves a user by their username.
func (s *Service) getUserByUsername(username string) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultQueryTimeout)
	defer cancel()

	user := &models.User{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, totp_secret, totp_enabled, 
		        failed_attempts, locked_until, last_login, created_at, updated_at 
		 FROM users WHERE username = $1`, username,
	).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.TOTPSecret,
		&user.TOTPEnabled, &user.FailedAttempts, &user.LockedUntil,
		&user.LastLogin, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("database error: %w", err)
	}
	return user, nil
}

// getUserByID retrieves a user by their numeric ID.
func (s *Service) getUserByID(id int) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultQueryTimeout)
	defer cancel()

	user := &models.User{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, totp_secret, totp_enabled, 
		        failed_attempts, locked_until, last_login, created_at, updated_at 
		 FROM users WHERE id = $1`, id,
	).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.TOTPSecret,
		&user.TOTPEnabled, &user.FailedAttempts, &user.LockedUntil,
		&user.LastLogin, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("database error: %w", err)
	}
	return user, nil
}
