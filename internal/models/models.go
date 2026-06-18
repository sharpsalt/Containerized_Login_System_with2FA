// Package models defines the core data structures used throughout the application.
// These structs map directly to database tables and are used by the auth service.
package models

import (
	"time"
	"unicode"
)

// User represents a registered user in the system.
type User struct {
	ID             int        // Primary key
	Username       string     // Unique username
	PasswordHash   string     // bcrypt-hashed password
	TOTPSecret     string     // Encrypted TOTP secret (empty if 2FA not enabled)
	TOTPEnabled    bool       // Whether TOTP-based 2FA is active
	FailedAttempts int        // Consecutive failed login attempts
	LockedUntil    *time.Time // Account locked until this time (nil if not locked)
	LastLogin      *time.Time // Timestamp of the last successful login
	CreatedAt      time.Time  // Registration timestamp
	UpdatedAt      time.Time  // Last profile update timestamp
}

// Session represents an active user session.
type Session struct {
	ID        string    // UUID-based session token
	UserID    int       // Foreign key to users table
	ExpiresAt time.Time // When this session expires
	CreatedAt time.Time // When this session was created
}

// IsLocked returns true if the user's account is currently locked.
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// IsExpired returns true if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// PasswordPolicy defines the password complexity requirements.
type PasswordPolicy struct {
	MinLength      int
	MaxLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireDigit   bool
	RequireSpecial bool
}

// ValidatePassword checks a password against the policy and returns a
// human-readable error message if it fails. Returns empty string on success.
func (p *PasswordPolicy) ValidatePassword(password string) string {
	if len(password) < p.MinLength {
		return "Password must be at least " + itoa(p.MinLength) + " characters."
	}
	if len(password) > p.MaxLength {
		return "Password cannot exceed " + itoa(p.MaxLength) + " characters (bcrypt limit)."
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	if p.RequireUpper && !hasUpper {
		return "Password must contain at least one uppercase letter."
	}
	if p.RequireLower && !hasLower {
		return "Password must contain at least one lowercase letter."
	}
	if p.RequireDigit && !hasDigit {
		return "Password must contain at least one digit."
	}
	if p.RequireSpecial && !hasSpecial {
		return "Password must contain at least one special character."
	}

	return ""
}

// itoa converts an integer to a string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	if neg {
		result = "-" + result
	}
	return result
}

// ValidateUsername checks that a username meets format requirements.
// Returns a human-readable error message if it fails. Empty string on success.
func ValidateUsername(username string) string {
	if len(username) < 3 {
		return "Username must be at least 3 characters."
	}
	if len(username) > 32 {
		return "Username must be at most 32 characters."
	}
	for i, ch := range username {
		if !isValidUsernameChar(ch) {
			_ = i // suppress unused warning
			return "Username can only contain letters, digits, underscores, and hyphens."
		}
	}
	// First character must be a letter
	if !unicode.IsLetter(rune(username[0])) {
		return "Username must start with a letter."
	}
	return ""
}

// isValidUsernameChar returns true if the character is allowed in usernames.
func isValidUsernameChar(ch rune) bool {
	return unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_' || ch == '-'
}
