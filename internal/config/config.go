// Package config provides application configuration loaded from environment variables.
// All settings have sensible defaults and can be overridden via env vars or .env files.
// Configuration is validated at load time to fail fast on invalid values.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration values.
type Config struct {
	// Database connection settings
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string

	// Security settings
	SessionTimeout    time.Duration // How long a session remains valid
	MaxFailedAttempts int           // Number of failed logins before lockout
	LockoutDuration   time.Duration // How long an account stays locked
	BcryptCost        int           // bcrypt hash cost factor (10-14 recommended)

	// Password policy
	MinPasswordLength int  // Minimum password length
	MaxPasswordLength int  // Maximum password length (bcrypt caps at 72 bytes)
	RequireUppercase  bool // Require at least one uppercase letter
	RequireLowercase  bool // Require at least one lowercase letter
	RequireDigit      bool // Require at least one digit
	RequireSpecial    bool // Require at least one special character

	// TOTP encryption key for encrypting secrets at rest (32 bytes for AES-256)
	TOTPEncryptionKey string

	// Application metadata
	AppVersion string
}

// Load reads configuration from environment variables with sensible defaults.
// Returns an error if any required configuration is invalid.
func Load() (*Config, error) {
	cfg := &Config{
		DBHost:     getEnv("DB_HOST", "postgres"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBUser:     getEnv("DB_USER", "authuser"),
		DBPassword: getEnv("DB_PASSWORD", "authpass"),
		DBName:     getEnv("DB_NAME", "authdb"),
		DBSSLMode:  getEnv("DB_SSLMODE", "disable"),

		SessionTimeout:    getDurationMinutes("SESSION_TIMEOUT_MINUTES", 30),
		MaxFailedAttempts: getIntEnv("MAX_FAILED_ATTEMPTS", 5),
		LockoutDuration:   getDurationMinutes("LOCKOUT_DURATION_MINUTES", 15),
		BcryptCost:        getIntEnv("BCRYPT_COST", 12),

		MinPasswordLength: getIntEnv("MIN_PASSWORD_LENGTH", 8),
		MaxPasswordLength: getIntEnv("MAX_PASSWORD_LENGTH", 72), // bcrypt limit
		RequireUppercase:  getBoolEnv("REQUIRE_UPPERCASE", true),
		RequireLowercase:  getBoolEnv("REQUIRE_LOWERCASE", true),
		RequireDigit:      getBoolEnv("REQUIRE_DIGIT", true),
		RequireSpecial:    getBoolEnv("REQUIRE_SPECIAL", false),

		TOTPEncryptionKey: getEnv("TOTP_ENCRYPTION_KEY", "change-me-to-a-32-byte-key!!!!!"),

		AppVersion: getEnv("APP_VERSION", "1.1.0"),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate checks that all configuration values are within acceptable ranges.
func (c *Config) validate() error {
	if c.BcryptCost < 10 || c.BcryptCost > 16 {
		return fmt.Errorf("BCRYPT_COST must be between 10 and 16, got %d", c.BcryptCost)
	}
	if c.MaxFailedAttempts < 1 {
		return fmt.Errorf("MAX_FAILED_ATTEMPTS must be at least 1, got %d", c.MaxFailedAttempts)
	}
	if c.SessionTimeout < 1*time.Minute {
		return fmt.Errorf("SESSION_TIMEOUT_MINUTES must be at least 1 minute")
	}
	if c.LockoutDuration < 1*time.Minute {
		return fmt.Errorf("LOCKOUT_DURATION_MINUTES must be at least 1 minute")
	}
	if c.MinPasswordLength < 8 {
		return fmt.Errorf("MIN_PASSWORD_LENGTH must be at least 8, got %d", c.MinPasswordLength)
	}
	if c.MaxPasswordLength > 72 {
		return fmt.Errorf("MAX_PASSWORD_LENGTH cannot exceed 72 (bcrypt limit), got %d", c.MaxPasswordLength)
	}
	if len(c.TOTPEncryptionKey) < 16 {
		return fmt.Errorf("TOTP_ENCRYPTION_KEY must be at least 16 characters")
	}
	return nil
}

// DSN returns the PostgreSQL connection string.
func (c *Config) DSN() string {
	return "host=" + c.DBHost +
		" port=" + c.DBPort +
		" user=" + c.DBUser +
		" password=" + c.DBPassword +
		" dbname=" + c.DBName +
		" sslmode=" + c.DBSSLMode
}

// getEnv reads an environment variable or returns a default value.
func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

// getIntEnv reads an integer environment variable or returns a default value.
func getIntEnv(key string, fallback int) int {
	if val, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(val); err == nil {
			return n
		}
	}
	return fallback
}

// getBoolEnv reads a boolean environment variable or returns a default value.
func getBoolEnv(key string, fallback bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(val); err == nil {
			return b
		}
	}
	return fallback
}

// getDurationMinutes reads a duration in minutes from an env var.
func getDurationMinutes(key string, fallback int) time.Duration {
	return time.Duration(getIntEnv(key, fallback)) * time.Minute
}
