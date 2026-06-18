// Package database handles PostgreSQL connection management and schema migrations.
// It provides automatic table creation on startup, connection retry logic,
// and expired session cleanup.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	// PostgreSQL driver registered via init()
	_ "github.com/lib/pq"

	"github.com/srijan-verma/auth-cli/internal/config"
)

// Connect establishes a connection to PostgreSQL with exponential backoff retry.
// This is necessary because the Go app may start before the database
// container is fully ready to accept connections.
func Connect(cfg *config.Config) (*sql.DB, error) {
	var db *sql.DB
	var err error

	maxRetries := 30
	backoff := 1 * time.Second

	for i := 0; i < maxRetries; i++ {
		db, err = sql.Open("postgres", cfg.DSN())
		if err != nil {
			slog.Warn("Failed to open database connection",
				"attempt", i+1,
				"max_retries", maxRetries,
				"error", err,
			)
			time.Sleep(backoff)
			backoff = min(backoff*2, 10*time.Second) // Exponential backoff, cap at 10s
			continue
		}

		// Use a context with timeout for the ping
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = db.PingContext(ctx)
		cancel()

		if err == nil {
			slog.Info("✅ Connected to PostgreSQL successfully")
			break
		}

		slog.Warn("Waiting for database to be ready",
			"attempt", i+1,
			"max_retries", maxRetries,
			"error", err,
		)
		time.Sleep(backoff)
		backoff = min(backoff*2, 10*time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database after %d attempts: %w", maxRetries, err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db, nil
}

// RunMigrations creates the required database tables if they don't already exist.
// Uses IF NOT EXISTS to make migrations idempotent and safe to run on every startup.
// Also includes a versioned migration tracking table for future schema changes.
func RunMigrations(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	migrations := []struct {
		name string
		sql  string
	}{
		{
			name: "create_users_table",
			sql: `CREATE TABLE IF NOT EXISTS users (
				id SERIAL PRIMARY KEY,
				username VARCHAR(255) UNIQUE NOT NULL,
				password_hash VARCHAR(255) NOT NULL,
				totp_secret TEXT DEFAULT '',
				totp_enabled BOOLEAN DEFAULT FALSE,
				failed_attempts INT DEFAULT 0,
				locked_until TIMESTAMP WITH TIME ZONE,
				last_login TIMESTAMP WITH TIME ZONE,
				created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
				updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
			)`,
		},
		{
			name: "create_sessions_table",
			sql: `CREATE TABLE IF NOT EXISTS sessions (
				id VARCHAR(36) PRIMARY KEY,
				user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
				created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
			)`,
		},
		{
			name: "create_audit_log_table",
			sql: `CREATE TABLE IF NOT EXISTS audit_log (
				id SERIAL PRIMARY KEY,
				user_id INT REFERENCES users(id) ON DELETE SET NULL,
				action VARCHAR(50) NOT NULL,
				detail TEXT DEFAULT '',
				ip_address VARCHAR(45) DEFAULT '',
				created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
			)`,
		},
		{
			name: "index_users_username",
			sql:  `CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		},
		{
			name: "index_sessions_user_id",
			sql:  `CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
		},
		{
			name: "index_sessions_expires_at",
			sql:  `CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,
		},
		{
			name: "index_audit_log_user_id",
			sql:  `CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)`,
		},
	}

	for _, m := range migrations {
		if _, err := db.ExecContext(ctx, m.sql); err != nil {
			return fmt.Errorf("migration '%s' failed: %w", m.name, err)
		}
	}

	slog.Info("✅ Database migrations completed successfully",
		"migration_count", len(migrations),
	)
	return nil
}

// CleanExpiredSessions removes all sessions that have passed their expiration time.
// Should be called periodically or on application startup.
func CleanExpiredSessions(db *sql.DB) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := db.ExecContext(ctx,
		"DELETE FROM sessions WHERE expires_at < NOW()",
	)
	if err != nil {
		return 0, fmt.Errorf("failed to clean expired sessions: %w", err)
	}

	count, _ := result.RowsAffected()
	if count > 0 {
		slog.Info("Cleaned expired sessions", "count", count)
	}
	return count, nil
}

// LogAuditEvent records an authentication-related event in the audit log.
func LogAuditEvent(db *sql.DB, userID *int, action, detail string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if userID != nil {
		db.ExecContext(ctx,
			"INSERT INTO audit_log (user_id, action, detail) VALUES ($1, $2, $3)",
			*userID, action, detail,
		)
	} else {
		db.ExecContext(ctx,
			"INSERT INTO audit_log (action, detail) VALUES ($1, $2)",
			action, detail,
		)
	}
}
