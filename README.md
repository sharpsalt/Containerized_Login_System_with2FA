# Auth CLI — Containerized Login System with 2FA

A **production-grade**, interactive command-line authentication system built with **Go**, **PostgreSQL**, and **Docker**. Features user registration, bcrypt password hashing, AES-256 encrypted TOTP-based two-factor authentication (Google Authenticator compatible), session management, audit logging, and account lockout protection.

---

## Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Usage Guide](#-usage-guide)
- [Commands Reference](#-commands-reference)
- [Database Schema](#-database-schema)
- [Running Tests](#-running-tests)
- [Project Structure](#-project-structure)
- [Security Design](#-security-design)
- [Development](#-development)

---

## Features

| Feature | Description |
|---------|-------------|
| **User Registration** | Create accounts with username/password validation |
| **Secure Authentication** | bcrypt password hashing (configurable cost factor) |
| **TOTP 2FA** | Google Authenticator-compatible with QR code display |
| **Encrypted TOTP Secrets** | AES-256-GCM encryption of TOTP secrets at rest |
| **Account Lockout** | Automatic lockout after configurable failed attempts |
| **Session Management** | UUID-based sessions with configurable timeout |
| **Single-Session Policy** | New login invalidates any existing session |
| **Password Policy** | Configurable complexity requirements (upper, lower, digit, special) |
| **Change Password** | In-session password change with current password verification |
| **Timing Attack Prevention** | Constant-time response for login regardless of username existence |
| **Audit Logging** | All security events logged to `audit_log` table |
| **Interactive CLI** | Tab completion, command history, colored output |
| **Graceful Shutdown** | Signal handling (SIGINT/SIGTERM) with session cleanup |
| **Docker** | Full containerization with data persistence |
| **Structured Logging** | Go `slog` for structured, leveled logging |

---

## Screenshots
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/b3a22a03-d08f-4b60-b151-9a6814f0ae96" />
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/b23946b4-b26d-4b72-ba89-c1304d85ade8" />
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/c67d53f6-d594-48f1-8329-62c6d602979d" />
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/e3b9d837-082d-46d9-b586-0731a2083b01" />


---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (v20.10+)
- [Docker Compose](https://docs.docker.com/compose/install/) (v2.0+)
- (Optional) [Go 1.22+](https://go.dev/dl/) for local development
- (Optional) [Make](https://www.gnu.org/software/make/) for convenience targets

---

## Quick Start

### 1. Clone the Repository

```bash
git clone hhttps://github.com/sharpsalt/Containerized_Login_System_with2FA.git
cd auth-cli
```

### 2. Start with Docker Compose

```bash
# Build and run the interactive CLI
docker compose run --rm --build app
```

Or using Make:

```bash
make docker-run
```

This command will:
1. Build the Go binary in a multi-stage Docker build
2. Start PostgreSQL 16 with a persistent volume and health checks
3. Wait for PostgreSQL to be healthy before starting the app
4. Run database migrations automatically
5. Clean up expired sessions from previous runs
6. Launch the interactive CLI

### 3. Alternative: Run Database Only, App Locally

```bash
# Start only PostgreSQL
make docker-db
# OR: docker compose up -d postgres

# Run the Go app locally
make run
# OR: DB_HOST=localhost go run ./cmd/main.go
```

### 4. Stop and Clean Up

```bash
# Stop containers (data persists in volume)
make docker-down

# Stop and remove ALL data
make docker-clean
```

---

## Configuration

All settings are configurable via environment variables. Copy the example file:

```bash
cp .env.example .env
```

### Database Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `postgres` | Database hostname |
| `DB_PORT` | `5432` | Database port |
| `DB_USER` | `authuser` | Database username |
| `DB_PASSWORD` | `authpass` | Database password |
| `DB_NAME` | `authdb` | Database name |
| `DB_SSLMODE` | `disable` | PostgreSQL SSL mode |

### Security Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSION_TIMEOUT_MINUTES` | `30` | Session expiry in minutes |
| `MAX_FAILED_ATTEMPTS` | `5` | Failed logins before lockout |
| `LOCKOUT_DURATION_MINUTES` | `15` | Lockout duration in minutes |
| `BCRYPT_COST` | `12` | bcrypt hash cost (10-16) |
| `TOTP_ENCRYPTION_KEY` | *(change me)* | AES-256 key for TOTP secret encryption |

### Password Policy

| Variable | Default | Description |
|----------|---------|-------------|
| `MIN_PASSWORD_LENGTH` | `8` | Minimum password length |
| `MAX_PASSWORD_LENGTH` | `72` | Maximum (bcrypt limit) |
| `REQUIRE_UPPERCASE` | `true` | Require uppercase letter |
| `REQUIRE_LOWERCASE` | `true` | Require lowercase letter |
| `REQUIRE_DIGIT` | `true` | Require digit |
| `REQUIRE_SPECIAL` | `false` | Require special character |

---

## Usage Guide

### Registration

```
❯ register

── New User Registration ──

  Password requirements:
    • At least 8 characters (max 72)
    • At least one uppercase letter (A-Z)
    • At least one lowercase letter (a-z)
    • At least one digit (0-9)

  Username: alice
  Password: ********
  Confirm Password: ********

   User 'alice' registered successfully! You can now login.
```

### Login

```
❯ login

── Login ──

  Username: alice
  Password: ********

   Login successful!

  ╭───────────────────────────────────────────────╮
  │            User Details                       │
  ├───────────────────────────────────────────────┤
  │  Username:      alice                         │
  │  Registered:    2026-06-17 12:00:00           │
  │  MFA Status:    ✗ Disabled                    │
  │  Session Exp:   2026-06-17 12:30:00           │
  │                 (29m 59s remaining)            │
  │  Last Login:    First login                   │
  ╰───────────────────────────────────────────────╯
```

### Enabling 2FA

```
alice [29m 45s] > enable-2fa

── Enable Two-Factor Authentication ──

  Step 1: Scan this QR code with Google Authenticator:

  [QR Code displayed in terminal]

  Step 2: Or manually enter this secret key:
     JBSWY3DPEHPK3PXP...

  Step 3: Enter the 6-digit code from your authenticator to verify:

  Verification Code: 123456

   Two-Factor Authentication enabled successfully!

    Save your secret key in a safe place as backup.
```

### Changing Password

```
alice [25m 10s] > change-password

── Change Password ──

  Current Password: ********
  Password requirements:
    • At least 8 characters (max 72)
    • At least one uppercase letter (A-Z)
    • At least one lowercase letter (a-z)
    • At least one digit (0-9)

  New Password: ********
  Confirm New Password: ********

   Password changed successfully!
```

---

##  Commands Reference

### Before Login

| Command | Description |
|---------|-------------|
| `register` | Create a new user account with password policy validation |
| `login` | Login with username and password (+ TOTP if enabled) |
| `help` | Show available commands |
| `version` | Show application version and configuration |
| `exit` | Quit the program |

### After Login

| Command | Description |
|---------|-------------|
| `whoami` | Display current user details (refreshed from DB) |
| `enable-2fa` | Enable TOTP-based two-factor authentication |
| `disable-2fa` | Disable 2FA (requires current 2FA code) |
| `change-password` | Change password (requires current password) |
| `logout` | End current session |
| `help` | Show available commands |
| `version` | Show application version and configuration |
| `exit` | Quit the program (auto-logout with session cleanup) |

---

## 🗄 Database Schema

### Users Table

```sql
CREATE TABLE users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,         -- bcrypt hash
    totp_secret     TEXT DEFAULT '',                -- AES-256-GCM encrypted
    totp_enabled    BOOLEAN DEFAULT FALSE,
    failed_attempts INT DEFAULT 0,
    locked_until    TIMESTAMP WITH TIME ZONE,       -- NULL if not locked
    last_login      TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Sessions Table

```sql
CREATE TABLE sessions (
    id          VARCHAR(36) PRIMARY KEY,             -- UUID v4
    user_id     INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Audit Log Table

```sql
CREATE TABLE audit_log (
    id          SERIAL PRIMARY KEY,
    user_id     INT REFERENCES users(id) ON DELETE SET NULL,
    action      VARCHAR(50) NOT NULL,                -- e.g., login_success, login_failed
    detail      TEXT DEFAULT '',
    ip_address  VARCHAR(45) DEFAULT '',
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Indexes

```sql
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
```

All migrations run automatically on startup and are idempotent (`IF NOT EXISTS`).

---

## 🧪 Running Tests

Tests require a running PostgreSQL instance:

```bash
# Start PostgreSQL
make docker-db

# Run tests
make test

# Run tests with coverage
make test-cover

# Run tests with race detector
make test-race

# Clean up
make docker-down
```

### Test Suite Coverage

| Category | Tests | Coverage |
|----------|-------|----------|
| **Registration** | Success, duplicate, weak password, invalid username |
| **Login** | Success, wrong password, nonexistent user, last_login update |
| **Account Lockout** | Lockout after max attempts, reset on success |
| **Sessions** | Create, validate, destroy, invalid ID, single-session policy | 
| **TOTP** | Generate, validate, enable/login flow, disable requires code | 
| **TOTP Encryption** | Round-trip, wrong key, empty string, unique nonces | 
| **Password Policy** | Valid, too short, too long, missing chars | 
| **Username Validation** | Valid formats, invalid formats | 
| **Change Password** | Success, wrong current password | 
| **Session Cleanup** | Expired session removal | 
| **Audit Log** | Login success events, failed login events | 

---

## Project Structure

```
.
├── cmd/
│   └── main.go                  # Entry point: config → DB → migrations → CLI
├── internal/
│   ├── auth/
│   │   ├── service.go           # Core auth: register, login, sessions, lockout
│   │   └── totp.go              # TOTP + AES-256-GCM encryption
│   ├── cli/
│   │   └── cli.go               # Interactive CLI with tab completion
│   ├── config/
│   │   └── config.go            # Env-based config with validation
│   ├── database/
│   │   └── postgres.go          # DB connection, migrations, audit, cleanup
│   └── models/
│       └── models.go            # User, Session, PasswordPolicy, validators
├── tests/
│   └── auth_test.go             # 30+ unit tests
├── Dockerfile                   # Multi-stage build (Alpine)
├── docker-compose.yml           # PostgreSQL + App with network isolation
├── Makefile                     # Dev workflow targets
├── .env.example                 # Configuration template
├── .gitignore
├── go.mod
├── go.sum
└── README.md
```

---

## Security Design

### Password Storage
- **bcrypt** with configurable cost factor (default: 12, ≈250ms per hash)
- Each password gets a unique random salt (built into bcrypt)
- Maximum password length enforced to 72 bytes (bcrypt's internal limit)
- Raw passwords are never stored, logged, or transmitted in plaintext

### Password Policy
- Configurable minimum/maximum length
- Optional requirements: uppercase, lowercase, digit, special character
- Requirements displayed to user during registration and password change

### Timing Attack Prevention
- **Dummy bcrypt comparison** for nonexistent usernames prevents user enumeration
- Attackers cannot distinguish "user doesn't exist" from "wrong password" by timing

### Race Condition Prevention
- **Atomic `INSERT ... ON CONFLICT`** for registration prevents duplicate users
- No SELECT-then-INSERT pattern that could allow concurrent duplicate registrations

### Account Lockout
- Configurable threshold (default: 5 failed attempts)
- Configurable lockout duration (default: 15 minutes)
- Failed attempt counter resets on successful login
- Remaining lockout time displayed on blocked login attempt

### Session Management
- **UUID v4** tokens (cryptographically random, 122 bits of entropy)
- Configurable timeout (default: 30 minutes)
- **Single-session policy**: new login invalidates previous sessions
- Sessions stored server-side in PostgreSQL
- Expired sessions cleaned on startup + on validation
- Session destroyed on explicit logout and graceful shutdown

### Two-Factor Authentication
- **RFC 6238** TOTP with 30-second period
- **SHA1** algorithm (Google Authenticator standard)
- **6-digit** codes with ±1 period clock skew tolerance
- **256-bit** secret keys
- **AES-256-GCM** encryption of secrets at rest in database
- QR code display in terminal for easy authenticator app setup
- Requires valid code to both enable and disable 2FA

### Audit Logging
- All security-relevant events logged to `audit_log` table
- Events tracked: register, login_success, login_failed, login_blocked, totp_failed, 2fa_enabled, 2fa_disabled, password_changed, session_created, account_locked

### Docker Security
- **Multi-stage build** — no build tools in runtime image
- **Non-root user** (`appuser`) in container
- **Alpine Linux** — minimal attack surface (~5MB base)
- **Network isolation** — services communicate on internal bridge network
- **Resource limits** on database container
- Database credentials via environment variables (not hardcoded)

---

## 🛠 Development

### Makefile Targets

```bash
make build         # Build the Go binary
make run           # Build and run locally
make test          # Run tests (needs DB)
make test-cover    # Run tests with coverage
make test-race     # Run tests with race detector
make lint          # Run go vet
make fmt           # Format code with gofmt
make tidy          # Run go mod tidy
make docker-db     # Start PostgreSQL only
make docker-run    # Build & run app in Docker
make docker-up     # Start all services (background)
make docker-down   # Stop all services
make docker-clean  # Stop & delete all data
make docker-logs   # Show container logs
make clean         # Remove build artifacts
```

### Local Development Workflow

```bash
# 1. Start DB
make docker-db

# 2. Run app locally with hot-reload-friendly setup
DB_HOST=localhost go run ./cmd/main.go

# 3. Run tests in another terminal
make test

# 4. Clean up
make docker-down
```

---

