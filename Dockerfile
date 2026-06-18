# ──────────────────────────────────────────────────────────────
# Multi-stage Dockerfile for Auth CLI
# Stage 1: Build the Go binary with all dependencies
# Stage 2: Minimal runtime image with just the binary
#
# Security: non-root user, minimal Alpine base, no build tools
# ──────────────────────────────────────────────────────────────

# ── Build Stage ──────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

# Install git for fetching Go module dependencies
RUN apk add --no-cache git

WORKDIR /app

# Copy dependency files first for better Docker layer caching
COPY go.mod go.sum* ./

# Download dependencies (cached if go.mod/go.sum haven't changed)
RUN go mod download 2>/dev/null || true

# Copy source code
COPY . .

# Ensure dependencies are resolved
RUN go mod tidy

# Build a statically linked binary with version injection
ARG APP_VERSION=1.1.0
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${APP_VERSION}" \
    -o /auth-cli ./cmd/main.go

# ── Runtime Stage ────────────────────────────────────────────
FROM alpine:3.19

# Install ca-certificates for HTTPS and timezone data
RUN apk add --no-cache ca-certificates tzdata || true

# Security: run as non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy the compiled binary from the build stage
COPY --from=builder /auth-cli /app/auth-cli

# Set ownership to non-root user
RUN chown appuser:appgroup /app/auth-cli

USER appuser

# Health check (the binary exists and is executable)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
    CMD test -x /app/auth-cli || exit 1

ENTRYPOINT ["/app/auth-cli"]
