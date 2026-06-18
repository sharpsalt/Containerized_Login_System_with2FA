# ──────────────────────────────────────────────────────────────
# Makefile for Auth CLI
# Common development tasks: build, test, lint, docker, clean
# ──────────────────────────────────────────────────────────────

.PHONY: all build run test lint clean docker-up docker-down docker-run docker-logs help

# Default target
all: lint build

## Build the Go binary locally
build:
	@echo " Building auth-cli..."
	CGO_ENABLED=0 go build -ldflags="-s -w" -o auth-cli ./cmd/main.go
	@echo " Built: ./auth-cli"

## Run the CLI locally (requires DB on localhost:5432)
run: build
	DB_HOST=localhost ./auth-cli

# ── Testing ──────────────────────────────────────────────────

## Run all tests (requires PostgreSQL on localhost:5432)
test:
	@echo " Running tests..."
	go test -v -count=1 ./tests/

## Run tests with coverage report
test-cover:
	@echo " Running tests with coverage..."
	go test -v -count=1 -cover -coverprofile=coverage.out ./tests/
	go tool cover -func=coverage.out
	@echo " HTML coverage report: go tool cover -html=coverage.out"

## Run tests with race detector
test-race:
	@echo " Running tests with race detector..."
	go test -v -race -count=1 ./tests/

# ── Code Quality ─────────────────────────────────────────────

## Run go vet
lint:
	@echo " Running go vet..."
	go vet ./...
	@echo " Lint passed"

## Format code
fmt:
	@echo " Formatting code..."
	gofmt -s -w .
	@echo " Code formatted"

## Tidy dependencies
tidy:
	go mod tidy

# ── Docker ───────────────────────────────────────────────────

## Start PostgreSQL in background
docker-db:
	@echo " Starting PostgreSQL..."
	docker compose up -d postgres
	@echo " Waiting for PostgreSQL to be ready..."
	@sleep 3
	@echo " PostgreSQL is ready"
## Build and run the full app in Docker (interactive)
docker-run:
	@echo " Building and starting Auth CLI..."
	docker compose run --rm --build app
## Start all services in background
docker-up:
	docker compose up -d --build
## Stop all services (preserves data)
docker-down:
	docker compose down
## Stop all services and delete data
docker-clean:
	docker compose down -v --remove-orphans
	@echo "  All data removed"
## Show logs
docker-logs:
	docker compose logs -f

# ── Cleanup ──────────────────────────────────────────────────

## Remove built artifacts
clean:
	rm -f auth-cli coverage.out
	@echo "  Clean"

# ── Help ─────────────────────────────────────────────────────

## Show this help message
help:
	@echo "Auth CLI - Available Commands:"
	@echo ""
	@echo "  make build         Build the Go binary"
	@echo "  make run           Build and run locally"
	@echo "  make test          Run tests (needs DB)"
	@echo "  make test-cover    Run tests with coverage"
	@echo "  make test-race     Run tests with race detector"
	@echo "  make lint          Run go vet"
	@echo "  make fmt           Format code with gofmt"
	@echo "  make tidy          Run go mod tidy"
	@echo ""
	@echo "  make docker-db     Start PostgreSQL only"
	@echo "  make docker-run    Build & run app in Docker"
	@echo "  make docker-up     Start all services (background)"
	@echo "  make docker-down   Stop all services"
	@echo "  make docker-clean  Stop & delete all data"
	@echo "  make docker-logs   Show container logs"
	@echo ""
	@echo "  make clean         Remove build artifacts"
	@echo "  make help          Show this message"