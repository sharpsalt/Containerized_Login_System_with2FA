// Package main is the entry point for the Auth CLI application.
// It initializes configuration, connects to the database, runs migrations,
// and starts the interactive command-line interface.
package main

import (
	"log"
	"github.com/srijan-verma/auth-cli/internal/auth"
	"github.com/srijan-verma/auth-cli/internal/cli"
	"github.com/srijan-verma/auth-cli/internal/config"
	database "github.com/srijan-verma/auth-cli/internal/database"
)

func main() {
	// Load configuration from environment variables
	cfg:=config.Load()
	// Connect to PostgreSQL (with retry logic for Docker startup)
	db,err:=database.Connect(cfg)
	if err!=nil{
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close() //i will put it in stack like defer will put each process into the stack
	// Run schema migrations (idempotent)
	if err:=database.RunMigrations(db);err!=nil{
		log.Fatalf("Failed to run migrations: %v",err)
	}
	// Initialize auth service and start the CLI
	authService:=auth.NewService(db,cfg)
	handler:=cli.NewHandler(authService)
	handler.Run()
}
