// Package cli implements the interactive command-line interface for the auth system.
// It provides readline-style editing, command history, tab completion,
// contextual commands based on authentication state, and graceful shutdown.
package cli

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mdp/qrterminal/v3"
	"github.com/peterh/liner"
	"golang.org/x/term"

	"github.com/srijan-verma/auth-cli/internal/auth"
	"github.com/srijan-verma/auth-cli/internal/config"
	"github.com/srijan-verma/auth-cli/internal/models"
)

// color constants for terminal output (ANSI escape codes)
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
)

// Commands available before authentication
var preLoginCommands = []string{"register", "login", "help", "version", "exit"}

// Commands available after authentication
var postLoginCommands = []string{
	"whoami", "enable-2fa", "disable-2fa",
	"change-password", "logout", "help", "version", "exit",
}

// Handler manages the CLI state and processes user commands.
type Handler struct {
	authService    *auth.Service
	cfg            *config.Config
	currentUser    *models.User
	currentSession *models.Session
	line           *liner.State
	shutdownCh     chan struct{} // Signal for graceful shutdown
}

// NewHandler creates a new CLI handler with the given auth service.
func NewHandler(authService *auth.Service, cfg *config.Config) *Handler {
	return &Handler{
		authService: authService,
		cfg:         cfg,
		shutdownCh:  make(chan struct{}),
	}
}

// Run starts the interactive CLI loop with graceful shutdown support.
func (h *Handler) Run() {
	h.printBanner()

	h.line = liner.NewLiner()
	defer h.line.Close()

	h.line.SetCtrlCAborts(true)

	// Handle OS signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		h.gracefulShutdown()
	}()

	// Configure tab completion based on current auth state
	h.line.SetCompleter(func(line string) []string {
		var commands []string
		if h.isLoggedIn() {
			commands = postLoginCommands
		} else {
			commands = preLoginCommands
		}

		var completions []string
		for _, cmd := range commands {
			if strings.HasPrefix(cmd, strings.ToLower(line)) {
				completions = append(completions, cmd)
			}
		}
		return completions
	})

	fmt.Printf("%sType 'help' for available commands. Press Tab for auto-completion.%s\n\n", colorDim, colorReset)

	for {
		prompt := h.getPrompt()
		input, err := h.line.Prompt(prompt)
		if err != nil {
			if err == liner.ErrPromptAborted {
				fmt.Println("\nUse 'exit' to quit.")
				continue
			}
			// EOF (Ctrl+D)
			h.gracefulShutdown()
			return
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		h.line.AppendHistory(input)

		// Check session expiry before processing commands
		if h.isLoggedIn() && h.currentSession.IsExpired() {
			h.printWarning("Session expired. Please login again.")
			h.currentUser = nil
			h.currentSession = nil
			continue
		}

		h.handleCommand(input)
	}
}

// handleCommand routes user input to the appropriate command handler.
func (h *Handler) handleCommand(input string) {
	cmd := strings.ToLower(strings.TrimSpace(input))

	if h.isLoggedIn() {
		switch cmd {
		case "whoami":
			h.cmdWhoAmI()
		case "enable-2fa":
			h.cmdEnable2FA()
		case "disable-2fa":
			h.cmdDisable2FA()
		case "change-password":
			h.cmdChangePassword()
		case "logout":
			h.cmdLogout()
		case "help":
			h.cmdHelpLoggedIn()
		case "version":
			h.cmdVersion()
		case "exit":
			h.gracefulShutdown()
		default:
			h.printError(fmt.Sprintf("Unknown command: '%s'. Type 'help' for available commands.", cmd))
		}
	} else {
		switch cmd {
		case "register":
			h.cmdRegister()
		case "login":
			h.cmdLogin()
		case "help":
			h.cmdHelpLoggedOut()
		case "version":
			h.cmdVersion()
		case "exit":
			h.gracefulShutdown()
		default:
			h.printError(fmt.Sprintf("Unknown command: '%s'. Type 'help' for available commands.", cmd))
		}
	}
}

// ─── Command Implementations ────────────────────────────────────────────────

// cmdRegister handles user registration flow with full validation feedback.
func (h *Handler) cmdRegister() {
	fmt.Printf("\n%s%s── New User Registration ──%s\n\n", colorBold, colorCyan, colorReset)

	// Show password requirements upfront
	policy := h.authService.GetPasswordPolicy()
	h.showPasswordRequirements(policy)

	username, err := h.line.Prompt("  Username: ")
	if err != nil {
		return
	}
	username = strings.TrimSpace(username)

	// Validate username format
	if msg := models.ValidateUsername(username); msg != "" {
		h.printError(msg)
		return
	}

	// Read password securely (hidden input)
	password, err := h.readPassword("  Password: ")
	if err != nil {
		return
	}

	// Validate password against policy
	if msg := policy.ValidatePassword(password); msg != "" {
		h.printError(msg)
		return
	}

	confirmPassword, err := h.readPassword("  Confirm Password: ")
	if err != nil {
		return
	}
	if password != confirmPassword {
		h.printError("Passwords do not match.")
		return
	}

	err = h.authService.Register(username, password)
	if err != nil {
		h.printError(err.Error())
		return
	}

	h.printSuccess(fmt.Sprintf("User '%s' registered successfully! You can now login.", username))
}

// cmdLogin handles the login flow including optional TOTP verification.
func (h *Handler) cmdLogin() {
	fmt.Printf("\n%s%s── Login ──%s\n\n", colorBold, colorCyan, colorReset)

	username, err := h.line.Prompt("  Username: ")
	if err != nil {
		return
	}
	username = strings.TrimSpace(username)

	if username == "" {
		h.printError("Username cannot be empty.")
		return
	}

	password, err := h.readPassword("  Password: ")
	if err != nil {
		return
	}

	user, totpRequired, err := h.authService.Login(username, password)
	if err != nil {
		h.printError(err.Error())
		return
	}

	// If 2FA is enabled, prompt for TOTP code
	if totpRequired {
		fmt.Printf("\n  %s Two-Factor Authentication Required%s\n", colorYellow, colorReset)
		code, err := h.line.Prompt("  Enter 2FA Code: ")
		if err != nil {
			return
		}
		code = strings.TrimSpace(code)

		if err := h.authService.VerifyTOTPAndLogin(user, code); err != nil {
			h.printError(err.Error())
			return
		}
	}

	// Create a new session
	session, err := h.authService.CreateSession(user.ID)
	if err != nil {
		h.printError("Failed to create session: " + err.Error())
		return
	}

	h.currentUser = user
	h.currentSession = session

	// Refresh user data to get updated last_login
	h.currentUser, _ = h.authService.GetUser(user.ID)

	h.printSuccess("Login successful!")
	h.displayUserDetails()
}

// cmdWhoAmI displays current user details (refreshed from DB).
func (h *Handler) cmdWhoAmI() {
	user, err := h.authService.GetUser(h.currentUser.ID)
	if err != nil {
		h.printError("Failed to retrieve user details: " + err.Error())
		return
	}
	h.currentUser = user
	h.displayUserDetails()
}

// cmdEnable2FA guides the user through 2FA setup with QR code.
func (h *Handler) cmdEnable2FA() {
	fmt.Printf("\n%s%s── Enable Two-Factor Authentication ──%s\n\n", colorBold, colorCyan, colorReset)

	secret, err := h.authService.EnableTOTP(h.currentUser.ID)
	if err != nil {
		h.printError(err.Error())
		return
	}

	// Generate the otpauth URL for QR code
	otpauthURL := auth.GenerateTOTPURL(h.currentUser.Username, secret)

	fmt.Printf("  %sStep 1:%s Scan this QR code with Google Authenticator:\n\n", colorBold, colorReset)

	// Display QR code in terminal
	qrterminal.GenerateWithConfig(otpauthURL, qrterminal.Config{
		Level:     qrterminal.L,
		Writer:    os.Stdout,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
		QuietZone: 2,
	})

	fmt.Printf("\n  %sStep 2:%s Or manually enter this secret key:\n", colorBold, colorReset)
	fmt.Printf("     %s%s%s\n\n", colorYellow, secret, colorReset)
	fmt.Printf("  %sStep 3:%s Enter the 6-digit code from your authenticator to verify:\n\n", colorBold, colorReset)

	code, err := h.line.Prompt("  Verification Code: ")
	if err != nil {
		return
	}
	code = strings.TrimSpace(code)

	if err := h.authService.ConfirmTOTP(h.currentUser.ID, secret, code); err != nil {
		h.printError("Verification failed: " + err.Error())
		return
	}

	h.currentUser, _ = h.authService.GetUser(h.currentUser.ID)
	h.printSuccess("Two-Factor Authentication enabled successfully! ")
	fmt.Printf("  %s  Save your secret key in a safe place as backup.%s\n\n", colorYellow, colorReset)
}

// cmdDisable2FA removes 2FA from the user's account (requires current code).
func (h *Handler) cmdDisable2FA() {
	fmt.Printf("\n%s%s── Disable Two-Factor Authentication ──%s\n\n", colorBold, colorCyan, colorReset)

	if !h.currentUser.TOTPEnabled {
		h.printError("2FA is not currently enabled on your account.")
		return
	}

	fmt.Printf("  %s  This will remove 2FA protection from your account.%s\n", colorYellow, colorReset)
	fmt.Printf("  %sEnter your current 2FA code to confirm:%s\n\n", colorDim, colorReset)

	code, err := h.line.Prompt("  2FA Code: ")
	if err != nil {
		return
	}
	code = strings.TrimSpace(code)

	if err := h.authService.DisableTOTP(h.currentUser.ID, code); err != nil {
		h.printError(err.Error())
		return
	}

	h.currentUser, _ = h.authService.GetUser(h.currentUser.ID)
	h.printSuccess("Two-Factor Authentication has been disabled.")
}

// cmdChangePassword handles the password change flow.
func (h *Handler) cmdChangePassword() {
	fmt.Printf("\n%s%s── Change Password ──%s\n\n", colorBold, colorCyan, colorReset)

	currentPassword, err := h.readPassword("  Current Password: ")
	if err != nil {
		return
	}

	policy := h.authService.GetPasswordPolicy()
	h.showPasswordRequirements(policy)

	newPassword, err := h.readPassword("  New Password: ")
	if err != nil {
		return
	}

	if msg := policy.ValidatePassword(newPassword); msg != "" {
		h.printError(msg)
		return
	}

	confirmPassword, err := h.readPassword("  Confirm New Password: ")
	if err != nil {
		return
	}
	if newPassword != confirmPassword {
		h.printError("Passwords do not match.")
		return
	}

	if currentPassword == newPassword {
		h.printError("New password must be different from current password.")
		return
	}

	if err := h.authService.ChangePassword(h.currentUser.ID, currentPassword, newPassword); err != nil {
		h.printError(err.Error())
		return
	}

	h.printSuccess("Password changed successfully!")
}

// cmdLogout destroys the current session.
func (h *Handler) cmdLogout() {
	if err := h.authService.DestroySession(h.currentSession.ID); err != nil {
		h.printError("Failed to destroy session: " + err.Error())
		return
	}

	username := h.currentUser.Username
	h.currentUser = nil
	h.currentSession = nil

	h.printSuccess(fmt.Sprintf("Goodbye, %s! Session ended.", username))
}

// cmdHelpLoggedOut shows commands available before authentication.
func (h *Handler) cmdHelpLoggedOut() {
	fmt.Printf("\n%s%s  Available Commands:%s\n", colorBold, colorCyan, colorReset)
	fmt.Println("  ─────────────────────────────────────────")
	printCommand("register", "Create a new user account")
	printCommand("login", "Login with username/password")
	printCommand("help", "Show available commands")
	printCommand("version", "Show application version")
	printCommand("exit", "Quit the program")
	fmt.Println()
}

// cmdHelpLoggedIn shows commands available after authentication.
func (h *Handler) cmdHelpLoggedIn() {
	fmt.Printf("\n%s%s  Available Commands:%s\n", colorBold, colorCyan, colorReset)
	fmt.Println("  ─────────────────────────────────────────")
	printCommand("whoami", "Show current user details")
	printCommand("enable-2fa", "Enable TOTP-based 2FA")
	printCommand("disable-2fa", "Disable TOTP-based 2FA")
	printCommand("change-password", "Change your password")
	printCommand("logout", "End current session")
	printCommand("help", "Show available commands")
	printCommand("version", "Show application version")
	printCommand("exit", "Quit the program")
	fmt.Println()
}

// cmdVersion displays the application version and build info.
func (h *Handler) cmdVersion() {
	fmt.Printf("\n  %sAuth CLI%s v%s\n", colorBold, colorReset, h.cfg.AppVersion)
	fmt.Printf("  %sSession timeout:%s %s\n", colorDim, colorReset, h.cfg.SessionTimeout)
	fmt.Printf("  %sMax login attempts:%s %d\n", colorDim, colorReset, h.cfg.MaxFailedAttempts)
	fmt.Printf("  %sLockout duration:%s %s\n\n", colorDim, colorReset, h.cfg.LockoutDuration)
}

// gracefulShutdown cleanly terminates the application,
// destroying any active session before exiting.
func (h *Handler) gracefulShutdown() {
	if h.isLoggedIn() {
		h.authService.DestroySession(h.currentSession.ID)
		fmt.Printf("\n  %sSession ended for %s.%s\n", colorDim, h.currentUser.Username, colorReset)
	}
	if h.line != nil {
		h.line.Close()
	}
	fmt.Println("\n  Goodbye! ")
	os.Exit(0)
}

// ─── Display Helpers ────────────────────────────────────────────────────────

// displayUserDetails prints a formatted box with the user's account information.
func (h *Handler) displayUserDetails() {
	user := h.currentUser
	session := h.currentSession

	mfaStatus := fmt.Sprintf("%s✗ Disabled%s", colorRed, colorReset)
	if user.TOTPEnabled {
		mfaStatus = fmt.Sprintf("%s✓ Enabled%s", colorGreen, colorReset)
	}

	lastLogin := "First login"
	if user.LastLogin != nil {
		lastLogin = user.LastLogin.Format("2006-01-02 15:04:05 MST")
	}

	sessionExpiry := "N/A"
	sessionRemaining := ""
	if session != nil {
		sessionExpiry = session.ExpiresAt.Format("2006-01-02 15:04:05 MST")
		remaining := time.Until(session.ExpiresAt)
		sessionRemaining = " (" + formatDuration(remaining) + " remaining)"
	}

	fmt.Printf("\n  %s╭───────────────────────────────────────────────╮%s\n", colorCyan, colorReset)
	fmt.Printf("  %s│%s            %s%sUser Details%s                       %s│%s\n", colorCyan, colorReset, colorBold, colorCyan, colorReset, colorCyan, colorReset)
	fmt.Printf("  %s├───────────────────────────────────────────────┤%s\n", colorCyan, colorReset)
	fmt.Printf("  %s│%s  %-14s %-29s %s│%s\n", colorCyan, colorReset, "Username:", user.Username, colorCyan, colorReset)
	fmt.Printf("  %s│%s  %-14s %-29s %s│%s\n", colorCyan, colorReset, "Registered:", user.CreatedAt.Format("2006-01-02 15:04:05"), colorCyan, colorReset)
	fmt.Printf("  %s│%s  %-14s %-38s %s│%s\n", colorCyan, colorReset, "MFA Status:", mfaStatus, colorCyan, colorReset)
	fmt.Printf("  %s│%s  %-14s %-29s %s│%s\n", colorCyan, colorReset, "Session Exp:", sessionExpiry, colorCyan, colorReset)
	if sessionRemaining != "" {
		fmt.Printf("  %s│%s  %-14s %-29s %s│%s\n", colorCyan, colorReset, "", sessionRemaining, colorCyan, colorReset)
	}
	fmt.Printf("  %s│%s  %-14s %-29s %s│%s\n", colorCyan, colorReset, "Last Login:", lastLogin, colorCyan, colorReset)
	fmt.Printf("  %s╰───────────────────────────────────────────────╯%s\n\n", colorCyan, colorReset)
}

// showPasswordRequirements displays the current password policy to the user.
func (h *Handler) showPasswordRequirements(policy *models.PasswordPolicy) {
	fmt.Printf("  %sPassword requirements:%s\n", colorDim, colorReset)
	fmt.Printf("    %s•%s At least %d characters (max %d)\n", colorDim, colorReset, policy.MinLength, policy.MaxLength)
	if policy.RequireUpper {
		fmt.Printf("    %s•%s At least one uppercase letter (A-Z)\n", colorDim, colorReset)
	}
	if policy.RequireLower {
		fmt.Printf("    %s•%s At least one lowercase letter (a-z)\n", colorDim, colorReset)
	}
	if policy.RequireDigit {
		fmt.Printf("    %s•%s At least one digit (0-9)\n", colorDim, colorReset)
	}
	if policy.RequireSpecial {
		fmt.Printf("    %s•%s At least one special character\n", colorDim, colorReset)
	}
	fmt.Println()
}

// printBanner displays the application startup banner.
func (h *Handler) printBanner() {
	fmt.Println()
	fmt.Printf("  %s%s╔══════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("  %s%s║%s     %s Auth CLI%s v%s                       %s%s║%s\n", colorBold, colorCyan, colorReset, colorBold, colorReset, h.cfg.AppVersion, colorBold, colorCyan, colorReset)
	fmt.Printf("  %s%s║%s     Secure Authentication System        %s%s║%s\n", colorBold, colorCyan, colorReset, colorBold, colorCyan, colorReset)
	fmt.Printf("  %s%s╚══════════════════════════════════════════╝%s\n", colorBold, colorCyan, colorReset)
	fmt.Println()
}

// getPrompt returns the appropriate prompt string based on auth state.
func (h *Handler) getPrompt() string {
	if h.isLoggedIn() {
		remaining := time.Until(h.currentSession.ExpiresAt).Round(time.Second)
		return fmt.Sprintf("%s%s%s [%s] > ", colorGreen, h.currentUser.Username, colorReset, formatDuration(remaining))
	}
	return fmt.Sprintf("%s❯%s ", colorCyan, colorReset)
}

// isLoggedIn returns true if the user has an active session.
func (h *Handler) isLoggedIn() bool {
	return h.currentUser != nil && h.currentSession != nil
}

// readPassword reads a password from the terminal without echoing.
func (h *Handler) readPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	fd := int(os.Stdin.Fd())
	password, err := term.ReadPassword(fd)
	fmt.Println() // Move to next line after hidden input

	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	return string(password), nil
}

// ─── Formatting Helpers ─────────────────────────────────────────────────────

// printCommand formats a single help entry.
func printCommand(cmd, desc string) {
	fmt.Printf("  %s%-18s%s %s\n", colorGreen, cmd, colorReset, desc)
}

// printSuccess prints a green success message.
func (h *Handler) printSuccess(msg string) {
	fmt.Printf("\n  %s %s%s\n\n", colorGreen, msg, colorReset)
}

// printError prints a red error message.
func (h *Handler) printError(msg string) {
	fmt.Printf("\n  %s %s%s\n\n", colorRed, msg, colorReset)
}

// printWarning prints a yellow warning message.
func (h *Handler) printWarning(msg string) {
	fmt.Printf("\n  %s  %s%s\n\n", colorYellow, msg, colorReset)
}

// formatDuration formats a duration into a human-readable string (e.g., "29m 45s").
func formatDuration(d time.Duration) string {
	if d < 0 {
		return "expired"
	}
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
