// Package auth - TOTP (Time-based One-Time Password) functionality.
// Implements Google Authenticator-compatible TOTP generation and validation
// using the pquerna/otp library (RFC 6238 compliant).
//
// TOTP secrets are encrypted at rest using AES-256-GCM to protect against
// database compromise. The encryption key is stored in configuration,
// not in the database.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// GenerateTOTPSecret creates a new TOTP secret for the given username.
// Returns the base32-encoded secret string that can be stored in the database
// and used to generate QR codes for authenticator apps.
func GenerateTOTPSecret(username string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "AuthCLI",
		AccountName: username,
		Period:      30,                // Standard 30-second rotation
		SecretSize:  32,                // 256-bit secret for strong security
		Digits:      otp.DigitsSix,     // Standard 6-digit codes
		Algorithm:   otp.AlgorithmSHA1, // SHA1 is the standard for Google Authenticator compatibility
	})
	if err != nil {
		return "", err
	}

	return key.Secret(), nil
}

// GenerateTOTPURL creates the otpauth:// URL used for QR code generation.
// This URL is scanned by authenticator apps like Google Authenticator.
func GenerateTOTPURL(username, secret string) string {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "AuthCLI",
		AccountName: username,
		Secret:      []byte(secret),
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		// Fallback: construct URL manually
		return "otpauth://totp/AuthCLI:" + username + "?secret=" + secret + "&issuer=AuthCLI"
	}
	return key.URL()
}

// ValidateTOTP checks if the provided code matches the current TOTP for the secret.
// Allows for clock skew of ±1 period (30 seconds) to account for time drift.
func ValidateTOTP(secret, code string) bool {
	valid, _ := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:     1,                // Allow ±1 period of clock drift
		Digits:   otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return valid
}

// ── TOTP Secret Encryption (AES-256-GCM) ───────────────────────────────────
// These functions protect TOTP secrets at rest in the database.
// Even if the database is compromised, the secrets cannot be recovered
// without the encryption key from the application configuration.

// deriveKey creates a 32-byte AES-256 key from an arbitrary-length password
// using SHA-256. This ensures the key is always the correct size for AES-256.
func deriveKey(keyStr string) []byte {
	hash := sha256.Sum256([]byte(keyStr))
	return hash[:]
}

// EncryptTOTPSecret encrypts a TOTP secret using AES-256-GCM.
// Returns a base64-encoded ciphertext that includes the nonce.
func EncryptTOTPSecret(secret, encryptionKey string) (string, error) {
	key := deriveKey(encryptionKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and prepend nonce to ciphertext
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(secret), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptTOTPSecret decrypts a base64-encoded AES-256-GCM ciphertext
// back to the original TOTP secret.
func DecryptTOTPSecret(encryptedSecret, encryptionKey string) (string, error) {
	if encryptedSecret == "" {
		return "", nil
	}

	key := deriveKey(encryptionKey)

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedSecret)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}
