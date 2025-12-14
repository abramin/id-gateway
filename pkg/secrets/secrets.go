package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"credo/internal/facts"
)

// Generate creates a cryptographically secure random secret.
// Returns a base64-encoded string suitable for use as API keys, client secrets, etc.
func Generate() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("could not generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Hash creates a bcrypt hash of the provided secret.
// Use this to securely store secrets for later verification.
func Hash(secret string) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("secret cannot be empty: %w", facts.ErrInvalidInput)
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			return "", fmt.Errorf("secret is too long: %w", facts.ErrInvalidInput)
		}
		return "", fmt.Errorf("could not hash secret: %w", err)
	}
	return string(hashed), nil
}

// Verify checks if a plaintext secret matches a bcrypt hash.
func Verify(secret, hash string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return fmt.Errorf("invalid secret: %w", facts.ErrInvalidInput)
		}
		return fmt.Errorf("could not verify secret: %w", err)
	}
	return nil
}
