package device

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"credo/internal/auth/models"

	"github.com/mssola/useragent"
)

// Uses SHA-256 to avoid storing PII (raw user-agent and IP address).
func ComputeDeviceFingerprint(userAgent, ipAddress string) string {
	// Normalize inputs
	data := fmt.Sprintf("%s|%s", strings.ToLower(userAgent), ipAddress)

	// SHA-256 hash
	hash := sha256.Sum256([]byte(data))

	// Return hex-encoded hash (64 chars)
	return hex.EncodeToString(hash[:])
}

// ValidateDeviceFingerprint checks if the current device matches the session's fingerprint.
func ValidateDeviceFingerprint(session *models.Session, userAgent, ipAddress string) bool {
	if session.DeviceFingerprintHash == "" {
		return true // Device binding not enabled for this session
	}

	expected := ComputeDeviceFingerprint(userAgent, ipAddress)
	return session.DeviceFingerprintHash == expected
}

// ParseUserAgent extracts a human-readable device display name from User-Agent string.
// Returns format: "Browser on OS" (e.g., "Chrome on macOS", "Safari on iOS")
func ParseUserAgent(userAgent string) string {
	if userAgent == "" {
		return "Unknown Device"
	}

	ua := useragent.New(userAgent)

	browser, _ := ua.Browser()
	os := ua.OS()

	// Handle mobile devices
	if ua.Mobile() {
		platform := ua.Platform()
		if platform != "" {
			return strings.TrimSpace(browser + " on " + platform)
		}
	}

	// Desktop/other
	if browser == "" {
		browser = "Unknown Browser"
	}
	if os == "" {
		os = "Unknown OS"
	}

	return strings.TrimSpace(browser + " on " + os)
}
