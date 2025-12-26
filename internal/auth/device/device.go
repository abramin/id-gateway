package device

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/mssola/useragent"
)

type Service struct {
	enabled bool
}

func NewService(enabled bool) *Service {
	return &Service{enabled: enabled}
}

func (s *Service) GenerateDeviceID() string {
	return uuid.New().String()
}

// Note: Does NOT include IP address (too volatile; used only for contextual risk scoring).
func (s *Service) ComputeFingerprint(userAgentString string) string {
	if !s.enabled || userAgentString == "" {
		return ""
	}

	ua := useragent.New(userAgentString)
	browser, version := ua.Browser()

	majorVersion := "unknown"
	if version != "" {
		parts := strings.Split(version, ".")
		if len(parts) > 0 && parts[0] != "" {
			majorVersion = parts[0]
		}
	}

	os := ua.OS()
	platform := "desktop"
	if ua.Mobile() {
		platform = "mobile"
	}

	browser = strings.ToLower(strings.TrimSpace(browser))
	if browser == "" {
		browser = "unknown"
	}
	os = strings.ToLower(strings.TrimSpace(os))
	if os == "" {
		os = "unknown"
	}

	data := fmt.Sprintf("%s|%s|%s|%s", browser, majorVersion, os, platform)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// CompareFingerprints compares stored and current device fingerprints.
// using constant-time comparison to prevent timing attacks.
// Returns (matched, driftDetected).
func (s *Service) CompareFingerprints(stored, current string) (matched bool, driftDetected bool) {
	if !s.enabled {
		return true, false
	}
	// Use constant-time comparison to prevent timing attacks that could reveal fingerprint structure
	matched = subtle.ConstantTimeCompare([]byte(stored), []byte(current)) == 1
	driftDetected = !matched
	return matched, driftDetected
}

// ParseUserAgent extracts a human-readable device display name from User-Agent string.
// Returns format: "Browser on OS" (e.g., "Chrome on macOS", "Safari on iOS")
func ParseUserAgent(userAgentString string) string {
	if userAgentString == "" {
		return "Unknown Device"
	}

	ua := useragent.New(userAgentString)

	browser, _ := ua.Browser()
	os := ua.OS()

	if ua.Mobile() {
		platform := ua.Platform()
		if platform != "" {
			return strings.TrimSpace(browser + " on " + platform)
		}
	}

	if browser == "" {
		browser = "Unknown Browser"
	}
	if os == "" {
		os = "Unknown OS"
	}

	return strings.TrimSpace(browser + " on " + os)
}
