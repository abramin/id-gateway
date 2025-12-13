package device

import (
	"crypto/sha256"
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

// GenerateDeviceID creates a new stable device identifier (cookie value).
func (s *Service) GenerateDeviceID() string {
	return uuid.New().String()
}

// ComputeFingerprint hashes stable User-Agent components.
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

// ValidateDeviceID checks if the device ID matches.
// When the session has no device ID (legacy), validation passes.
func (s *Service) ValidateDeviceID(sessionDeviceID, cookieDeviceID string) bool {
	if !s.enabled {
		return true
	}
	if sessionDeviceID == "" {
		return true
	}
	return sessionDeviceID == cookieDeviceID
}

// CompareFingerprints checks for fingerprint drift (soft signal).
// When the session has no fingerprint (legacy), comparison passes.
func (s *Service) CompareFingerprints(stored, current string) (matched bool, driftDetected bool) {
	if !s.enabled || stored == "" {
		return true, false
	}
	matched = stored == current
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
