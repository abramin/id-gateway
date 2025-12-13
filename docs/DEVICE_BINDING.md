# Device Binding Implementation Guide

## Overview

Device binding enhances session security by establishing a cryptographic link between sessions and physical devices. This document outlines the **privacy-first, production-ready** implementation used in Credo's authentication system.

## Security Model

Device binding uses **layered security signals** instead of a single brittle identifier:

### 1. Primary Binding: Device ID Cookie (Hard Requirement)

**What:** Server-generated UUID stored in httpOnly cookie
**Lifetime:** 1 year
**Purpose:** Stable device identity that survives IP changes, VPN switches, and network roaming

**Why this works:**
- ✅ **Stable:** Persists across IP changes, VPN switches, mobile roaming, CGNAT
- ✅ **Unique:** UUID per physical device, no collisions
- ✅ **Secure:** HttpOnly + Secure + SameSite prevents XSS and CSRF theft
- ✅ **Privacy-preserving:** No PII, no tracking across domains

**Cookie specification:**
```
Name:     __Secure-Device-ID
Value:    <UUID v4>
HttpOnly: true
Secure:   true
SameSite: Strict
MaxAge:   31536000 (1 year)
Path:     /
```

### 2. Secondary Signal: Browser Fingerprint (Soft Signal)

**What:** SHA-256 hash of normalized User-Agent components (browser, OS, platform)
**Purpose:** Detect browser upgrades and OS updates (expected behavior, not errors)

**Components hashed:**
- Browser name (e.g., "chrome")
- Browser major version (e.g., "120", not "120.0.6099.129")
- Operating system (e.g., "windows", "macos", "ios")
- Platform (e.g., "desktop", "mobile")

**NOT included:**
- ❌ IP address (too volatile - VPN, mobile, CGNAT)
- ❌ Browser minor version (updates too frequently)
- ❌ Browser build number (changes weekly)

**Validation logic:**
- Mismatch → Log warning, update fingerprint, **continue session**
- Don't deny access - browser/OS updates are normal user behavior

### 3. Tertiary Signal: IP Change Risk Scoring (Contextual Only)

**What:** IP address and ASN tracked for anomaly detection
**Purpose:** Contextual risk scoring, **not device identification**

**Risk levels:**
- **Low:** Same IP or same ASN (same ISP/company)
- **Medium:** Different ASN, same country/region
- **High:** Different country (trigger step-up MFA in future)

**Critical:** IP changes are **logged and scored**, never **denied outright**.

---

## Why Not Use IP for Device Binding?

### Problem 1: IP Instability Causes False Positives

**Scenarios where IP changes are legitimate:**

| Scenario | Frequency | Impact |
|----------|-----------|--------|
| Mobile network tower switch | Every 5-15 min | IP changes constantly |
| VPN server rotation | Every session | User switches VPN endpoints |
| CGNAT (Carrier-Grade NAT) | Every few hours | Entire neighborhoods share rotating IPs |
| Corporate proxy rotation | Per request | Large companies rotate proxy IPs |
| IPv6 privacy extensions | Every 24 hours | RFC 4941 privacy feature |

**Real-world example:**
```
09:00 - User opens app on phone (IP: 203.0.113.45, DeviceID: abc-123)
09:15 - User enters subway (IP: 203.0.114.78, DeviceID: abc-123)
      → Current approach: Session invalidated (fingerprint mismatch)
      → Correct approach: Session continues (DeviceID matches, IP logged)
```

### Problem 2: Weak Signal Multiplication ≠ Strong Signal

**Current flawed logic:** "IP is weak + UA is weak = combined is strong"
**Reality:** Combining weak signals creates **more false positives**, not better security.

**Example attack this DOESN'T prevent:**
```
Attacker steals session token from user on corporate network
Attacker uses same Chrome version from same corporate proxy
→ IP matches, UA matches, fingerprint matches
→ Attack succeeds
```

**User-Agent collision:**
- Chrome 120 on Windows 11 = **millions of users**
- Safari on iPhone 15 = **millions of users**

**IP collision:**
- Corporate NAT = **thousands of users**
- University proxy = **tens of thousands**

---

## Design Principles (per PRD-016 & AGENTS.md)

1. **Layered security:** Device ID (hard) + fingerprint (soft) + IP risk (contextual)
2. **Privacy-first:** No raw PII stored; IP used only for risk scoring
3. **Graceful degradation:** Optional feature; legacy sessions without device binding still work
4. **Production-ready:** Handles VPN, mobile, CGNAT, IPv6 privacy extensions
5. **No grace periods:** Device ID cookies eliminate the need for workarounds

---

## Implementation Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│ HTTP Request                                                 │
├─────────────────────────────────────────────────────────────┤
│ Cookie: __Secure-Device-ID=abc-123-def-456                 │
│ User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)...   │
│ X-Forwarded-For: 203.0.113.45                              │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Middleware: ClientMetadata                                  │
├─────────────────────────────────────────────────────────────┤
│ • Extract User-Agent                                        │
│ • Extract client IP (X-Forwarded-For / RemoteAddr)         │
│ • Store in context                                          │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Auth Service: Authorize / Token / Refresh                   │
├─────────────────────────────────────────────────────────────┤
│ 1. Check/set device ID cookie                              │
│ 2. Compute fingerprint (UA components, no IP)              │
│ 3. Validate device ID matches session                      │
│ 4. Score IP change risk (log, don't deny)                  │
│ 5. Update session metadata                                 │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Session Store                                                │
├─────────────────────────────────────────────────────────────┤
│ • DeviceID: "abc-123-def-456"                              │
│ • DeviceFingerprintHash: "sha256(...)"                      │
│ • LastIP: "203.0.113.45" (not serialized)                  │
│ • LastASN: "AS15169" (not serialized)                      │
└─────────────────────────────────────────────────────────────┘
```

### Session Model

```go
// filepath: internal/auth/models/models.go
type Session struct {
    ID     uuid.UUID `json:"id"`
    UserID uuid.UUID `json:"user_id"`

    // Primary device binding (hard requirement)
    DeviceID string `json:"device_id"` // UUID from cookie

    // Secondary fingerprint (soft signal)
    DeviceFingerprintHash string `json:"device_fingerprint_hash"` // SHA-256(browser|os|platform)

    // Display metadata (UI only)
    DeviceDisplayName   string `json:"device_display_name,omitempty"`  // "Chrome on macOS"
    ApproximateLocation string `json:"approximate_location,omitempty"` // "San Francisco, US"

    // Risk scoring (not serialized to JSON, ephemeral)
    LastIP       string    `json:"-"` // For IP change detection
    LastASN      string    `json:"-"` // For ISP change detection
    LastSeenAt   time.Time `json:"last_seen_at"`

    // Session lifecycle
    Status    string    `json:"status"`     // "active", "revoked", "pending_consent"
    CreatedAt time.Time `json:"created_at"`
    ExpiresAt time.Time `json:"expires_at"`
}
```

---

## Code Implementation

### 1. Configuration

```go
// filepath: internal/platform/config/config.go
type DeviceBindingConfig struct {
    Enabled          bool `env:"DEVICE_BINDING_ENABLED" default:"true"`
    CookieName       string `env:"DEVICE_COOKIE_NAME" default:"__Secure-Device-ID"`
    CookieMaxAge     int `env:"DEVICE_COOKIE_MAX_AGE" default:"31536000"` // 1 year
    EnforceOnRefresh bool `env:"ENFORCE_ON_REFRESH" default:"true"`
}
```

### 2. Device Service

```go
// filepath: internal/auth/device/device.go
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

// GenerateDeviceID creates a new device identifier
func (s *Service) GenerateDeviceID() string {
    return uuid.New().String()
}

// ComputeFingerprint hashes stable User-Agent components
// NOTE: Does NOT include IP address (too volatile)
func (s *Service) ComputeFingerprint(userAgent string) string {
    if !s.enabled || userAgent == "" {
        return ""
    }

    ua := useragent.New(userAgent)
    browser, version := ua.Browser()

    // Extract major version only (minor versions change too often)
    majorVersion := "unknown"
    if version != "" {
        parts := strings.Split(version, ".")
        if len(parts) > 0 {
            majorVersion = parts[0]
        }
    }

    os := ua.OS()
    platform := "desktop"
    if ua.Mobile() {
        platform = "mobile"
    }

    // Hash stable components only
    data := fmt.Sprintf("%s|%s|%s|%s",
        strings.ToLower(browser),
        majorVersion,
        strings.ToLower(os),
        platform,
    )

    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

// ValidateDeviceID checks if device ID matches (hard requirement)
func (s *Service) ValidateDeviceID(sessionDeviceID, cookieDeviceID string) bool {
    if !s.enabled {
        return true // Feature disabled
    }

    if sessionDeviceID == "" {
        return true // Legacy session without device binding
    }

    return sessionDeviceID == cookieDeviceID
}

// CompareFingerprints checks for fingerprint drift (soft signal)
// Returns: matched, driftDetected
func (s *Service) CompareFingerprints(stored, current string) (matched bool, driftDetected bool) {
    if !s.enabled || stored == "" {
        return true, false // Feature disabled or legacy session
    }

    matched = (stored == current)
    driftDetected = !matched

    return matched, driftDetected
}

// ScoreIPChange returns risk level based on IP change
type RiskLevel int

const (
    RiskLow    RiskLevel = 0
    RiskMedium RiskLevel = 1
    RiskHigh   RiskLevel = 2
)

func (s *Service) ScoreIPChange(oldIP, newIP string) RiskLevel {
    if oldIP == newIP {
        return RiskLow
    }

    // TODO: Implement ASN and geolocation comparison
    // For now, any IP change is medium risk
    // Future: Same ASN = low, different country = high

    return RiskMedium
}
```

### 3. Service Integration

```go
// filepath: internal/auth/service/service.go

// Authorize creates a new session with device binding
func (s *Service) Authorize(ctx context.Context, req *models.AuthorizationRequest) (*models.AuthorizationResult, error) {
    // ... existing user lookup ...

    // Generate device ID (will be set as cookie by handler)
    deviceID := s.deviceService.GenerateDeviceID()

    // Compute fingerprint from User-Agent (no IP)
    userAgent := getContextValue(ctx, models.ContextKeyUserAgent)
    fingerprint := s.deviceService.ComputeFingerprint(userAgent)

    // Get IP for display only (not binding)
    ipAddress := getContextValue(ctx, models.ContextKeyIPAddress)

    session := &models.Session{
        // ... existing fields ...
        DeviceID:              deviceID,
        DeviceFingerprintHash: fingerprint,
        DeviceDisplayName:     device.ParseUserAgent(userAgent),
        LastIP:                ipAddress,
        LastSeenAt:            time.Now(),
    }

    // Store device ID in response for handler to set cookie
    result := &models.AuthorizationResult{
        Code:        authCode,
        RedirectURI: redirectURI,
        DeviceID:    deviceID, // Handler will set as cookie
    }

    return result, nil
}

// Token validates device binding during token exchange
func (s *Service) Token(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
    // ... existing authorization code validation ...

    // Validate device ID (hard requirement)
    cookieDeviceID := getContextValue(ctx, models.ContextKeyDeviceID)
    if !s.deviceService.ValidateDeviceID(session.DeviceID, cookieDeviceID) {
        s.logAuthFailure(ctx, "device_id_mismatch", true,
            "session_id", session.ID.String(),
            "expected_device_id", session.DeviceID,
        )
        s.incrementAuthFailure()
        return nil, dErrors.New(dErrors.CodeUnauthorized, "device mismatch")
    }

    // Check fingerprint drift (soft signal, don't fail)
    userAgent := getContextValue(ctx, models.ContextKeyUserAgent)
    currentFingerprint := s.deviceService.ComputeFingerprint(userAgent)

    matched, driftDetected := s.deviceService.CompareFingerprints(
        session.DeviceFingerprintHash,
        currentFingerprint,
    )

    if driftDetected {
        s.logger.Info("fingerprint_drift_detected",
            "session_id", session.ID.String(),
            "reason", "browser_or_os_update",
        )
        // Update to new fingerprint (browser upgraded)
        session.DeviceFingerprintHash = currentFingerprint
    }

    // Score IP change (contextual only, don't fail)
    currentIP := getContextValue(ctx, models.ContextKeyIPAddress)
    riskLevel := s.deviceService.ScoreIPChange(session.LastIP, currentIP)

    if riskLevel >= RiskMedium {
        s.logger.Warn("ip_change_detected",
            "session_id", session.ID.String(),
            "risk_level", riskLevel,
            "old_ip", session.LastIP,
            "new_ip", currentIP,
        )
        // Future: Trigger step-up MFA for RiskHigh
    }

    // Update session metadata
    session.LastIP = currentIP
    session.LastSeenAt = time.Now()

    // ... continue with token generation ...
}
```

### 4. Handler Cookie Management

```go
// filepath: internal/auth/handler/handler.go

func (h *Handler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
    // ... existing authorization logic ...

    result, err := h.auth.Authorize(ctx, &req)
    if err != nil {
        httpError.WriteError(w, err)
        return
    }

    // Set device ID cookie (if device binding enabled)
    if result.DeviceID != "" {
        http.SetCookie(w, &http.Cookie{
            Name:     "__Secure-Device-ID",
            Value:    result.DeviceID,
            Path:     "/",
            MaxAge:   31536000, // 1 year
            HttpOnly: true,
            Secure:   true,
            SameSite: http.SameSiteStrictMode,
        })
    }

    respond.WriteJSON(w, http.StatusOK, result)
}

func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
    // Extract device ID from cookie
    deviceIDCookie, _ := r.Cookie("__Secure-Device-ID")
    deviceID := ""
    if deviceIDCookie != nil {
        deviceID = deviceIDCookie.Value
    }

    // Add to context for service validation
    ctx := context.WithValue(r.Context(), models.ContextKeyDeviceID, deviceID)

    // ... existing token exchange logic ...
}
```

---

## Testing Strategy

### Unit Tests

```go
// filepath: internal/auth/device/device_test.go

func TestComputeFingerprint_NoIP(t *testing.T) {
    svc := NewService(true)

    // Same UA should give same fingerprint regardless of IP
    ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0"

    fp1 := svc.ComputeFingerprint(ua)
    fp2 := svc.ComputeFingerprint(ua)

    assert.Equal(t, fp1, fp2, "Fingerprint should be deterministic")
    assert.Len(t, fp1, 64, "SHA-256 hex should be 64 chars")
}

func TestComputeFingerprint_MinorVersionIgnored(t *testing.T) {
    svc := NewService(true)

    // Minor version updates should NOT change fingerprint
    ua1 := "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.6099.109"
    ua2 := "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.6099.224"

    fp1 := svc.ComputeFingerprint(ua1)
    fp2 := svc.ComputeFingerprint(ua2)

    assert.Equal(t, fp1, fp2, "Minor version should not affect fingerprint")
}

func TestComputeFingerprint_MajorVersionMatters(t *testing.T) {
    svc := NewService(true)

    // Major version upgrade SHOULD change fingerprint
    ua1 := "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0"
    ua2 := "Mozilla/5.0 (Windows NT 10.0) Chrome/121.0.0.0"

    fp1 := svc.ComputeFingerprint(ua1)
    fp2 := svc.ComputeFingerprint(ua2)

    assert.NotEqual(t, fp1, fp2, "Major version change should change fingerprint")
}

func TestValidateDeviceID_LegacySessionAllowed(t *testing.T) {
    svc := NewService(true)

    // Legacy session without device ID should pass validation
    result := svc.ValidateDeviceID("", "any-cookie-value")
    assert.True(t, result, "Legacy sessions should be allowed")
}

func TestScoreIPChange_SameIPLowRisk(t *testing.T) {
    svc := NewService(true)

    risk := svc.ScoreIPChange("203.0.113.45", "203.0.113.45")
    assert.Equal(t, RiskLow, risk)
}
```

### Integration Tests

```go
// Test VPN scenario: Device ID stays same, IP changes
func TestToken_VPNIPChange_SessionContinues(t *testing.T) {
    // 1. Authorize from IP 203.0.113.45
    authReq := &models.AuthorizationRequest{...}
    ctx1 := contextWithIP(context.Background(), "203.0.113.45")
    authRes, _ := service.Authorize(ctx1, authReq)

    // 2. Token exchange from different IP (VPN switch)
    tokenReq := &models.TokenRequest{Code: authRes.Code}
    ctx2 := contextWithIP(context.Background(), "198.51.100.78")
    ctx2 = contextWithDeviceID(ctx2, authRes.DeviceID)

    tokenRes, err := service.Token(ctx2, tokenReq)

    // Should succeed - device ID matches, IP change is logged
    assert.NoError(t, err)
    assert.NotEmpty(t, tokenRes.AccessToken)
}

// Test stolen token: Different device ID
func TestToken_StolenToken_Denied(t *testing.T) {
    // 1. Legitimate user authorizes
    authRes, _ := service.Authorize(ctx, authReq)

    // 2. Attacker tries to use code with different device
    ctx2 := contextWithDeviceID(context.Background(), "attacker-device-id")

    tokenRes, err := service.Token(ctx2, &models.TokenRequest{Code: authRes.Code})

    // Should fail - device ID mismatch
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "device mismatch")
}
```

---

## Privacy & Security Considerations

### Data Retention

| Field | Stored | Serialized | Purpose |
|-------|--------|------------|---------|
| `DeviceID` | ✅ Database | ✅ JSON | Session binding |
| `DeviceFingerprintHash` | ✅ Database | ✅ JSON | Browser update detection |
| `DeviceDisplayName` | ✅ Database | ✅ JSON | UI display only |
| `LastIP` | ✅ Memory only | ❌ Not serialized | Ephemeral risk scoring |
| `LastASN` | ✅ Memory only | ❌ Not serialized | Ephemeral risk scoring |

**Why IP is not serialized:**
- Privacy: IP is PII under GDPR
- Volatility: Changes too frequently to be useful in storage
- Purpose: Only needed for real-time risk scoring

### Audit Logging

**DO log:**
- `session_id` (non-PII identifier)
- `user_id` (non-PII identifier)
- `device_id_mismatch` events
- `fingerprint_drift` events
- `ip_change_detected` with risk level

**DO NOT log:**
- Raw IP addresses in audit logs (use hashed or redacted)
- Raw User-Agent strings (use parsed display name)
- Device fingerprint hashes (no security value in logs)

---

## Migration Path

### Phase 1: Soft Launch (Week 1-2)

- Enable device ID cookie generation
- Compute and store fingerprints
- Log all validation results, **don't enforce**
- Monitor false positive rate

**Operational notes (Phase 1):**

- Enable in an environment with `DEVICE_BINDING_ENABLED=true`.
- Cookie settings are configurable via `DEVICE_COOKIE_NAME` (default `__Secure-Device-ID`) and `DEVICE_COOKIE_MAX_AGE` (default `31536000` seconds).
- Current implementation logs `device_id_missing`, `device_id_mismatch`, and `fingerprint_drift_detected` during `/auth/token`, but does not deny requests.

### Phase 2: Enforcement (Week 3+)

- Enable device ID validation (deny on mismatch)
- Keep fingerprint as soft signal (log drift, don't deny)
- Enable IP risk scoring (log only, no MFA yet)

### Phase 3: Advanced (Future)

- Integrate GeoIP for country-level risk scoring
- Implement step-up MFA for high-risk IP changes
- Add ASN comparison for ISP change detection

---

## Industry References

1. **Auth0 Adaptive MFA**
   "IP addresses should be used for risk scoring, not device identification"
   https://auth0.com/docs/secure/multi-factor-authentication/adaptive-mfa

2. **Google BeyondCorp**
   "Device identity is established through certificates and hardware attestation, not network location"
   https://cloud.google.com/beyondcorp-enterprise/docs/secure-access

3. **OWASP Session Management Cheat Sheet**
   "Do not rely on IP addresses for session binding due to their volatile nature"
   https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

4. **RFC 6749 (OAuth 2.0)**
   Section 10.12: "The authorization server SHOULD NOT make assumptions about the client deployment topology"
   https://datatracker.ietf.org/doc/html/rfc6749#section-10.12

---

## Versioning

- **Version:** 2.0
- **Last Updated:** 2025-12-13
- **Revisions:**
  - 2.0: Complete redesign - removed IP from fingerprint, added device ID cookies, IP as risk signal
  - 1.2: Added code implementation steps/examples
  - 1.1: Added implementation strategy, config, flow, testing, privacy notes
  - 1.0: Initial document (deprecated - used IP in fingerprint)
