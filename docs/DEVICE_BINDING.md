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

## Design Principles (per PRD-016)

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
