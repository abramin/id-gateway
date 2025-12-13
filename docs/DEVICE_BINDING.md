// ...existing content...

## Implementation Strategy (per PRD-016 & AGENTS.md)

### Design Principles

- Optional, config-driven feature; graceful degradation when disabled.
- No PII stored: only SHA-256 hash of normalized user-agent + IP.
- Handlers stay thin; middleware extracts metadata; services orchestrate validation.
- Backward compatible: legacy sessions without fingerprints still work.

### Components

- **Config:** `DeviceBinding.Enabled`, `EnforceOnRefresh`, `GracePeriod`.
- **Middleware:** `ClientMetadata` populates `User-Agent` and client IP in context.
- **Fingerprint Service:** Computes/validates hash; returns empty when disabled; tolerant of missing legacy data.
- **Session Model:** `DeviceFingerprintHash` (optional), `DeviceDisplayName`, `ApproximateLocation`.
- **Service Hooks:**
  - On authorize: compute and store fingerprint; set display name/location.
  - On refresh: validate fingerprint when enabled; apply grace period; log security events; optionally step-up/MFA in future.

### Flow (High Level)

1. Request enters with metadata middleware (captures UA/IP).
2. Authorize: service computes fingerprint (or empty), saves on session.
3. Token refresh: service validates fingerprint if enabled; within grace period allow with warning; otherwise deny and revoke/step-up.
4. Tokens issued; audit logs include session ID (not token or fingerprint).

### Configuration Examples

- Dev: disabled; no enforcement.
- Prod: enabled; enforce on refresh; 24h grace for VPN/mobile changes.
- High-security: enabled; strict grace (e.g., 1h).

### Testing Guidance

- Fingerprint service unit tests: enabled/disabled, case/whitespace normalization, match/mismatch.
- Service tests: authorize stores fingerprint; refresh enforces/permits per config/grace; legacy sessions without fingerprint pass.

### Privacy & Security

- Hash only (no raw UA/IP persisted).
- Grace period to reduce false positives; consider step-up MFA for mismatches later.
- Audit with IDs (session_id, user_id), never raw tokens/fingerprints.

// ...existing content...

### Code Implementation (Step-by-Step)

1. **Config**

```go
// filepath: internal/auth/config.go
type DeviceBindingConfig struct {
    Enabled          bool          `yaml:"enabled" env:"DEVICE_BINDING_ENABLED" default:"false"`
    EnforceOnRefresh bool          `yaml:"enforce_on_refresh" env:"ENFORCE_ON_REFRESH" default:"true"`
    GracePeriod      time.Duration `yaml:"grace_period" env:"GRACE_PERIOD" default:"24h"`
}
```

2. **Middleware** (already present)

```go
// filepath: internal/platform/middleware/middleware.go
// ClientMetadata middleware captures User-Agent and client IP into context.
func ClientMetadata(next http.Handler) http.Handler { /* ...existing code... */ }
func GetUserAgent(ctx context.Context) string       { /* ...existing code... */ }
func GetClientIP(ctx context.Context) string        { /* ...existing code... */ }
```

3. **Fingerprint Service**

```go
// filepath: internal/auth/fingerprint/fingerprint.go
package fingerprint

type Service struct {
    config Config
}
type Config struct {
    Enabled bool
}
func NewService(c Config) *Service { return &Service{config: c} }
func (s *Service) Compute(userAgent, ip string) string { /* sha256 of normalized UA|IP; empty if disabled */ }
func (s *Service) Validate(stored, userAgent, ip string) bool { /* disabled → true; empty stored → true; else hash match */ }
```

4. **Session Model** (already has field)

```go
// filepath: internal/auth/models/models.go
type Session struct {
    // ...
    DeviceFingerprintHash string `json:"device_fingerprint_hash,omitempty"`
    DeviceDisplayName     string `json:"device_display_name,omitempty"`
    ApproximateLocation   string `json:"approximate_location,omitempty"`
    // ...
}
```

5. **Service Integration**

```go
// filepath: internal/auth/service/service.go
type Service struct {
    sessions      SessionStore
    codes         AuthorizationCodeStore
    refreshTokens RefreshTokenStore
    fingerprint   *fingerprint.Service
    config        Config
    logger        Logger
}

// On authorize: compute & store fingerprint
func (s *Service) Authorize(ctx context.Context, req *models.AuthorizationRequest) (*models.AuthorizationResult, error) {
    ua := middleware.GetUserAgent(ctx)
    ip := middleware.GetClientIP(ctx)
    fp := s.fingerprint.Compute(ua, ip)
    // set DeviceFingerprintHash on session; also DeviceDisplayName/ApproximateLocation if available
    // ...existing logic...
}

// On refresh: validate fingerprint (graceful if disabled/legacy)
func (s *Service) TokenRefresh(ctx context.Context, req *models.TokenRefreshRequest) (*models.TokenResult, error) {
    // load session/refresh token...
    if s.config.DeviceBinding.EnforceOnRefresh {
        ua := middleware.GetUserAgent(ctx)
        ip := middleware.GetClientIP(ctx)
        if !s.fingerprint.Validate(session.DeviceFingerprintHash, ua, ip) {
            // optional: allow within GracePeriod, else deny
            // ...return error or step-up...
        }
    }
    // ...issue new tokens...
}
```

6. **Wiring in main**

```go
// filepath: cmd/server/main.go
fpSvc := fingerprint.NewService(fingerprint.Config{Enabled: cfg.Auth.DeviceBinding.Enabled})
authSvc := authservice.NewService(sessionStore, codeStore, refreshTokenStore, fpSvc, cfg.Auth, logger)

// Middleware order
router.Use(middleware.ClientMetadata)
router.Use(middleware.RequestID)
router.Use(middleware.Logger(logger))
```

7. **Testing Pointers**

```go
// filepath: internal/auth/fingerprint/fingerprint_test.go
func TestCompute_DisabledIsEmpty(t *testing.T)    { /* expect "" */ }
func TestCompute_EnabledIsHash(t *testing.T)      { /* expect 64-char hex */ }
func TestValidate_MatchAndMismatch(t *testing.T)  { /* same UA/IP true; diff UA/IP false; stored empty true */ }
```

---

## Versioning

- **Version:** 1.2
- **Last Updated:** 2025-12-13
- **Revisions:**
  - 1.2: Added code implementation steps/examples.
  - 1.1: Added implementation strategy, config, flow, testing, privacy notes.
  - 1.0: Initial document.
