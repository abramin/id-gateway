# PRD-016: Token Lifecycle & Revocation

**Status:** Not Started
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Dependencies:** PRD-001 (Authentication & Session Management)
**Last Updated:** 2025-12-12

---

## 1. Overview

### Problem Statement

The current authentication system (PRD-001) provides only short-lived access tokens with no refresh mechanism, token revocation capability, or session management. Users cannot:

- Maintain long-lived sessions without re-authenticating
- Log out and invalidate tokens
- Revoke compromised tokens
- Manage sessions across multiple devices
- Invalidate all sessions on security events (password change, suspicious activity)

This is a **critical blocker** for production deployment.

### Goals

- Implement OAuth 2.0 refresh token flow (RFC 6749 Section 6)
- Provide token revocation endpoint (RFC 7009)
- Enable session-level and global logout
- Support concurrent session limits
- Invalidate tokens on security events
- Provide token binding to devices for enhanced security (see [DEVICE_BINDING.md](../DEVICE_BINDING.md))

### Non-Goals

- Sliding session windows (extend expiry on activity)
- Remember me / persistent sessions beyond refresh tokens
- Single Sign-On (SSO) across multiple applications
- Token introspection endpoint (RFC 7662) - can be added later

---

## 2. User Stories

**As a user**
**I want to** stay logged in for days without re-entering credentials
**So that** I have a convenient authentication experience

**As a user**
**I want to** log out and invalidate my session
**So that** my account is secure when I leave a shared device

**As a user**
**I want to** see and revoke active sessions on other devices
**So that** I can secure my account if my phone was stolen

**As a system administrator**
**I want to** revoke all sessions for a user on password change
**So that** compromised credentials don't persist

**As a security engineer**
**I want to** bind tokens to devices
**So that** stolen tokens can't be used from different IPs/devices

---

## 3. Functional Requirements

### FR-1: Refresh Token Issuance

**Endpoint:** `POST /auth/token` (extend existing endpoint)

**Description:** When exchanging authorization code for tokens, also issue a refresh token for long-lived sessions.

**Input (Token Exchange):**

```json
{
  "grant_type": "authorization_code",
  "code": "authz_abc123xyz",
  "redirect_uri": "https://app.example.com/callback",
  "client_id": "demo-client"
}
```

**Output (Enhanced Response):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "id_token": "idt_550e8400-e29b-41d4-a716-446655440000",
  "refresh_token": "ref_7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile"
}
```

**Business Logic:**

1. On successful authorization code exchange (existing flow)
2. Generate refresh token:
   - Format: `"ref_" + uuid.New().String()`
   - Store refresh token in session record
   - Set refresh token expiry: 30 days from issuance
3. Bind token to device (see [DEVICE_BINDING.md](../DEVICE_BINDING.md) for security model)
4. Return refresh token alongside access token
5. Emit audit event: `refresh_token_issued`

**Refresh Token Properties:**

- **Long-lived:** 30 days (configurable)
- **Single-use:** Consumed on refresh, new refresh token issued (rotation)
- **Revocable:** Can be explicitly revoked via logout
- **Device-bound:** (Optional) Bound via device ID cookie + browser fingerprint drift detection (soft) — see `docs/DEVICE_BINDING.md`

---

### FR-2: Token Refresh

**Endpoint:** `POST /auth/token` (extend with new grant type)

**Description:** Exchange a valid refresh token for a new access token without re-authentication.

**Input:**

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "ref_7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "client_id": "demo-client"
}
```

**Output (Success - 200):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", // NEW token
  "id_token": "idt_550e8400-e29b-41d4-a716-446655440000",
  "refresh_token": "ref_9a1b2c3d-4e5f-6789-0abc-def123456789", // NEW refresh token (rotation)
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile"
}
```

**Business Logic:**

1. Validate `grant_type` is `"refresh_token"`
2. Validate `refresh_token` and `client_id` are provided
3. Find session by refresh token in SessionStore
4. If session not found → 401 Invalid refresh token
5. Validate refresh token has not expired (< 30 days old)
6. Validate refresh token has not been revoked (session status != "revoked")
7. Validate device binding (see [DEVICE_BINDING.md](../DEVICE_BINDING.md) for validation logic)
8. **Refresh Token Rotation:**
   - Revoke old refresh token (mark as used)
   - Generate new refresh token
   - Update session with new refresh token
9. Generate new access token (new expiry, same session_id)
10. Generate new ID token
11. Update session `LastRefreshedAt` timestamp
12. Emit audit event: `token_refreshed`
13. Return new tokens

**Error Cases (RFC 6749 §5.2):**

- 400 Bad Request: Missing required fields (`invalid_request`)
- 400 Bad Request: Invalid grant_type (`unsupported_grant_type`)
- 400 Bad Request: Invalid refresh token - not found (`invalid_grant`)
- 400 Bad Request: Expired refresh token (`invalid_grant`)
- 400 Bad Request: Refresh token already used - rotation violation (`invalid_grant`)
- 400 Bad Request: Session revoked (`invalid_grant`)
- 400 Bad Request: Device mismatch (`invalid_grant` with additional context)
- 500 Internal Server Error: Store failure

**Note (RFC 6749 §5.2):** All grant-related errors return HTTP 400 with the appropriate OAuth error code. HTTP 401 is reserved for client authentication failures via HTTP Authorization header.

**Security - Token Rotation:**

- When refresh token is used, it is immediately invalidated
- A new refresh token is issued (rotation)
- If an old refresh token is reused → indicates replay attack → revoke entire session family

---

### FR-3: Token Revocation (Logout)

**Endpoint:** `POST /auth/revoke`

**Description:** Revoke access and refresh tokens, effectively logging out the user.

**Input:**

```json
{
  "token": "ref_7c9e6679-7425-40de-944b-e07fc1f90ae7", // Can be access_token or refresh_token
  "token_type_hint": "refresh_token" // Optional hint: "access_token" or "refresh_token"
}
```

**Output (Success - 200):**

```json
{
  "revoked": true,
  "message": "Token revoked successfully"
}
```

**Business Logic:**

1. Extract token from request
2. Determine token type:
   - If `token_type_hint` provided, use it
   - Else, parse token (JWT vs opaque)
3. If access token (JWT):
   - Extract `session_id` from JWT claims
   - Find session by ID
4. If refresh token (opaque):
   - Find session by refresh token
5. If session not found → 200 (idempotent, already revoked)
6. Update session status to "revoked"
7. Set `RevokedAt` timestamp
8. Clear refresh token from session
9. Add access token `jti` to revocation list (Redis set with TTL = token expiry)
10. Emit audit event: `token_revoked`
11. Return success

**Token Revocation List (TRL):**

- Store revoked access token JTIs in Redis
- Key: `revoked_tokens:{jti}`
- TTL: Same as token expiry (no need to store expired tokens)
- Check TRL on every authenticated request via middleware

**Error Cases (RFC 7009 §2.2):**

- 400 Bad Request: Missing token (`invalid_request`)
- 200 OK: Token invalid, unknown, or already revoked (idempotent per RFC 7009)
- 500 Internal Server Error: Store failure

**Note (RFC 7009 §2.2):** The revocation endpoint returns HTTP 200 even if the token was already invalid, expired, or revoked. This ensures idempotent behavior.

---

### FR-4: Session Management

**Endpoint:** `GET /auth/sessions`

**Description:** List all active sessions for the authenticated user.

**Input:**

- Header: `Authorization: Bearer <access_token>`

**Output (Success - 200):**

```json
{
  "sessions": [
    {
      "session_id": "sess_abc123",
      "device": "Chrome on macOS",
      "location": "San Francisco, US",
      "created_at": "2025-12-01T10:00:00Z",
      "last_activity": "2025-12-12T15:30:00Z",
      "is_current": true
    },
    {
      "session_id": "sess_def456",
      "device": "Safari on iPhone",
      "location": "San Francisco, US",
      "created_at": "2025-12-10T08:00:00Z",
      "last_activity": "2025-12-11T12:00:00Z",
      "is_current": false
    }
  ]
}
```

**Business Logic:**

1. Extract user from bearer token
2. Query SessionStore for all active sessions for user
3. For each session:
   - Derive device info from stored metadata (see note below)
   - Mark current session (match session_id from token)
4. Return session list

**Note on Device Display:**

With privacy-first design (hashed fingerprints), we need to capture device metadata separately for display:

**Store display-safe metadata on Session:**

```go
type Session struct {
    // ... other fields
    DeviceFingerprintHash string   // For security validation
    DeviceDisplayName     string   // For UI display: "Chrome on macOS"
    ApproximateLocation   string   // For UI display: "San Francisco, US" (from IP at creation)
}
```

---

### FR-5: Revoke Specific Session

**Endpoint:** `DELETE /auth/sessions/{session_id}`

**Description:** Revoke a specific session by ID (logout from another device).

**Input:**

- Header: `Authorization: Bearer <access_token>`
- Path: `session_id`

**Output (Success - 200):**

```json
{
  "revoked": true,
  "session_id": "sess_def456",
  "message": "Session revoked successfully"
}
```

**Business Logic:**

1. Extract user from bearer token
2. Validate user owns the session (session.user_id == token.user_id)
3. If not owner → 403 Forbidden
4. Update session status to "revoked"
5. Add session's access token JTI to revocation list
6. Emit audit event: `session_revoked`
7. Return success

---

### FR-6: Revoke All Sessions (Global Logout)

**Endpoint:** `POST /auth/logout-all`

**Description:** Revoke all sessions for the authenticated user (except optionally the current one).

**Input:**

- Header: `Authorization: Bearer <access_token>`

**Query Params:**

- `except_current` (optional, default: true) - Keep current session active

**Output (Success - 200):**

```json
{
  "revoked_count": 3,
  "message": "All sessions revoked successfully"
}
```

**Business Logic:**

1. Extract user and current session_id from bearer token
2. Query SessionStore for all active sessions for user
3. For each session:
   - If `except_current=true` AND session is current session → skip
   - Else → revoke session (status="revoked", add JTI to TRL)
4. Emit audit event: `all_sessions_revoked`
5. Return revoked count

**Use Cases:**

- User suspects account compromise
- Password change (security event)
- User wants to log out everywhere

---

## 4. Technical Requirements

### Architectural Decision: Separated Lifecycle Models

**Context:** The initial design proposed a single `Session` struct containing authorization codes, refresh tokens, and session metadata. However, these have fundamentally different lifetimes:

| Artifact           | Lifetime   | Purpose                         |
| ------------------ | ---------- | ------------------------------- |
| Authorization Code | 10 minutes | Exchange for initial tokens     |
| Refresh Token      | 30 days    | Renew access tokens             |
| Session            | 30+ days   | Track user authentication state |

**Problem:** Mixing lifetimes in one struct causes:

- **Memory waste:** Dead fields occupy space for 30+ days (e.g., `Code` field unused after 10 minutes)
- **Unclear ownership:** Which expiry matters? `CodeExpiresAt` or `SessionExpiresAt`?
- **Privacy risks:** Storing raw `UserAgent` and `IPAddress` increases PII exposure
- **Difficult cleanup:** Cannot delete expired codes without touching sessions
- **Technical debt:** Pattern calcifies quickly, requiring data migration to fix later

**Decision:** Separate into three focused models with single responsibility.

**Benefits:**

1. Each model has one clear lifetime and expiry concept
2. Independent cleanup (delete expired codes without touching sessions)
3. Privacy-first design (hash device fingerprints, no raw PII)
4. Easier token rotation (update refresh token without touching session)
5. Clear upgrade path to persistence (add Redis/Postgres per model)
6. Reduced memory footprint (no dead fields)

---

### TR-1: Separated Lifecycle Models

**Rationale:** Authorization codes (10 min), refresh tokens (30 days), and sessions (30+ days) have distinct lifetimes. Mixing them in one struct causes:

- Dead fields occupying memory for extended periods
- Ambiguous cleanup logic (which expiry matters?)
- Privacy risks from storing raw user-agent/IP data
- Difficult token rotation and lifecycle management

**Solution:** Separate models with single responsibility and privacy-first design.

---

#### Session Model (Location: `internal/auth/models.go`)

Core long-lived session representing user authentication state.

```go
// Session represents a user's authentication session with the authorization server.
// Lifetime: 30+ days (configurable)
type Session struct {
    ID             uuid.UUID  `json:"id"`
    UserID         uuid.UUID  `json:"user_id"`
    ClientID       string     `json:"client_id"`
    RequestedScope []string   `json:"requested_scope"`
    Status         string     `json:"status"` // "active", "revoked"

    // Device binding for security - See DEVICE_BINDING.md for full security model
    DeviceID              string `json:"device_id"`                // Primary: UUID from cookie (hard requirement)
    DeviceFingerprintHash string `json:"device_fingerprint_hash"` // Secondary: SHA-256(browser|os|platform) - no IP
    DeviceDisplayName     string `json:"device_display_name,omitempty"` // UI display: "Chrome on macOS"
    ApproximateLocation   string `json:"approximate_location,omitempty"` // UI display: "San Francisco, US"
    LastSeenAt            time.Time `json:"last_seen_at"` // Last activity timestamp

    // Lifecycle timestamps
    CreatedAt      time.Time  `json:"created_at"`
    ExpiresAt      time.Time  `json:"expires_at"`  // Session expiry (30+ days)
    RevokedAt      *time.Time `json:"revoked_at,omitempty"`
}
```

**Design Notes:**

- No authorization code or refresh token fields (separated below)
- Device binding uses layered security model (see [DEVICE_BINDING.md](../DEVICE_BINDING.md)):
  - `DeviceID`: UUID from httpOnly cookie (primary binding)
  - `DeviceFingerprintHash`: SHA-256(browser|os|platform) - **no IP** (soft signal)
  - Display metadata for UI only, no raw PII stored
- Single expiry concept: when the session ends
- Status field for explicit revocation tracking

---

#### AuthorizationCode Model (Location: `internal/auth/models.go`)

Ephemeral authorization code for OAuth 2.0 code exchange flow.

```go
// AuthorizationCode represents a short-lived OAuth 2.0 authorization code.
// Lifetime: 10 minutes
type AuthorizationCode struct {
    ID          uuid.UUID `json:"id"`
    Code        string    `json:"code"`           // Format: "authz_<random>"
    SessionID   uuid.UUID `json:"session_id"`     // Links to parent Session
    RedirectURI string    `json:"redirect_uri"`   // Stored for validation at token exchange
    ExpiresAt   time.Time `json:"expires_at"`     // 10 minutes from creation
    Used        bool      `json:"used"`           // Prevent replay attacks
    CreatedAt   time.Time `json:"created_at"`
}
```

**Design Notes:**

- Single purpose: exchange for tokens
- Self-contained expiry (10 minutes)
- Links to Session via `SessionID`
- Can be deleted immediately after use or after expiry
- Independent cleanup: delete all expired codes without touching sessions

---

#### RefreshToken Model (Location: `internal/auth/models.go`)

Long-lived token for renewing access tokens without re-authentication.

```go
// RefreshToken represents a long-lived token for access token renewal.
// Lifetime: 30 days (configurable)
type RefreshToken struct {
    ID          uuid.UUID `json:"id"`
    Token           string     `json:"token"`             // Format: "ref_<uuid>"
    SessionID       uuid.UUID  `json:"session_id"`        // Links to parent Session
    ExpiresAt       time.Time  `json:"expires_at"`        // 30 days from creation
    Used            bool       `json:"used"`              // For rotation detection
    LastRefreshedAt *time.Time `json:"last_refreshed_at,omitempty"`
    CreatedAt       time.Time  `json:"created_at"`
}
```

**Design Notes:**

- Single purpose: renew access tokens
- Self-contained expiry (30 days)
- Links to Session via `SessionID`
- `Used` flag enables rotation detection (replay attack prevention)
- Independent cleanup: delete used/expired refresh tokens without affecting session

---

#### Device Binding

**See [DEVICE_BINDING.md](../DEVICE_BINDING.md) for complete implementation details.**

The device binding implementation uses a layered security model:

1. **Primary binding:** Device ID cookie (UUID, httpOnly, stable across IP changes)
2. **Secondary signal:** Browser fingerprint (SHA-256 of UA components, **no IP**)
3. **Tertiary signal:** IP change risk scoring (contextual only, not for binding)

**Key design principles:**

- Privacy-first: No raw PII stored
- Production-ready: Handles VPN, mobile, CGNAT scenarios
- Security-focused: Device ID prevents token theft, fingerprint detects browser updates
- Graceful degradation: Works with legacy sessions

Refer to [DEVICE_BINDING.md](../DEVICE_BINDING.md) for:

- Security rationale (why IP binding fails in production)
- Complete code implementation
- Testing strategies
- Migration path

---

#### Store Interfaces (Location: `internal/auth/store.go`)

Update store interfaces to handle separated models.

```go
// SessionStore manages user authentication sessions.
type SessionStore interface {
    // Session CRUD
    CreateSession(ctx context.Context, session *Session) error
    GetSession(ctx context.Context, id uuid.UUID) (*Session, error)
    GetSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]*Session, error)
    UpdateSessionStatus(ctx context.Context, id uuid.UUID, status string, revokedAt *time.Time) error
    DeleteSession(ctx context.Context, id uuid.UUID) error

    // Cleanup
    DeleteExpiredSessions(ctx context.Context) (int, error)
}

// AuthorizationCodeStore manages short-lived authorization codes.
type AuthorizationCodeStore interface {
    // AuthorizationCode CRUD
    CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error
    GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
    MarkAuthorizationCodeUsed(ctx context.Context, code string) error
    DeleteAuthorizationCode(ctx context.Context, code string) error

    // Cleanup
    DeleteExpiredCodes(ctx context.Context) (int, error)
}

// RefreshTokenStore manages long-lived refresh tokens.
type RefreshTokenStore interface {
    // RefreshToken CRUD
    CreateRefreshToken(ctx context.Context, token *RefreshToken) error
    GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
    GetRefreshTokensBySessionID(ctx context.Context, sessionID uuid.UUID) ([]*RefreshToken, error)
    MarkRefreshTokenUsed(ctx context.Context, token string) error
    UpdateLastRefreshed(ctx context.Context, token string, timestamp time.Time) error
    DeleteRefreshToken(ctx context.Context, token string) error
    DeleteRefreshTokensBySessionID(ctx context.Context, sessionID uuid.UUID) error

    // Cleanup
    DeleteExpiredTokens(ctx context.Context) (int, error)
    DeleteUsedTokens(ctx context.Context) (int, error)
}
```

**Store Design Notes:**

- Separate stores with independent cleanup methods
- Clean expired auth codes without touching sessions
- Revoke refresh tokens independently or cascade from session
- Each store manages its own lifecycle

### TR-2: Token Revocation List (TRL)

**Interface** (Location: `internal/auth/revocation.go`)

```go
type TokenRevocationList interface {
    // Add token JTI to revocation list with TTL
    RevokeToken(ctx context.Context, jti string, ttl time.Duration) error

    // Check if token JTI is revoked
    IsRevoked(ctx context.Context, jti string) (bool, error)

    // Revoke all tokens for a session
    RevokeSessionTokens(ctx context.Context, sessionID string, jtis []string, ttl time.Duration) error
}

// In-memory implementation for MVP
type InMemoryTRL struct {
    mu      sync.RWMutex
    revoked map[string]time.Time // jti -> expiry
}

// Production: Redis implementation
type RedisTRL struct {
    client *redis.Client
}
```

### TR-3: JWT Claims Enhancement

**Add JTI to Access Tokens:**

```go
type AccessTokenClaims struct {
    jwt.RegisteredClaims
    UserID    string   `json:"user_id"`
    SessionID string   `json:"session_id"`
    ClientID  string   `json:"client_id"`
    TenantID  string   `json:"tenant_id"` // Tenant identifier for multi-tenant support
    Scope     []string `json:"scope"`
    JTI       string   `json:"jti"` // Unique token identifier for revocation
}
```

**Per-Tenant Issuer Format (RFC 8414 Compliance):**

The `iss` claim uses a per-tenant issuer URL format:
```
{base_url}/tenants/{tenant_id}
```

Example: `https://auth.credo.io/tenants/550e8400-e29b-41d4-a716-446655440000`

Token validation must:
1. Verify the issuer URL matches the expected base URL pattern
2. Extract tenant ID from the issuer URL and validate it exists
3. The `tenant_id` claim is also included for client convenience (avoids parsing the issuer URL)

### TR-4: Middleware - Revocation Check

**Location:** `internal/transport/http/middleware/auth.go`

```go
func (m *Middleware) RequireValidToken(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract and validate JWT (existing logic)
        claims := extractClaims(r)

        // NEW: Check if token is revoked
        revoked, err := m.trl.IsRevoked(r.Context(), claims.JTI)
        if err != nil {
            http.Error(w, "Revocation check failed", http.StatusInternalServerError)
            return
        }
        if revoked {
            http.Error(w, "Token has been revoked", http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
    })
}
```

### TR-5: Cleanup and Lifecycle Management

**Background Task** (Location: `internal/auth/cleanup.go`)

Periodic cleanup of expired authorization codes, refresh tokens, and sessions.

```go
// CleanupService handles periodic deletion of expired authentication artifacts.
type CleanupService struct {
    sessionStore  SessionStore
    codeStore     AuthorizationCodeStore
    tokenStore    RefreshTokenStore
    interval      time.Duration
}

// Start begins periodic cleanup in a background goroutine.
func (s *CleanupService) Start(ctx context.Context) error {
    ticker := time.NewTicker(s.interval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            s.performCleanup(ctx)
        case <-ctx.Done():
            return ctx.Err()
        }
    }
}

func (s *CleanupService) performCleanup(ctx context.Context) {
    // Clean expired authorization codes (10+ minutes old)
    if deleted, err := s.codeStore.DeleteExpiredCodes(ctx); err != nil {
        log.Errorf("Failed to clean expired codes: %v", err)
    } else if deleted > 0 {
        log.Infof("Cleaned %d expired authorization codes", deleted)
    }

    // Clean used/expired refresh tokens (30+ days old or already used)
    if deleted, err := s.tokenStore.DeleteExpiredTokens(ctx); err != nil {
        log.Errorf("Failed to clean expired tokens: %v", err)
    } else if deleted > 0 {
        log.Infof("Cleaned %d expired refresh tokens", deleted)
    }

    // Clean expired sessions (30+ days old)
    if deleted, err := s.sessionStore.DeleteExpiredSessions(ctx); err != nil {
        log.Errorf("Failed to clean expired sessions: %v", err)
    } else if deleted > 0 {
        log.Infof("Cleaned %d expired sessions", deleted)
    }
}
```

**Cleanup Strategy:**

- Run every 5 minutes (configurable)
- Authorization codes: Delete after 10 minutes + grace period
- Refresh tokens: Delete after marked as used OR after expiry
- Sessions: Delete after expiry OR revocation + grace period
- Independent cleanup prevents cascading deletion issues

---

## 5. Implementation Steps

### Phase 1: Model Refactoring & Core Infrastructure (3-4 hours)

**Goal:** Separate lifetimes and establish privacy-first foundations.

1. **Create new models** in `internal/auth/models/models.go`:

   - `Session` (core long-lived session)
   - `AuthorizationCode` (ephemeral 10-min codes)
   - `RefreshToken` (30-day renewal tokens)

2. **Implement device binding** per [DEVICE_BINDING.md](../DEVICE_BINDING.md):

   - Device service with device ID generation
   - Browser fingerprint computation (UA components, no IP)
   - Device ID cookie management

3. **Create store interfaces** in `internal/auth/store.go`:

   - `SessionStore` interface
   - `AuthorizationCodeStore` interface
   - `RefreshTokenStore` interface

4. **Implement in-memory stores**:

   - `InMemorySessionStore`
   - `InMemoryAuthorizationCodeStore`
   - `InMemoryRefreshTokenStore`

5. **Update existing code** to use separated models:

   - Migrate existing `Session` usage to `AuthorizationCode` for OAuth flow
   - Update authorization endpoint to create both `Session` and `AuthorizationCode`

6. **Add tests** for new models and stores

**Benefits of This Foundation:**

- Clear separation prevents future technical debt
- Privacy-first design (no PII stored)
- Easy to add persistence layer later
- Independent lifecycle management

---

### Phase 2: Refresh Token Flow (3-4 hours)

**Goal:** Implement long-lived sessions with token rotation.

1. **Update token exchange endpoint** (`POST /auth/token`):

   - Issue `RefreshToken` alongside access tokens
   - Store refresh token with 30-day expiry
   - Generate device ID and set cookie (per [DEVICE_BINDING.md](../DEVICE_BINDING.md))
   - Compute and store browser fingerprint

2. **Implement refresh grant type** (`grant_type=refresh_token`):

   - Validate refresh token from `RefreshTokenStore`
   - Validate device binding (per [DEVICE_BINDING.md](../DEVICE_BINDING.md))
   - Implement token rotation (mark old token used, create new one)
   - Generate new access token with same session

3. **Add rotation detection**:

   - Detect reused refresh tokens (possible replay attack)
   - Revoke entire session on rotation violation

4. **Update tests**:
   - Token issuance with refresh token
   - Refresh token exchange flow
   - Token rotation security
   - Replay attack detection

---

### Phase 3: Token Revocation (2-3 hours)

**Goal:** Enable logout and session invalidation.

1. **Implement TokenRevocationList** in `internal/auth/revocation.go`:

   - `InMemoryTRL` with expiry tracking
   - `RevokeToken()`, `IsRevoked()` methods

2. **Add JTI to access tokens**:

   - Update `AccessTokenClaims` struct
   - Generate unique JTI on token creation

3. **Create revocation endpoint** (`POST /auth/revoke`):

   - Parse token (JWT or opaque refresh token)
   - Extract session ID
   - Mark session as revoked
   - Add access token JTI to TRL
   - Delete refresh tokens for session

4. **Update authentication middleware**:

   - Check TRL on every request
   - Return 401 for revoked tokens

5. **Add tests** for revocation flow

---

### Phase 4: Session Management (2-3 hours)

**Goal:** Multi-device session visibility and control.

1. **Implement session listing** (`GET /auth/sessions`):

   - Query all active sessions for user
   - Parse device info from fingerprint context (store separately if needed)
   - Mark current session
   - Return session metadata

2. **Implement session revocation** (`DELETE /auth/sessions/{id}`):

   - Validate session ownership
   - Mark session as revoked
   - Delete associated refresh tokens
   - Add access tokens to TRL

3. **Implement global logout** (`POST /auth/logout-all`):

   - Query all user sessions
   - Revoke all (except current if `except_current=true`)
   - Cascade delete refresh tokens
   - Add all access tokens to TRL

4. **Add tests** for session management

---

### Phase 5: Cleanup & Production Readiness (1-2 hours)

**Goal:** Automatic cleanup and monitoring.

1. **Implement CleanupService** in `internal/auth/cleanup.go`:

   - Periodic deletion of expired codes (10+ min old)
   - Periodic deletion of used/expired refresh tokens
   - Periodic deletion of expired sessions

2. **Add cleanup configuration**:

   - Configurable cleanup interval (default: 5 minutes)
   - Grace periods for each artifact type

3. **Add monitoring/metrics**:

   - Count of active sessions
   - Count of expired artifacts cleaned
   - Token revocation rate

4. **Integration tests**:
   - End-to-end flow: login → refresh → logout
   - Multi-device session management
   - Cleanup verification

---

## 6. Acceptance Criteria

- [x] Users receive refresh tokens on login
- [x] Refresh tokens can be exchanged for new access tokens
- [x] Refresh tokens rotate on each use (old token invalidated)
- [x] Reusing old refresh token revokes entire session (security)
- [x] Users can log out and invalidate their session
- [x] Revoked tokens fail authentication checks
- [x] Users can list all active sessions
- [x] Users can revoke individual sessions
- [x] Users can revoke all sessions at once
- [ ] Password change triggers global session revocation
- [x] Token revocation list uses TTL (no memory leak)
- [x] All token lifecycle events emit audit events
- [ ] Concurrent session limits enforced (optional)

---

## 7. Security Considerations

### Refresh Token Rotation

- **Why:** Prevents replay attacks if refresh token is stolen
- **How:** Each refresh invalidates old token, issues new one
- **Detection:** Reuse of old refresh token → revoke entire session family

### Token Revocation List Performance

- Use Redis for production (distributed)
- Set TTL = token expiry (no cleanup needed)
- Only store JTI (16 bytes) + expiry, not full token

### Device Binding

See [DEVICE_BINDING.md](../DEVICE_BINDING.md) for complete security model and implementation.

**Summary:**

- Device ID cookie (primary binding) + fingerprint (soft signal) + IP risk scoring
- Production-ready: Handles VPN, mobile, CGNAT without false positives
- Privacy-first: No raw PII stored

### Concurrent Session Limits

- Prevent account sharing by limiting active sessions
- Configurable per user or globally
- Oldest session auto-revoked when limit exceeded

Related Future Requirements: See [docs/requirements-wishlist.md](docs/requirements-wishlist.md) for the evolving specification and policy options (evict-oldest vs deny-new), audit and metrics.

---

## 8. API Examples

### Example 1: Login and Refresh Flow

```bash
# Step 1: Get authorization code
curl -X POST http://localhost:8080/auth/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "client_id": "demo-client",
    "redirect_uri": "https://app.example.com/callback",
    "state": "xyz123"
  }'

# Response:
# {"code": "authz_abc123", "redirect_uri": "https://app.example.com/callback?code=authz_abc123&state=xyz123"}

# Step 2: Exchange code for tokens (includes refresh token)
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "authz_abc123",
    "redirect_uri": "https://app.example.com/callback",
    "client_id": "demo-client"
  }'

# Response:
# {
#   "access_token": "eyJhbGc...",
#   "id_token": "idt_...",
#   "refresh_token": "ref_7c9e6679-7425-40de-944b-e07fc1f90ae7",
#   "token_type": "Bearer",
#   "expires_in": 3600
# }

# Step 3: Access token expires after 1 hour, use refresh token
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "refresh_token",
    "refresh_token": "ref_7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "client_id": "demo-client"
  }'

# Response: New access token + new refresh token (rotation)
```

### Example 2: Logout

```bash
# Revoke current session
curl -X POST http://localhost:8080/auth/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "token": "ref_7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "token_type_hint": "refresh_token"
  }'

# Response: {"revoked": true, "message": "Token revoked successfully"}
```

### Example 3: Session Management

```bash
# List all sessions
curl -X GET http://localhost:8080/auth/sessions \
  -H "Authorization: Bearer eyJhbGc..."

# Revoke specific session (logout from another device)
curl -X DELETE http://localhost:8080/auth/sessions/sess_def456 \
  -H "Authorization: Bearer eyJhbGc..."

# Revoke all sessions except current
curl -X POST http://localhost:8080/auth/logout-all?except_current=true \
  -H "Authorization: Bearer eyJhbGc..."
```

---

## 9. Future Enhancements

- Token introspection endpoint (RFC 7662)
- Sliding session windows (extend on activity)
- Remember me / persistent sessions
- Single Sign-On (SSO) across applications
- Token exchange (RFC 8693) for service-to-service
- Proof Key for Code Exchange (PKCE) for mobile apps

---

## References

- [RFC 6749: OAuth 2.0 Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7009: Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
- [OWASP: Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

## Revision History

| Version | Date       | Author       | Changes                                                                                                                           |
| ------- | ---------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| 1.4     | 2025-12-17 | Engineering  | RFC 8414 compliance: Per-tenant issuer implementation                                                                             |
|         |            |              | - Added per-tenant issuer format: `{base_url}/tenants/{tenant_id}`                                                                |
|         |            |              | - Added TenantID to AccessTokenClaims struct                                                                                      |
|         |            |              | - Documented issuer validation requirements                                                                                       |
| 1.3     | 2025-12-17 | Engineering  | RFC compliance: Updated error codes for token and revocation endpoints                                                            |
|         |            |              | - Token (refresh grant): Changed 401 → 400 for invalid_grant errors per RFC 6749 §5.2                                             |
|         |            |              | - Revoke: Added explicit RFC 7009 §2.2 reference for idempotent 200 OK behavior                                                   |
|         |            |              | - Added OAuth error codes (invalid_grant, invalid_request, unsupported_grant_type)                                                |
| 1.2     | 2025-12-13 | Engineering  | remove IP Address from List sessions response                                                                                     |
| 1.1     | 2025-12-13 | Engineering  | Updated device binding to reference DEVICE_BINDING.md; changed to layered security model (device ID + fingerprint, no IP binding) |
| 1.0     | 2025-12-12 | Product Team | Initial PRD                                                                                                                       |
