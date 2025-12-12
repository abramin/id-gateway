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
- Provide token binding to device/IP for enhanced security

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
3. Optionally bind token to device fingerprint (user-agent + IP hash)
4. Return refresh token alongside access token
5. Emit audit event: `refresh_token_issued`

**Refresh Token Properties:**

- **Long-lived:** 30 days (configurable)
- **Single-use:** Consumed on refresh, new refresh token issued (rotation)
- **Revocable:** Can be explicitly revoked via logout
- **Device-bound:** (Optional) Tied to device fingerprint

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
7. **(Optional)** Validate device fingerprint matches (if token binding enabled)
8. **Refresh Token Rotation:**
   - Revoke old refresh token (mark as used)
   - Generate new refresh token
   - Update session with new refresh token
9. Generate new access token (new expiry, same session_id)
10. Generate new ID token
11. Update session `LastRefreshedAt` timestamp
12. Emit audit event: `token_refreshed`
13. Return new tokens

**Error Cases:**

- 400 Bad Request: Missing required fields
- 400 Bad Request: Invalid grant_type (must be "refresh_token")
- 401 Unauthorized: Invalid or expired refresh token
- 401 Unauthorized: Refresh token already used (rotation violation - possible replay attack)
- 401 Unauthorized: Session revoked
- 403 Forbidden: Device fingerprint mismatch (if token binding enabled)
- 500 Internal Server Error: Store failure

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

**Error Cases:**

- 400 Bad Request: Missing token
- 500 Internal Server Error: Store failure

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
      "ip_address": "192.168.1.100",
      "location": "San Francisco, US",
      "created_at": "2025-12-01T10:00:00Z",
      "last_activity": "2025-12-12T15:30:00Z",
      "is_current": true
    },
    {
      "session_id": "sess_def456",
      "device": "Safari on iPhone",
      "ip_address": "192.168.1.101",
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
   - Parse device from user-agent
   - Extract IP address from session metadata
   - Lookup geolocation from IP (optional, use MaxMind GeoIP)
   - Mark current session (match session_id from token)
4. Return session list

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

### TR-1: Enhanced Session Model

**Update Session Model** (Location: `internal/auth/models.go`)

```go
type Session struct {
    ID              uuid.UUID
    UserID          uuid.UUID
    Code            string    // Authorization code
    CodeExpiresAt   time.Time
    CodeUsed        bool

    // Token management
    RefreshToken    string    // Format: "ref_<uuid>"
    RefreshTokenExpiresAt time.Time // 30 days
    RefreshTokenUsed bool      // For rotation detection

    // Device binding (optional)
    DeviceFingerprint string  // Hash of user-agent + IP
    UserAgent       string
    IPAddress       string

    // Session tracking
    LastRefreshedAt *time.Time
    RevokedAt       *time.Time

    ClientID        string
    RedirectURI     string
    RequestedScope  []string
    Status          string    // "pending_consent", "active", "revoked"
    CreatedAt       time.Time
    ExpiresAt       time.Time
}
```

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
    Scope     []string `json:"scope"`
    JTI       string   `json:"jti"` // Unique token identifier for revocation
}
```

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

### TR-5: Device Fingerprinting (Optional)

**Function** (Location: `internal/auth/fingerprint.go`)

```go
func ComputeDeviceFingerprint(userAgent, ipAddress string) string {
    // Hash user-agent + IP for device binding
    data := fmt.Sprintf("%s|%s", userAgent, ipAddress)
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:16]) // First 16 bytes
}

func ValidateDeviceFingerprint(session *Session, userAgent, ipAddress string) bool {
    if session.DeviceFingerprint == "" {
        return true // Device binding not enabled
    }
    expected := ComputeDeviceFingerprint(userAgent, ipAddress)
    return session.DeviceFingerprint == expected
}
```

---

## 5. Implementation Steps

### Phase 1: Refresh Token Flow (4-5 hours)

1. Update Session model with RefreshToken fields
2. Modify `POST /auth/token` to issue refresh tokens on code exchange
3. Add refresh token generation and storage
4. Implement `grant_type=refresh_token` flow
5. Add refresh token rotation logic
6. Update tests for refresh flow

### Phase 2: Token Revocation (2-3 hours)

1. Implement TokenRevocationList interface (in-memory)
2. Create `POST /auth/revoke` endpoint
3. Add JTI to access token claims
4. Store revoked JTIs in TRL with TTL
5. Update middleware to check TRL on every request
6. Add tests for revocation

### Phase 3: Session Management (2-3 hours)

1. Add device tracking fields to Session model
2. Implement `GET /auth/sessions` endpoint
3. Implement `DELETE /auth/sessions/{id}` endpoint
4. Implement `POST /auth/logout-all` endpoint
5. Add user-agent and IP extraction helpers
6. Add tests for session management

---

## 6. Acceptance Criteria

- [ ] Users receive refresh tokens on login
- [ ] Refresh tokens can be exchanged for new access tokens
- [ ] Refresh tokens rotate on each use (old token invalidated)
- [ ] Reusing old refresh token revokes entire session (security)
- [ ] Users can log out and invalidate their session
- [ ] Revoked tokens fail authentication checks
- [ ] Users can list all active sessions
- [ ] Users can revoke individual sessions
- [ ] Users can revoke all sessions at once
- [ ] Password change triggers global session revocation
- [ ] Token revocation list uses TTL (no memory leak)
- [ ] All token lifecycle events emit audit events
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

- Optional feature (can be enabled via config)
- Prevents stolen tokens from being used on different devices
- Tradeoff: Users on VPN/dynamic IPs may have issues

### Concurrent Session Limits

- Prevent account sharing by limiting active sessions
- Configurable per user or globally
- Oldest session auto-revoked when limit exceeded

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

| Version | Date       | Author       | Changes     |
| ------- | ---------- | ------------ | ----------- |
| 1.0     | 2025-12-12 | Product Team | Initial PRD |
