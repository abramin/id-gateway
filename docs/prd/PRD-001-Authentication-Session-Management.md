# PRD-001: Authentication & Session Management

**Status:** Complete
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Last Updated:** 2025-12-24

---

## 1. Overview

**Note:** This PRD has been updated to align with PRD-016 (Token Lifecycle & Revocation). The session model now supports separated authorization codes and refresh tokens with independent lifecycles. PRD-001 covers token issuance, while PRD-016 covers token refresh, revocation, and session management.

### Problem Statement

Credo requires a lightweight authentication system that manages user identities and sessions without implementing a full OAuth2/OIDC stack. Users need to authenticate, receive tokens, and access their profile information through standard endpoints.

### Goals

- Implement OIDC-lite authentication flow (OAuth2 + minimal identity layer) using signed JWTs
- Manage user lifecycle (creation, retrieval, profile access)
- Handle session creation and validation with privacy-first device fingerprinting
- Separate authorization codes, sessions, and refresh tokens for independent lifecycle management
- Issue access tokens, ID tokens, and refresh tokens for authenticated users with configurable TTLs
- Provide userinfo endpoint for profile claims

### Non-Goals

- Full OIDC certification compliance
- Social login integration (Google, Facebook, etc.)
- Password management (passwords not required for demo)
- Multi-factor authentication

---

## 2. User Stories

**As a** client application
**I want to** authenticate users via email
**So that** I can identify who is making requests

**As a** user
**I want to** obtain access tokens after authentication
**So that** I can access protected resources

**As a** client application
**I want to** retrieve user profile information
**So that** I can display user details and personalize the experience

---

## 2.1. OAuth2 Flow Support

This implementation follows the standard **OAuth 2.0 Authorization Code Flow** (RFC 6749) with the following parameters:

**redirect_uri**

- Required for browser-based flows where the user is redirected back to the client application after authentication
- The gateway appends the `code` (authorization code) and `state` as query parameters to this URI
- Client applications extract the code and exchange it for tokens via the token endpoint
- Optional: If not provided, the response contains only the authorization code

**state**

- CSRF protection token provided by the client
- The gateway echoes this value back in the redirect_uri
- Client must validate the state matches before using the authorization code
- Prevents authorization code injection attacks
- Optional but strongly recommended for security

**code (Authorization Code)**

- Short-lived, single-use credential issued by the authorization endpoint
- Client exchanges this code for access and ID tokens at the token endpoint
- Expires after 10 minutes if not used
- Cannot be reused (marked as consumed after exchange)

**Example browser-based flow:**

1. Client redirects user to: `POST /auth/authorize` with redirect_uri, state, and scopes
2. Gateway creates session internally, responds with: `{"redirect_uri": "https://client.com/callback?code=abc123&state=xyz"}`
3. Client redirects user to the returned redirect_uri
4. Client validates state matches, extracts authorization code
5. Client calls `POST /auth/token` with grant_type=authorization_code and code to get tokens

---

## 3. Functional Requirements

### FR-1: User Authorization

**Endpoint:** `POST /auth/authorize`

**Description:** Initiate an authentication session for a user by email. If the user doesn't exist, create them automatically. Returns an authorization code following OAuth 2.0 specification.

**Input:**

```json
{
  "email": "user@example.com",
  "client_id": "demo-client",
  "scopes": ["openid", "profile"], // Optional, defaults to ["openid"]
  "redirect_uri": "https://app.example.com/callback", // Required for code flow
  "state": "xyz123" // Optional, CSRF protection (strongly recommended)
}
```

**Output (Success - 200):**

```json
{
  "code": "authz_abc123xyz",
  "redirect_uri": "https://app.example.com/callback?code=authz_abc123xyz&state=xyz123"
}
```

**Business Logic:**

1. Validate email format
2. Validate redirect_uri format (must be valid HTTPS URL, or HTTP for localhost only)
3. Validate client_id is provided and non-empty
4. Check if user exists by email
5. If not exists, create new user with:
   - Generated unique ID (UUID)
   - Email as provided
   - FirstName/LastName extracted from email (before @)
   - Verified = false
6. If exists, retrieve user
7. Create new session with:
   - Generated unique ID (UUID)
   - UserID from step 4/5
   - RequestedScope from input (default to ["openid"] if empty)
   - Status = "pending_consent"
   - ClientID from input
   - DeviceFingerprintHash = SHA-256(user-agent + IP) for privacy-first device binding
   - DeviceDisplayName = parsed from user-agent (e.g., "Chrome on macOS") for UI display
   - ApproximateLocation = derived from IP (e.g., "San Francisco, US") for UI display
   - CreatedAt = current timestamp
   - ExpiresAt = current timestamp + Session TTL (default 24h, configurable via `SESSION_TTL`)
8. Generate authorization code (separate from session):
   - Format: `authz_<uuid>` (e.g., `authz_550e8400-e29b-41d4-a716-446655440000`)
   - SessionID = link to session from step 7
   - RedirectURI from input (stored for validation at token exchange)
   - ExpiresAt = current timestamp + 10 minutes
   - Used = false (for replay attack prevention)
   - CreatedAt = current timestamp
9. Save session to SessionStore
10. Save authorization code to AuthorizationCodeStore (separate from session)
11. Build redirect_uri response:
    - Append code and state as query parameters
    - If state provided: echo it back in response for CSRF validation
12. Return authorization code and complete redirect_uri

**Error Cases:**

- 400 Bad Request: Invalid email format
- 400 Bad Request: Invalid redirect_uri format
- 400 Bad Request: Unknown client_id (RFC 6749 §4.1.2.1 - MUST NOT redirect)
- 400 Bad Request: Inactive client (`invalid_client`)
- 400 Bad Request: redirect_uri not in client's registered URIs (RFC 6749 §4.1.2.1 - MUST NOT redirect)
- 500 Internal Server Error: Store failure

**Note (RFC 6749 §4.1.2.1):** If the request fails due to a missing, invalid, or mismatching redirect_uri, or if the client_id is missing or invalid, the server MUST NOT redirect the user-agent. Instead, return an error response directly.

---

### FR-2: Token Exchange

**Endpoint:** `POST /auth/token`

**Description:** Exchange a valid authorization code for access and ID tokens following OAuth 2.0 specification.

**Input:**

```json
{
  "grant_type": "authorization_code",
  "code": "authz_abc123xyz",
  "redirect_uri": "https://app.example.com/callback",
  "client_id": "demo-client"
}
```

**Output (Success - 200):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "ref_7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Business Logic:**

1. Validate grant_type is "authorization_code"
2. Validate code, redirect_uri, and client_id are provided
3. Find authorization code in AuthorizationCodeStore (separate from session)
4. If authorization code not found, return 401 (invalid code)
5. Validate authorization code has not expired (< 10 minutes old)
6. Validate authorization code has not been used before (prevent replay attacks)
7. Validate redirect_uri matches the one stored in authorization code (OAuth 2.0 requirement)
8. Find session by SessionID from authorization code
9. If session not found, return 401 (invalid session)
10. Validate client_id matches the one stored in session
11. Mark authorization code as used in AuthorizationCodeStore (set Used = true)
12. Generate JWT access_token with claims: user_id, session_id, client_id, jti, exp, iat, iss, aud
13. Sign JWT with HS256 using configured signing key
14. Generate ID token
15. Generate refresh token:
    - Format: `"ref_" + uuid.New().String()`
    - Store in RefreshTokenStore with SessionID link
    - Set expiry: 30 days from issuance
16. Set token expiry: expires_in = token TTL in seconds (default 15m, configurable via `TOKEN_TTL`). Note: Session TTL (default 24h, `SESSION_TTL`) governs how long the underlying session remains valid.
17. Update session status to "active"
18. Save updated session
19. Return access_token, id_token, and refresh_token

**Error Cases (RFC 6749 §5.2):**

- 400 Bad Request: Missing required fields (`invalid_request`)
- 400 Bad Request: Unsupported grant_type (`unsupported_grant_type`)
- 400 Bad Request: Invalid authorization code - not found (`invalid_grant`)
- 400 Bad Request: Authorization code expired (`invalid_grant`)
- 400 Bad Request: Authorization code already used (`invalid_grant`)
- 400 Bad Request: redirect_uri mismatch (`invalid_grant`)
- 400 Bad Request: client_id mismatch (`invalid_client`)
- 500 Internal Server Error: Store failure

**Note (RFC 6749 §5.2):** Token endpoint errors return HTTP 400 with an `error` field. HTTP 401 is only used when client authentication fails via HTTP Authorization header (not applicable for JSON body authentication).

---

### FR-3: User Info Retrieval

**Endpoint:** `GET /auth/userinfo`

**Description:** Retrieve authenticated user's profile information using a bearer token.

**Input:**

- Header: `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`

**Output (Success - 200):**

```json
{
  "sub": "user_def456",
  "email": "user@example.com",
  "email_verified": false,
  "name": "User Example",
  "given_name": "User",
  "family_name": "Example"
}
```

**Business Logic:**

1. Extract bearer token from Authorization header
2. Validate format: "Bearer <token>"
3. Validate JWT signature and expiration using JWTService
4. Extract session_id from JWT claims
5. Retrieve session from SessionStore
6. If session not found, return 401
7. Retrieve user from UserStore using session.UserID
8. If user not found, return 401
9. Return user profile in OIDC userinfo format

**Error Cases:**

- 401 Unauthorized: Missing or invalid Authorization header
- 401 Unauthorized: Token not found or expired
- 401 Unauthorized: User not found
- 500 Internal Server Error: Store failure

---

## 4. Technical Requirements

### TR-1: Data Models

**User Model** (Location: `internal/auth/models.go`)

```go
type User struct {
    ID        uuid.UUID // Unique user identifier
    Email     string    // Unique, valid email format
    FirstName string    // Extracted from email or provided
    LastName  string    // Extracted from email or provided
    Verified  bool      // Email verification status (default: false)
}
```

**Session Model** (Location: `internal/auth/models.go`)

Core long-lived session representing user authentication state. Authorization codes and refresh tokens are managed separately.

```go
type Session struct {
    ID             uuid.UUID  `json:"id"`
    UserID         uuid.UUID  `json:"user_id"`
    ClientID       string     `json:"client_id"`
    RequestedScope []string   `json:"requested_scope"`
    Status         string     `json:"status"` // "pending_consent", "active", "revoked"

    // Device binding for security (privacy-first: no raw PII)
    DeviceFingerprintHash string `json:"device_fingerprint_hash"` // SHA-256(user-agent + IP) for validation

    // Device display metadata (optional, for session management UI)
    DeviceDisplayName   string `json:"device_display_name,omitempty"`   // e.g., "Chrome on macOS"
    ApproximateLocation string `json:"approximate_location,omitempty"`  // e.g., "San Francisco, US"

    // Lifecycle timestamps
    CreatedAt time.Time  `json:"created_at"`
    ExpiresAt time.Time  `json:"expires_at"`  // Session expiry (30+ days)
    RevokedAt *time.Time `json:"revoked_at,omitempty"`
}
```

**AuthorizationCode Model** (Location: `internal/auth/models.go`)

Ephemeral authorization code for OAuth 2.0 code exchange flow. Separated from Session for independent lifecycle management.

```go
type AuthorizationCodeRecord struct {
    Code        string    `json:"code"`         // Format: "authz_<random>"
    SessionID   uuid.UUID `json:"session_id"`   // Links to parent Session
    RedirectURI string    `json:"redirect_uri"` // Stored for validation at token exchange
    ExpiresAt   time.Time `json:"expires_at"`   // 10 minutes from creation
    Used        bool      `json:"used"`         // Prevent replay attacks
    CreatedAt   time.Time `json:"created_at"`
}
```

**RefreshToken Model** (Location: `internal/auth/models.go`)

Long-lived token for renewing access tokens without re-authentication.

```go
type RefreshToken struct {
    Token           string     `json:"token"`      // Format: "ref_<uuid>"
    SessionID       uuid.UUID  `json:"session_id"` // Links to parent Session
    ExpiresAt       time.Time  `json:"expires_at"` // 30 days from creation
    Used            bool       `json:"used"`       // For rotation detection
    LastRefreshedAt *time.Time `json:"last_refreshed_at,omitempty"`
    CreatedAt       time.Time  `json:"created_at"`
}
```

**Design Rationale:**

The separation of Session, AuthorizationCode, and RefreshToken into distinct models provides:

- **Clear lifetime boundaries:** Codes (10 min), refresh tokens (30 days), sessions (30+ days)
- **Independent cleanup:** Delete expired codes without touching sessions
- **Privacy-first:** DeviceFingerprintHash instead of raw user-agent/IP (no PII)
- **Easier rotation:** Update refresh tokens without modifying session
- **Reduced memory:** No dead fields occupying space after use

### TR-2: Storage Interfaces

**UserStore** (Location: `internal/auth/store/user`)

```go
type UserStore interface {
    Save(ctx context.Context, user *User) error
    FindByID(ctx context.Context, id uuid.UUID) (*User, error)
    FindByEmail(ctx context.Context, email string) (*User, error)
    FindOrCreateByEmail(ctx context.Context, email string, user *models.User) (*models.User, error)
    Delete(ctx context.Context, id uuid.UUID) error
}
```

**SessionStore** (Location: `internal/auth/store/session`)

```go
type SessionStore interface {
    Save(ctx context.Context, session *Session) error
    FindByID(ctx context.Context, id uuid.UUID) (*Session, error)
    DeleteSessionsByUser(ctx context.Context, userID uuid.UUID) error
}
```

**AuthorizationCodeStore** (Location: `internal/auth/store/authcode`)

Manages short-lived authorization codes separately from sessions.

```go
type AuthorizationCodeStore interface {
    Save(ctx context.Context, code *AuthorizationCodeRecord) error
    FindByCode(ctx context.Context, code string) (*AuthorizationCodeRecord, error)
    MarkUsed(ctx context.Context, code string) error
    DeleteExpiredCodes(ctx context.Context) (int, error)
}
```

**RefreshTokenStore** (Location: `internal/auth/store/refreshtoken`)

Manages long-lived refresh tokens for token renewal.

```go
type RefreshTokenStore interface {
    Save(ctx context.Context, token *RefreshToken) error
    FindByToken(ctx context.Context, token string) (*RefreshToken, error)
    FindBySessionID(ctx context.Context, sessionID uuid.UUID) ([]*RefreshToken, error)
    MarkUsed(ctx context.Context, token string) error
    DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) error
    DeleteExpiredTokens(ctx context.Context) (int, error)
}
```

### TR-3: Service Layer

**AuthService** (Location: `internal/auth/service/service.go`)

```go
type AuthService struct {
    users    UserStore
    sessions SessionStore
}

func (s *AuthService) Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResult, error)
func (s *AuthService) Token(ctx context.Context, req *TokenRequest) (*TokenResult, error)
func (s *AuthService) UserInfo(ctx context.Context, token string) (*User, error)
```

### TR-4: HTTP Handlers

**Handler Struct** (Location: `internal/auth/handler/handler.go`)

```go
type Handler struct {
    authService *auth.Service
}
```

**Handler Functions** (Location: `internal/auth/handler/handler.go`)

```go
func (h *Handler) handleAuthorize(w http.ResponseWriter, r *http.Request)
func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request)
func (h *Handler) handleUserInfo(w http.ResponseWriter, r *http.Request)
```

### TR-5: Dependencies

**Required:**

- `internal/platform/logger` - For structured logging
- `pkg/domain-errors` - For typed error handling
- `internal/audit` - For logging authentication events

**Store Implementation:**

- Use in-memory stores in `internal/auth/store/user` and `internal/auth/store/session` (already implemented)
- Thread-safe with `sync.RWMutex`
- Returns typed errors from `pkg/domain-errors`

---

## 5. API Specifications

### Endpoint Summary

| Endpoint          | Method | Auth Required | Purpose                     |
| ----------------- | ------ | ------------- | --------------------------- |
| `/auth/authorize` | POST   | No            | Start auth session          |
| `/auth/token`     | POST   | No            | Exchange session for tokens |
| `/auth/userinfo`  | GET    | Yes (Bearer)  | Get user profile            |

### Token Format

**Access Token:** JWT (HS256) containing `user_id`, `session_id`, `client_id`, `tenant_id`, `iss`, `aud`, `iat`, `exp`, and optional `env`. Lifetime = Token TTL (default 15m via `TOKEN_TTL`).

**ID Token:** JWT (HS256) containing `sub` (user_id), `sid` (session_id), `azp` (client_id), `iss`, `aud`, `iat`, `exp`, optional `env`. Lifetime = Token TTL (default 15m).

**Session Lifetime:** Session records persist for Session TTL (default 24h via `SESSION_TTL`) and are used to validate codes, tokens, and userinfo. Code lifetime is fixed at 10 minutes.

**Token Type:** Bearer

**Issuer Format (RFC 8414 Compliance):**

Per RFC 8414 (Authorization Server Metadata), each tenant has a unique issuer URL:

```
{base_url}/tenants/{tenant_id}
```

Example: `https://auth.credo.io/tenants/550e8400-e29b-41d4-a716-446655440000`

The `iss` claim in both access tokens and ID tokens uses this per-tenant issuer format. The tenant ID can be derived from parsing the issuer URL, but `tenant_id` is also included as a custom claim in access tokens for client convenience.

### Error Response Format

All endpoints return errors in this format:

```json
{
  "error": "invalid_request",
  "error_description": "Missing required field: email",
  "status_code": 400
}
```

---

## 6. Security Requirements

### SR-1: Input Validation

- Validate all email addresses match regex: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
- Validate redirect_uri is a valid URL with https:// scheme (http:// allowed for localhost)
- Sanitize all string inputs (trim whitespace, validate length)
- Reject requests with missing required fields

### SR-2: Token Security

- Tokens are signed JWTs (HS256). Validate signature, issuer, audience, and exp on every request.
- Token TTL is short-lived (default 15 minutes, configurable via `TOKEN_TTL`).
- Session TTL governs how long the authorization session stays valid (default 24h, `SESSION_TTL`).

### SR-3: CSRF Protection

- When state parameter is provided in authorize request, echo it back in redirect_uri
- Clients should validate state matches their original value before using session_id
- State should be cryptographically random and unpredictable

### SR-4: Data Privacy

- Never log passwords (not applicable for email-only auth)
- Log only user IDs, not email addresses, in non-audit logs
- Use audit system for sensitive operations

---

## 7. Observability Requirements

### Logging

**Events to Log:**

- User created: `user_created` (audit)
- Session started: `session_created` (audit)
- Token issued: `token_issued` (audit)
- UserInfo accessed: `userinfo_accessed` (audit)
- Authentication failures: `auth_failed` (standard log)

Deletion-specific audit events are defined in PRD-001B.

**Log Format:**

```go
logger.Info("session created",
    "user_id", user.ID,
    "session_id", session.ID,
    "client_id", req.ClientID,
)
```

### Metrics

- Total users created (counter)
- Active sessions (gauge)
- Token requests per minute (rate)
- Auth failures per minute (rate)
- Latency per endpoint (histogram)

---

## 8. Testing Requirements

### Unit Tests

- [x] Test user creation with valid email
- [x] Test user retrieval by ID and email
- [x] Test session creation and retrieval (separated from authorization codes)
- [x] Test authorization code creation and retrieval (separate lifecycle)
- [x] Test refresh token generation and storage
- [x] Test device fingerprint hashing (privacy-first)
- [x] Test token generation format (with jti claim)
- [x] Test token validation and parsing
- [x] Test redirect_uri building with code and state
- [x] Test redirect_uri validation (https required, localhost exception)
- [x] Test state parameter echo in response
- [x] Test error cases (invalid email, invalid redirect_uri, not found, etc.)
- [x] Test authorization code expiry and replay prevention
- [x] Test refresh token issuance on token exchange

### Integration Tests

- [x] Test complete flow: authorize → token → userinfo
- [x] Test concurrent user creation (race conditions)
- [x] Test session expiry handling
- [x] Test invalid bearer token rejection

### Manual Testing

```bash
# 1. Authorize - OAuth 2.0 Authorization Code Flow
curl -X POST http://localhost:8080/auth/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "client_id": "demo-client",
    "redirect_uri": "https://myapp.com/callback",
    "state": "random-csrf-token-123",
    "scopes": ["openid", "profile"]
  }'

# Expected Response:
# {
#   "code": "authz_550e8400-e29b-41d4-a716-446655440000",
#   "redirect_uri": "https://myapp.com/callback?code=authz_550e8400-e29b-41d4-a716-446655440000&state=random-csrf-token-123"
# }

# 2. Exchange Authorization Code for Tokens
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "authz_550e8400-e29b-41d4-a716-446655440000",
    "redirect_uri": "https://myapp.com/callback",
    "client_id": "demo-client"
  }'

# Expected Response:
# {
#   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
#   "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
#   "refresh_token": "ref_7c9e6679-7425-40de-944b-e07fc1f90ae7",
#   "token_type": "Bearer",
#   "expires_in": 900
# }

# 3. Get UserInfo with Access Token
curl http://localhost:8080/auth/userinfo \
  -H "Authorization: Bearer <access_token_jwt>"
# Replace with the JWT from the token exchange response

# Expected Response:
# {
#   "sub": "550e8400-e29b-41d4-a716-446655440000",
#   "email": "alice@example.com",
#   "email_verified": false,
#   "name": "Alice Example",
#   "given_name": "Alice",
#   "family_name": "Example"
# }

# 4. Test Error Cases

# 4a. Try to reuse authorization code (should fail)
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "authz_550e8400-e29b-41d4-a716-446655440000",
    "redirect_uri": "https://myapp.com/callback",
    "client_id": "demo-client"
  }'

# Expected: 400 Bad Request (invalid_grant - code already used)

# 4b. Try with wrong redirect_uri (should fail)
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "authz_NEW_CODE",
    "redirect_uri": "https://evil.com/callback",
    "client_id": "demo-client"
  }'

# Expected: 400 Bad Request (redirect_uri mismatch)

# 4c. Try with unsupported grant_type (should fail)
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "password",
    "username": "alice@example.com",
    "password": "secret"
  }'

# Expected: 400 Bad Request (unsupported grant_type)
```

---

## 9. Implementation Steps

**Note:** These implementation steps reflect the updated architecture with separated lifecycle models (Session, AuthorizationCode, RefreshToken) as defined in PRD-016.

### Phase 1: Model & Store Foundation (2-3 hours)

1. Create separated data models in `internal/auth/models/models.go`:
   - Update `Session` model (remove code fields, add device fingerprinting)
   - Create `AuthorizationCodeRecord` model (10-minute lifecycle)
   - Create `RefreshToken` model (30-day lifecycle)
2. Implement separate store interfaces:
   - `SessionStore` (without FindByCode)
   - `AuthorizationCodeStore` (new)
   - `RefreshTokenStore` (new)
3. Implement in-memory stores with independent cleanup

### Phase 2: Service Layer (2-3 hours)

1. Update `AuthService` in `internal/auth/service.go`
2. Implement `Authorize()` method:
   - Find or create user by email
   - Create session with device fingerprinting (SHA-256 hash)
   - Create authorization code (separate from session)
   - Return authorization code and redirect URI
3. Implement `Token()` method:
   - Validate authorization code from AuthorizationCodeStore
   - Find session by SessionID from authorization code
   - Generate access token (with jti claim), ID token, and refresh token
   - Store refresh token in RefreshTokenStore
   - Return token response
4. Implement `UserInfo()` method:
   - Parse bearer token
   - Retrieve session and user
   - Return user profile

### Phase 3: HTTP Handlers (1-2 hours)

1. Update `Handler` struct in `router.go` to include `AuthService`
2. Implement `handleAuthorize`:
   - Parse JSON request body
   - Extract device metadata (user-agent, IP) from request
   - Call `authService.Authorize()`
   - Return JSON response or error
3. Implement `handleToken`:
   - Parse JSON request body
   - Call `authService.Token()`
   - Return JSON response with refresh_token
4. Implement `handleUserInfo`:
   - Extract bearer token from header
   - Call `authService.UserInfo()`
   - Return JSON response or error

### Phase 4: Dependency Injection (30 min)

1. Update `cmd/server/main.go`:
   - Initialize UserStore (already exists)
   - Initialize SessionStore (updated interface)
   - Initialize AuthorizationCodeStore (new)
   - Initialize RefreshTokenStore (new)
   - Create AuthService with all stores
   - Pass AuthService to HTTP Handler
2. Wire up in router

### Phase 5: Testing (1-2 hours)

1. Write unit tests for separated models and stores
2. Write unit tests for AuthService methods
3. Write integration test for complete flow (authorize → code → tokens with refresh)
4. Manual testing with curl commands
5. Edge case testing (invalid inputs, not found, code expiry, etc.)

---

## 10. Acceptance Criteria

- [x] User can authenticate with email and receive authorization code
- [x] User can exchange authorization code for access token, ID token, and refresh token
- [x] User can retrieve profile using bearer token
- [x] Authorization codes are stored separately from sessions with 10-minute expiry
- [x] Refresh tokens are issued with 30-day expiry and linked to sessions
- [x] Sessions use privacy-first device fingerprinting (hashed, not raw PII)
- [x] Sessions include device display metadata for future session management UI
- [x] Authorization codes cannot be reused (replay attack prevention)
- [x] Invalid bearer tokens return 401 Unauthorized
- [x] Non-existent sessions return 401 Unauthorized
- [x] All authentication events are logged to audit system
- [x] Concurrent requests don't cause race conditions
- [x] All endpoints return proper error responses
- [x] Code passes `make test` and `make lint`
- [x] Manual curl tests work as documented
- [x] Independent cleanup of expired authorization codes (without affecting sessions)
- [x] Access tokens include jti claim for future revocation support

---

## 11. Dependencies & Blockers

### Dependencies

- `internal/auth/store/user` and `internal/auth/store/session` in-memory stores - ✅ Already implemented
- `internal/auth/store/authcode` for authorization code storage - 🔄 In progress
- `internal/auth/store/refreshtoken` for refresh token storage - 🔄 In progress
- `pkg/domain-errors` - ✅ Already implemented
- `internal/audit` - ✅ Already implemented
- `internal/platform/logger` - ✅ Already implemented

### Potential Blockers

- None identified

### Related PRDs

- **PRD-016 (Token Lifecycle & Revocation)**: Implements the refresh token exchange flow, token revocation, and session management endpoints. PRD-001 provides the foundation by issuing refresh tokens, while PRD-016 adds the consumption and revocation mechanisms.

---

## 12. Future Enhancements (Out of Scope)

- Real JWT signing with RS256/ES256
- Per-tenant signing keys (currently global key used across all tenants)
- Token refresh flow implementation (see PRD-016)
- Session revocation endpoint (see PRD-016)
- Session management endpoints (see PRD-016)
- Token introspection endpoint
- Password authentication
- Multi-factor authentication
- Rate limiting per user/IP
- OIDC discovery endpoint per tenant: `GET /tenants/{tenant_id}/.well-known/openid-configuration`
- JWKS endpoint per tenant: `GET /tenants/{tenant_id}/.well-known/jwks.json`
- PKCE support for public clients

**Note:** Refresh token issuance is included in this PRD as foundation for PRD-016 (Token Lifecycle & Revocation), which implements the full refresh flow and revocation capabilities.

---

## 13. Deferred Tenant & Client Integration

Authentication flows currently accept and validate client_id directly.
Tenant resolution via client_id will be delegated to Tenant & Client Management (PRD-026A) once integrated.

Until then, auth behavior remains unchanged to avoid cross-PRD coupling during MVP implementation.

## 14. Open Questions

1. **User Auto-Creation:** Should we auto-create users on first auth?

   - **Recommendation:** Yes, for demo purposes. Simplifies onboarding.

2. **Token Revocation / Refresh:** Do we need refresh tokens or explicit token revocation?

   - **Recommendation:** Not for MVP. Consider refresh + revocation in a follow-up.

3. **GDPR Deletes:** See PRD-001B for admin-only delete scope, sequencing, and audit coverage.

---

## 15. References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- Tutorial: `docs/TUTORIAL.md` Section 1
- Architecture: `docs/architecture.md`
- Code Structure: `docs/structure.md`

---

## 16. Features Identified During Implementation

The following features were implemented to support production readiness beyond original PRD scope:

1. **Sharded Transactional Locking**: 32-shard mutex pool to reduce lock contention during concurrent authorization flows (`internal/auth/service/service.go`)
2. **Device ID Cookie Management**: httpOnly, Secure, SameSite=Strict cookie for stable device binding across sessions
3. **Rate Limiting Integration**: Authorization endpoint integrates with PRD-017 rate limiting
4. **Token Pre-generation**: JWT tokens generated before acquiring transaction locks to minimize lock hold time
5. **Request ID Correlation**: All audit events include request_id for distributed tracing
6. **Flow-specific Error Mapping**: Detailed error messages differentiate authorization code flow vs refresh flow errors

---

## Revision History

| Version | Date       | Author       | Changes                                                                                                          |
| ------- | ---------- | ------------ | ---------------------------------------------------------------------------------------------------------------- |
| 1.0     | 2025-12-03 | Product Team | Initial PRD                                                                                                      |
| 1.1     | 2025-12-05 | Engineering  | Updated to OAuth 2.0 Authorization Code Flow (RFC 6749 compliant)                                                |
|         |            |              | - Changed authorize endpoint to return `code` instead of `session_id`                                            |
|         |            |              | - Updated token endpoint to use `grant_type` and `code`                                                          |
|         |            |              | - Added code expiry, replay prevention, and redirect_uri validation                                              |
|         |            |              | - Updated Session model with Code, CodeExpiresAt, CodeUsed fields                                                |
|         |            |              | - Added FindByCode() to SessionStore interface                                                                   |
|         |            |              | - Added FindOrCreateByEmail() to User Store interface                                                            |
| 1.2     | 2025-12-11 | Engineering  | Documented JWT token format, token/session TTLs, audit events for deletes, and corrected store/service locations |
| 1.3     | 2025-12-11 | Engineering  | Carved out admin-only deletes into PRD-001B and removed delete helper methods from PRD-001 scope                 |
| 1.4     | 2025-12-12 | Engineering  | Updated to reflect PRD-016 session model and token changes:                                                      |
|         |            |              | - Separated Session, AuthorizationCode, and RefreshToken into distinct models with independent lifecycles        |
|         |            |              | - Added privacy-first device fingerprinting (DeviceFingerprintHash instead of raw PII)                           |
|         |            |              | - Added DeviceDisplayName and ApproximateLocation for session management UI                                      |
|         |            |              | - Removed authorization code fields from Session model (now in AuthorizationCodeRecord)                          |
|         |            |              | - Added refresh token issuance on token exchange                                                                 |
|         |            |              | - Added jti claim to access tokens for future revocation support                                                 |
|         |            |              | - Updated storage interfaces to reflect separated stores                                                         |
|         |            |              | - Updated acceptance criteria and testing requirements                                                           |
| 1.5     | 2025-12-14 | Engineering  | Add new section 13 for tenant flow integration                                                                   |
| 1.6     | 2025-12-17 | Engineering  | RFC 6749 compliance: Updated error codes for authorize and token endpoints                                       |
|         |            |              | - Authorize: Added missing error cases (unknown client_id, inactive client, redirect_uri mismatch)               |
|         |            |              | - Token: Changed 401 → 400 for invalid_grant errors (invalid/expired/used code, redirect_uri mismatch)           |
|         |            |              | - Added RFC section references and OAuth error codes (invalid_grant, invalid_client, invalid_request)            |
| 1.7     | 2025-12-17 | Engineering  | RFC 8414 compliance: Per-tenant issuer implementation                                                            |
|         |            |              | - Added issuer format: `{base_url}/tenants/{tenant_id}`                                                          |
|         |            |              | - Updated Token Format section with issuer documentation                                                         |
|         |            |              | - Added tenant_id to access token claims                                                                         |
|         |            |              | - Documented future work: per-tenant OIDC discovery and JWKS endpoints                                           |
| 1.8     | 2025-12-24 | Engineering  | PRD review and status verification - all acceptance criteria confirmed complete                                  |
