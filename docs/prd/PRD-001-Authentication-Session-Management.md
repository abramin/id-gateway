# PRD-001: Authentication & Session Management

**Status:** Implementation Required
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Last Updated:** 2025-12-03

---

## 1. Overview

### Problem Statement
The ID Gateway requires a lightweight authentication system that manages user identities and sessions without implementing a full OAuth2/OIDC stack. Users need to authenticate, receive tokens, and access their profile information through standard endpoints.

### Goals
- Implement OIDC-lite authentication flow (OAuth2 + minimal identity layer)
- Manage user lifecycle (creation, retrieval, profile access)
- Handle session creation and validation
- Issue access and ID tokens for authenticated users
- Provide userinfo endpoint for profile claims

### Non-Goals
- Full OIDC certification compliance
- Social login integration (Google, Facebook, etc.)
- Password management (passwords not required for demo)
- Multi-factor authentication
- JWT signing with real cryptography (use simple tokens for MVP)

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

This implementation supports a simplified OAuth2 authorization code flow with the following optional parameters:

**redirect_uri**
- Used for browser-based flows where the user is redirected back to the client application after authentication
- The gateway appends the `session_id` and `state` as query parameters to this URI
- Client applications can then extract the session_id and exchange it for tokens
- Optional: If not provided, the response contains only the session_id

**state**
- CSRF protection token provided by the client
- The gateway echoes this value back in the redirect_uri
- Client should validate the state matches before using the session_id
- Prevents authorization code injection attacks
- Optional but recommended for production flows

**Example browser-based flow:**
1. Client redirects user to: `POST /auth/authorize` with redirect_uri and state
2. Gateway responds with: `{"redirect_uri": "https://client.com/callback?session_id=sess_xyz&state=abc"}`
3. Client redirects user to the returned redirect_uri
4. Client validates state matches, extracts session_id
5. Client calls `POST /auth/token` with session_id to get tokens

---

## 3. Functional Requirements

### FR-1: User Authorization
**Endpoint:** `POST /auth/authorize`

**Description:** Initiate an authentication session for a user by email. If the user doesn't exist, create them automatically.

**Input:**
```json
{
  "email": "user@example.com",
  "client_id": "demo-client",
  "scopes": ["openid", "profile"],      // Optional
  "redirect_uri": "https://app.example.com/callback",  // Optional
  "state": "xyz123"                     // Optional, CSRF protection
}
```

**Output (Success - 200):**
```json
{
  "session_id": "sess_abc123xyz",
  "redirect_uri": "https://app.example.com/callback?session_id=sess_abc123xyz&state=xyz123"
}
```

**Business Logic:**
1. Validate email format
2. Validate redirect_uri format if provided (must be valid URL)
3. Check if user exists by email
4. If not exists, create new user with:
   - Generated unique ID
   - Email as provided
   - FirstName/LastName extracted from email (before @)
   - Verified = false
5. If exists, retrieve user
6. Create new session with:
   - Generated unique ID
   - UserID from step 3/4
   - RequestedScope from input (default to ["openid"] if empty)
   - Status = "pending_consent"
   - CreatedAt = current timestamp
7. Save session to SessionStore
8. Build redirect_uri response:
   - If redirect_uri provided: append session_id and state as query params
   - If state provided: echo it back in response for CSRF validation
9. Return session_id and redirect_uri

**Error Cases:**
- 400 Bad Request: Invalid email format
- 400 Bad Request: Invalid redirect_uri format
- 500 Internal Server Error: Store failure

---

### FR-2: Token Exchange
**Endpoint:** `POST /auth/token`

**Description:** Exchange a valid session ID for access and ID tokens.

**Input:**
```json
{
  "session_id": "sess_abc123xyz",
  "grant_type": "session"  // Custom grant type
}
```

**Output (Success - 200):**
```json
{
  "access_token": "at_sess_abc123xyz",
  "id_token": "idt_sess_abc123xyz",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Business Logic:**
1. Validate session_id is provided
2. Retrieve session from SessionStore
3. If session not found, return 404
4. Check if session is expired (if TTL implemented)
5. Generate access_token as: `"at_" + session_id`
6. Generate id_token as: `"idt_" + session_id`
7. Set expires_in = 3600 (1 hour)
8. Return tokens

**Error Cases:**
- 400 Bad Request: Missing session_id
- 404 Not Found: Session not found
- 401 Unauthorized: Session expired
- 500 Internal Server Error: Store failure

---

### FR-3: User Info Retrieval
**Endpoint:** `GET /auth/userinfo`

**Description:** Retrieve authenticated user's profile information using a bearer token.

**Input:**
- Header: `Authorization: Bearer at_sess_abc123xyz`

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
3. Parse token to extract session_id (remove "at_" prefix)
4. Retrieve session from SessionStore
5. If session not found, return 401
6. Retrieve user from UserStore using session.UserID
7. If user not found, return 401
8. Return user profile in OIDC userinfo format

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
    ID        string    // Format: "user_<uuid>"
    Email     string    // Unique, valid email format
    FirstName string    // Extracted from email or provided
    LastName  string    // Extracted from email or provided
    Verified  bool      // Email verification status (default: false)
    CreatedAt time.Time // User creation timestamp
}
```

**Session Model** (Location: `internal/auth/models.go`)
```go
type Session struct {
    ID             string   // Format: "sess_<uuid>"
    UserID         string   // Foreign key to User.ID
    RequestedScope []string // Scopes like ["openid", "profile"]
    Status         string   // "pending_consent", "active", "expired"
    CreatedAt      time.Time
    ExpiresAt      *time.Time // Optional expiry
}
```

### TR-2: Storage Interfaces

**UserStore** (Location: `internal/auth/store.go`)
```go
type UserStore interface {
    SaveUser(ctx context.Context, user *User) error
    FindUserByID(ctx context.Context, id string) (*User, error)
    FindUserByEmail(ctx context.Context, email string) (*User, error)
    DeleteUser(ctx context.Context, id string) error // For GDPR
}
```

**SessionStore** (Location: `internal/auth/store.go`)
```go
type SessionStore interface {
    SaveSession(ctx context.Context, session *Session) error
    FindSessionByID(ctx context.Context, id string) (*Session, error)
    DeleteSession(ctx context.Context, id string) error
    DeleteSessionsByUser(ctx context.Context, userID string) error // For GDPR
}
```

### TR-3: Service Layer

**AuthService** (Location: `internal/auth/service.go`)
```go
type AuthService struct {
    users    UserStore
    sessions SessionStore
}

func (s *AuthService) Authorize(ctx context.Context, req AuthorizationRequest) (*AuthorizationResult, error)
func (s *AuthService) Token(ctx context.Context, req TokenRequest) (*TokenResult, error)
func (s *AuthService) UserInfo(ctx context.Context, token string) (*User, error)
```

### TR-4: HTTP Handlers

**Handler Struct** (Location: `internal/transport/http/router.go`)
```go
type Handler struct {
    authService   *auth.AuthService
    // ... other services
}
```

**Handler Functions** (Location: `internal/transport/http/handlers_auth.go`)
```go
func (h *Handler) handleAuthorize(w http.ResponseWriter, r *http.Request)
func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request)
func (h *Handler) handleUserInfo(w http.ResponseWriter, r *http.Request)
```

### TR-5: Dependencies

**Required:**
- `internal/platform/logger` - For structured logging
- `pkg/errors` - For typed error handling
- `internal/audit` - For logging authentication events

**Store Implementation:**
- Use `internal/auth/store_memory.go` (already implemented)
- Thread-safe with `sync.RWMutex`
- Returns typed errors from `pkg/errors`

---

## 5. API Specifications

### Endpoint Summary

| Endpoint | Method | Auth Required | Purpose |
|----------|--------|---------------|---------|
| `/auth/authorize` | POST | No | Start auth session |
| `/auth/token` | POST | No | Exchange session for tokens |
| `/auth/userinfo` | GET | Yes (Bearer) | Get user profile |

### Token Format

**Access Token:** `at_<session_id>`
**ID Token:** `idt_<session_id>`
**Token Type:** Bearer
**Lifetime:** 3600 seconds (1 hour)

**Note:** For MVP, tokens are simple opaque strings. Future enhancement: Use JWT with signatures.

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
- Tokens must be unguessable (include UUIDs)
- Tokens should expire after 1 hour
- Bearer tokens must be validated on every request

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
- [ ] Test user creation with valid email
- [ ] Test user retrieval by ID and email
- [ ] Test session creation and retrieval
- [ ] Test token generation format
- [ ] Test token validation and parsing
- [ ] Test redirect_uri building with session_id and state
- [ ] Test redirect_uri validation (https required, localhost exception)
- [ ] Test state parameter echo in response
- [ ] Test error cases (invalid email, invalid redirect_uri, not found, etc.)

### Integration Tests
- [ ] Test complete flow: authorize → token → userinfo
- [ ] Test concurrent user creation (race conditions)
- [ ] Test session expiry handling
- [ ] Test invalid bearer token rejection

### Manual Testing
```bash
# 1. Authorize (Simple)
curl -X POST http://localhost:8080/auth/authorize \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "client_id": "demo"}'

# Expected: {"session_id": "sess_...", "redirect_uri": ""}

# 1b. Authorize (With redirect and state - OAuth2 flow)
curl -X POST http://localhost:8080/auth/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "client_id": "demo",
    "redirect_uri": "https://myapp.com/callback",
    "state": "abc123",
    "scopes": ["openid", "profile"]
  }'

# Expected: {"session_id": "sess_...", "redirect_uri": "https://myapp.com/callback?session_id=sess_...&state=abc123"}

# 2. Get Token
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{"session_id": "sess_..."}'

# Expected: {"access_token": "at_...", "id_token": "idt_...", ...}

# 3. Get UserInfo
curl http://localhost:8080/auth/userinfo \
  -H "Authorization: Bearer at_sess_..."

# Expected: {"sub": "user_...", "email": "alice@example.com", ...}
```

---

## 9. Implementation Steps

### Phase 1: Service Layer (2-3 hours)
1. Update `AuthService` in `internal/auth/service.go`
2. Implement `Authorize()` method:
   - Find or create user by email
   - Create session
   - Return session ID and user ID
3. Implement `Token()` method:
   - Validate session
   - Generate tokens
   - Return token response
4. Implement `UserInfo()` method:
   - Parse bearer token
   - Retrieve session and user
   - Return user profile

### Phase 2: HTTP Handlers (1-2 hours)
1. Update `Handler` struct in `router.go` to include `AuthService`
2. Implement `handleAuthorize`:
   - Parse JSON request body
   - Call `authService.Authorize()`
   - Return JSON response or error
3. Implement `handleToken`:
   - Parse JSON request body
   - Call `authService.Token()`
   - Return JSON response or error
4. Implement `handleUserInfo`:
   - Extract bearer token from header
   - Call `authService.UserInfo()`
   - Return JSON response or error

### Phase 3: Dependency Injection (30 min)
1. Update `cmd/server/main.go`:
   - Initialize UserStore (already exists)
   - Initialize SessionStore (already exists)
   - Create AuthService with stores
   - Pass AuthService to HTTP Handler
2. Wire up in router

### Phase 4: Testing (1-2 hours)
1. Write unit tests for AuthService methods
2. Write integration test for complete flow
3. Manual testing with curl commands
4. Edge case testing (invalid inputs, not found, etc.)

---

## 10. Acceptance Criteria

- [ ] User can authenticate with email and receive session ID
- [ ] User can exchange session ID for access and ID tokens
- [ ] User can retrieve profile using bearer token
- [ ] Invalid bearer tokens return 401 Unauthorized
- [ ] Non-existent sessions return 404 Not Found
- [ ] All authentication events are logged to audit system
- [ ] Concurrent requests don't cause race conditions
- [ ] All endpoints return proper error responses
- [ ] Code passes `make test` and `make lint`
- [ ] Manual curl tests work as documented

---

## 11. Dependencies & Blockers

### Dependencies
- `internal/auth/store_memory.go` - ✅ Already implemented
- `pkg/errors` - ✅ Already implemented
- `internal/audit` - ✅ Already implemented
- `internal/platform/logger` - ✅ Already implemented

### Potential Blockers
- None identified

---

## 12. Future Enhancements (Out of Scope)

- Real JWT signing with RS256/ES256
- Refresh token support
- Session revocation endpoint
- Token introspection endpoint
- Password authentication
- Multi-factor authentication
- Rate limiting per user/IP
- OIDC discovery endpoint (/.well-known/openid-configuration)
- PKCE support for public clients

---

## 13. Open Questions

1. **Session Expiry:** Should sessions expire? If yes, after how long?
   - **Recommendation:** Yes, 24 hours for MVP

2. **User Auto-Creation:** Should we auto-create users on first auth?
   - **Recommendation:** Yes, for demo purposes. Simplifies onboarding.

3. **Token Revocation:** Do we need ability to revoke tokens?
   - **Recommendation:** Not for MVP. Add in Phase 2.

---

## 14. References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- Tutorial: `docs/TUTORIAL.md` Section 1
- Architecture: `docs/architecture.md`
- Code Structure: `docs/structure.md`

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-03 | Product Team | Initial PRD |
