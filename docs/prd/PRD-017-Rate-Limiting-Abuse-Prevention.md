# PRD-017: Rate Limiting & Abuse Prevention

**Status:** Not Started
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Dependencies:** PRD-001 (Authentication), PRD-016 (Token Lifecycle)

---

## 1. Overview

### Problem Statement

The current system has no rate limiting or abuse prevention mechanisms. This makes it vulnerable to:

- **Brute force attacks** on login endpoints
- **Credential stuffing** using leaked password lists
- **DDoS attacks** overwhelming the service
- **Cost attacks** (excessive registry API calls, VC issuance)
- **Resource exhaustion** (filling databases, caches)
- **Enumeration attacks** (discovering valid user accounts)

Rate limiting is **critical for production** and should be implemented before any public deployment.

### Goals

- Implement per-user rate limiting (differentiated by endpoint class)
- Implement per-IP rate limiting with sliding windows
- Provide distributed rate limiting (Redis-backed) for multi-instance deployments
- Return standard rate limit headers (X-RateLimit-\*)
- Support quota management for partner APIs (API keys)
- Prevent DDoS with global request throttling
- Add bot detection patterns

### Non-Goals

- Advanced bot detection (CAPTCHA, behavioral analysis) - see PRD-023
- Distributed tracing for rate limit decisions
- Real-time rate limit dashboards
- Geographic blocking / CDN-level protection
- Application-level DDoS mitigation (use cloud provider)

---

## 2. User Stories

**As a system operator**
**I want to** rate limit authentication attempts per IP
**So that** brute force attacks are prevented

**As a platform engineer**
**I want to** differentiated rate limits by endpoint class
**So that** critical endpoints are better protected

**As a partner integrator**
**I want to** see rate limit headers in API responses
**So that** I can implement proper retry logic

**As a compliance officer**
**I want to** audit rate limit violations
**So that** I can identify attack patterns

**As a platform engineer**
**I want to** rate limit OAuth clients by client_id
**So that** compromised or misbehaving clients are isolated and don't affect other applications

---

## 3. Functional Requirements

### FR-1: Per-IP Rate Limiting

**Scope:** All public endpoints

**Description:** Limit requests per IP address using sliding window algorithm.

**Rate Limit Tiers:**

| Endpoint Class           | Rate Limit    | Window | Example Endpoints                               |
| ------------------------ | ------------- | ------ | ----------------------------------------------- |
| **Authentication**       | 10 req/min    | 1 min  | `/auth/authorize`, `/auth/token`                |
| **Sensitive Operations** | 30 req/min    | 1 min  | `/consent`, `/vc/issue`, `/decision/evaluate`   |
| **Read Operations**      | 100 req/min   | 1 min  | `/auth/userinfo`, `/consent`, `/me/data-export` |
| **Global Limit**         | 1000 req/hour | 1 hour | All endpoints combined                          |

**Headers:**

Response includes:

```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1735934400 (Unix timestamp)
Retry-After: 45 (seconds, only on 429 response)
```

**Response on Limit Exceeded (429):**

```json
{
  "error": "rate_limit_exceeded",
  "message": "Too many requests from this IP address. Please try again later.",
  "retry_after": 45
}
```

**Business Logic:**

1. Extract client IP from request (handle X-Forwarded-For for proxies)
2. Determine endpoint class from route
3. Check rate limit for IP + endpoint class; if config/limits are missing, default to deny and emit an operational alert.
4. If limit exceeded:
   - Return 429 Too Many Requests
   - Include Retry-After header
   - Emit audit event: `rate_limit_exceeded`
5. Else:
   - Increment counter atomically
   - Add rate limit headers to response
   - Continue processing

---

### FR-2: Per-User Rate Limiting

**Scope:** Authenticated endpoints

**Description:** Limit requests per authenticated user to prevent account abuse.

**Rate Limit Tiers:**

| Endpoint Class           | Rate Limit   | Window | Reason                   |
| ------------------------ | ------------ | ------ | ------------------------ |
| **Consent Operations**   | 50 req/hour  | 1 hour | Prevent consent spam     |
| **Registry Lookups**     | 100 req/hour | 1 hour | Limit external API costs |
| **VC Issuance**          | 20 req/hour  | 1 hour | Prevent VC flooding      |
| **Decision Evaluations** | 200 req/hour | 1 hour | Prevent compute abuse    |
| **Data Export**          | 5 req/hour   | 1 hour | Expensive operation      |

**Composite Key:** `user_id:endpoint_class`

**Business Logic:**

1. Extract user_id from JWT claims
2. Check user-specific rate limit
3. If limit exceeded → 429 with user-specific message
4. Track separately from IP limits (both must pass)

**Response on Limit Exceeded (429):**

```json
{
  "error": "user_rate_limit_exceeded",
  "message": "You have exceeded your request quota for this operation.",
  "quota_limit": 50,
  "quota_remaining": 0,
  "quota_reset": 1735934400
}
```

---

### FR-2b: Authentication-Specific Protections (OWASP Authentication Cheat Sheet)

**Scope:** `/auth/authorize`, `/auth/token`, `/auth/password-reset`, `/mfa/challenge`, `/mfa/enroll`

**Description:** Combine credential-specific throttles with global limits to slow brute force and credential stuffing.

**Controls:**

- Username/email and IP combined key with sliding window: 5 attempts/15 minutes, hard lock for 15 minutes after 10 failures/day; emit audit `auth.lockout`.
- Progressive backoff before 401/429 responses (250ms → 500ms → 1s) to reduce online guessing speed.
- Generic error messaging to prevent account enumeration (same response for invalid username vs password/MFA code).
- Require CAPTCHA or out-of-band verification after 3 consecutive lockouts within 24 hours.
- OTP verification endpoints share the same counters to prevent bypassing login limits.

**Account Lockout Response (429):**

```json
{
  "error": "account_locked",
  "message": "Account temporarily locked due to too many failed attempts. Please try again later or reset your password.",
  "retry_after": 900,
  "support_url": "https://example.com/support"
}
```

Note: This response intentionally does not reveal whether the account exists (prevents enumeration).

---

### FR-2c: Per-Client Rate Limiting (OAuth client_id)

**Scope:** OAuth endpoints (`/auth/authorize`, `/auth/token`, `/auth/revoke`, `/auth/introspect`)

**Description:** Rate limit requests by OAuth `client_id` to isolate misbehaving or compromised clients. Uses trust-based tiers where confidential clients (server-side with client_secret) get higher limits than public clients (SPAs, mobile apps).

**Rationale:**

- **Compromised client isolation** - If client credentials leak, limits prevent the compromised client from overwhelming the auth server
- **Per-application quotas** - Different OAuth apps can have differentiated limits
- **Harder to circumvent than IP** - Client IDs require registration; attackers can't easily create new ones

**Rate Limit Tiers (Trust-Based):**

| Client Type      | Rate Limit  | Window | Rationale                                      |
| ---------------- | ----------- | ------ | ---------------------------------------------- |
| **Confidential** | 100 req/min | 1 min  | Server-side clients with secure secret storage |
| **Public**       | 30 req/min  | 1 min  | SPAs/mobile apps - higher abuse risk           |

**Composite Key:** `client:{client_id}:{endpoint}`

**Headers:** (same pattern as FR-1)

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 85
X-RateLimit-Reset: 1735934400
```

**Response on Limit Exceeded (429):**

```json
{
  "error": "client_rate_limit_exceeded",
  "message": "OAuth client has exceeded its request quota. Please retry later.",
  "retry_after": 30
}
```

**Business Logic:**

1. Extract `client_id` from request (query param for authorize, body/header for token)
2. Lookup client type (confidential vs public) from client registry
3. Determine rate limit based on client type
4. Check rate limit for `client:{client_id}:{endpoint}`
5. If limit exceeded:
   - Return 429 Too Many Requests
   - Include Retry-After header
   - Emit audit event: `client_rate_limit_exceeded`
6. Else:
   - Increment counter
   - Add rate limit headers
   - Continue processing

**Interaction with Other Limits:**

Client rate limits are checked **after** IP rate limits but **before** user rate limits:

```
Request → Global throttle → IP limit → Client limit → User limit → Handler
```

All limits must pass. The most restrictive result is returned to the client.

---

### FR-3: Sliding Window Algorithm

**Implementation:** Token bucket or sliding window counter

**Why Sliding Window:**

- More accurate than fixed windows
- Prevents "boundary attacks" (spike at window edge)
- Smooth rate distribution

**Algorithm (Redis-backed):**

```
Key: rate_limit:{scope}:{identifier}:{window}
Value: Sorted set of timestamps

On each request:
1. Remove timestamps older than window: ZREMRANGEBYSCORE key 0 (now - window)
2. Count remaining timestamps: ZCARD key
3. If count >= limit → reject (429)
4. Else: Add current timestamp: ZADD key now now
5. Set expiry on key: EXPIRE key (window + buffer)
```

**Advantages:**

- Accurate sliding window
- Handles distributed deployments
- O(log N) complexity with Redis sorted sets
- Automatic cleanup with TTL

---

### FR-4: Rate Limit Bypass (Allowlist)

**Endpoint:** `POST /admin/rate-limit/allowlist` (admin only)

**Description:** Allow specific IPs or users to bypass rate limits.

**Input:**

```json
{
  "type": "ip", // or "user_id"
  "identifier": "192.168.1.100",
  "reason": "Internal monitoring service",
  "expires_at": "2025-12-31T23:59:59Z" // optional
}
```

**Output:**

```json
{
  "allowlisted": true,
  "identifier": "192.168.1.100",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

**Error Responses:**

**401 Unauthorized (missing or invalid token):**

```json
{
  "error": "unauthorized",
  "message": "Admin authentication required"
}
```

**403 Forbidden (insufficient permissions):**

```json
{
  "error": "forbidden",
  "message": "Insufficient permissions to manage rate limit allowlist"
}
```

**400 Bad Request (invalid input):**

```json
{
  "error": "invalid_request",
  "message": "Invalid allowlist entry",
  "details": {
    "type": "must be 'ip' or 'user_id'",
    "identifier": "invalid format"
  }
}
```

**Security Note (per AGENTS.md Principle #7):** Error responses must NEVER echo the actual user-provided identifier value. Only echo field names and generic validation messages. The raw identifier should be logged server-side for debugging but never returned to the client.

**404 Not Found (when removing from allowlist):**

```json
{
  "error": "not_found",
  "message": "Identifier not found in allowlist"
}
```

**Business Logic:**

1. Validate admin JWT token
2. Add identifier to allowlist (Redis set)
3. Set optional TTL for automatic expiry
4. Emit audit event: `rate_limit_allowlist_added`

**Middleware Check:**
Before rate limiting, check if identifier is in allowlist.

---

### FR-5: Partner API Quotas (API Keys)

**Scope:** Partner integrations with API keys

**Description:** Enforce monthly quotas for partner API usage.

**Quota Tiers:**

| Tier           | Monthly Quota    | Overage    | Price  |
| -------------- | ---------------- | ---------- | ------ |
| **Free**       | 1,000 requests   | Blocked    | $0     |
| **Starter**    | 10,000 requests  | $0.01/req  | $50    |
| **Business**   | 100,000 requests | $0.005/req | $400   |
| **Enterprise** | Unlimited        | Negotiated | Custom |

**Headers:**

```
X-Quota-Limit: 10000
X-Quota-Remaining: 7583
X-Quota-Reset: 1738291200 (first of next month)
```

**Business Logic:**

1. Extract API key from `X-API-Key` header
2. Lookup quota tier for API key
3. Check current usage for current month
4. If quota exceeded:
   - If overage allowed → charge, continue
   - Else → 429 with quota message
5. Increment usage counter
6. Add quota headers to response

**Error Responses:**

**401 Unauthorized (invalid API key):**

```json
{
  "error": "invalid_api_key",
  "message": "API key is missing or invalid"
}
```

**403 Forbidden (API key lacks access):**

```json
{
  "error": "forbidden",
  "message": "API key does not have access to this resource"
}
```

**429 Too Many Requests (quota exceeded):**

```json
{
  "error": "quota_exceeded",
  "message": "Monthly API quota exceeded. Upgrade your plan for additional requests.",
  "quota_limit": 1000,
  "quota_used": 1000,
  "quota_reset": 1738291200,
  "upgrade_url": "https://example.com/plans"
}
```

---

### FR-6: DDoS Protection (Global Throttling)

**Scope:** All endpoints

**Description:** Global request throttling to prevent service-wide overload.

**Limits:**

- **Per-instance:** 1,000 req/sec
- **Global (all instances):** 10,000 req/sec

**Implementation:**

1. Use token bucket algorithm per instance
2. Use Redis counter for global limit
3. If global limit exceeded:
   - Return 503 Service Unavailable
   - Include Retry-After header
   - Shed load gracefully (fail fast)

**Response (503):**

```json
{
  "error": "service_unavailable",
  "message": "Service is temporarily overloaded. Please try again later.",
  "retry_after": 60
}
```

---

### FR-7: Rate Limiter Failure Mode

**Scope:** All rate-limited endpoints

**Description:** Define behavior when the rate limiting infrastructure (Redis) is unavailable.

**Policy:** Bounded Fail Open with Mandatory Fallback (per AGENTS.md Principle #10: Rotate, Repave, Repair)

**Rationale:**

- Availability over security for transient failures
- Redis failures should be rare and short-lived
- Denying all requests would cause complete service outage
- **However:** Unbounded fail-open creates attack vector (exhaust Redis to bypass limits)

**Fallback Behavior:**

1. If Redis is unavailable, use in-memory fallback limiter (MANDATORY for auth endpoints)
2. Log warning: `rate_limiter_unavailable`
3. Emit metric: `rate_limit.fallback_allow`
4. Set header: `X-RateLimit-Status: degraded`

**Circuit Breaker (REQUIRED):**

- Open circuit after 5 consecutive Redis failures
- Half-open after 10 seconds to test recovery
- Close circuit after 3 successful operations
- Maximum degraded mode duration: 5 minutes
- **Repair trigger:** Auto-restart instance if degraded mode exceeds 5 minutes

**Monitoring:**

- Alert if fallback mode exceeds 1% of requests
- Alert if Redis connection failures persist > 30 seconds
- Alert if circuit breaker opens

**Mandatory: In-Memory Fallback for Auth Endpoints**

For authentication endpoints (`/auth/*`, `/mfa/*`), maintain a local in-memory rate limiter:

- **Required**, not optional - auth endpoints must always be rate limited
- Smaller limits than distributed version (50% of normal limits)
- Per-instance only (not shared across instances)
- Prevents total bypass during Redis outage

---

## 4. Technical Requirements

### TR-0: Validation Strategy (Boundary Validation)

**Approach:** Validate at system boundaries (middleware, handlers), use simple types internally.

**Rationale:** Domain primitives add complexity without proportional benefit for internal infrastructure code like rate limiting. The cost of over-engineering (development time, cognitive load, testing surface) exceeds the benefit when:
- Inputs come from trusted internal sources (already validated at API boundaries)
- The domain is well-understood with few edge cases
- Code is not exposed to external consumers

**When to use strict domain primitives:**
- External-facing APIs with untrusted input
- Cross-service boundaries
- Complex business rules that vary by type

**When simple types suffice:**
- Internal infrastructure (rate limiting, caching, logging)
- Single-service, single-team ownership
- Inputs already validated upstream

**Key principle:** Validate once at the boundary, trust internally.

```go
// Middleware validates IP before calling rate limit service
func RateLimitMiddleware(svc *ratelimit.Service) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ip := extractAndValidateIP(r) // Validation happens HERE
            if ip == "" {
                http.Error(w, "invalid request", http.StatusBadRequest)
                return
            }
            // Internal call uses validated string - no re-validation needed
            result, _ := svc.CheckIPRateLimit(r.Context(), ip, endpoint.Class)
            // ...
        })
    }
}
```

---

### TR-1: Rate Limiter Interface

**Location:** `internal/ratelimit/service/interfaces.go`

```go
type BucketStore interface {
    // Allow checks if a request is allowed and increments the counter.
    // Key is a simple string - validation happens at the boundary (middleware).
    Allow(ctx context.Context, key string, limit int, window time.Duration) (*RateLimitResult, error)

    // AllowN checks with custom cost (e.g., registry lookup costs 5 tokens).
    AllowN(ctx context.Context, key string, cost int, limit int, window time.Duration) (*RateLimitResult, error)

    // Reset clears the rate limit counter for a key (admin operation).
    Reset(ctx context.Context, key string) error

    // GetCurrentCount returns the current request count for a key.
    GetCurrentCount(ctx context.Context, key string) (int, error)
}

// In-memory implementation (MVP, not distributed)
type InMemoryBucketStore struct {
    mu      sync.RWMutex
    buckets map[string]*slidingWindow // key.String() -> window
}

// Production: Redis-backed (distributed)
type RedisBucketStore struct {
    client *redis.Client
}
```

### TR-2: Token Bucket / Sliding Window

**Token Bucket (simpler, good enough for MVP):**

```go
type TokenBucket struct {
    tokens    int
    capacity  int
    refillRate time.Duration
    lastRefill time.Time
    mu        sync.Mutex
}

func (b *TokenBucket) Take(cost int) bool {}
```

- Bucket refill/eviction should be handled by a background goroutine (context-aware) to amortize work across requests; emit metrics for refill latency, eviction counts, and queue depth when shared stores backpressure.

**Sliding Window (Redis, production):**

```lua
-- Redis Lua script for sliding window
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

-- Remove old entries
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

-- Count current entries
local count = redis.call('ZCARD', key)

if count < limit then
    redis.call('ZADD', key, now, now)
    redis.call('EXPIRE', key, window + 10)
    return {1, limit - count - 1}
else
    return {0, 0}
end
```

### TR-3: Middleware Implementation

**Location:** `internal/transport/http/middleware/ratelimit.go`

```go
type RateLimitMiddleware struct {
    limiter RateLimiter
    config  RateLimitConfig
}

func (m *RateLimitMiddleware) RateLimit(class EndpointClass) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        })
    }
}
```

### TR-4: Configuration

**Location:** `internal/platform/ratelimit/config.go`

```go
type EndpointClass string

const (
    ClassAuth      EndpointClass = "auth"
    ClassSensitive EndpointClass = "sensitive"
    ClassRead      EndpointClass = "read"
    ClassWrite     EndpointClass = "write"
)

type RateLimitConfig struct {
    Limits map[EndpointClass]Limit
    Global GlobalLimit
}

type Limit struct {
    RequestsPerWindow int
    Window            time.Duration
}

type GlobalLimit struct {
    PerInstance int
    PerSecond   int
}

// Load from environment variables or config file
func LoadRateLimitConfig() RateLimitConfig {
    return RateLimitConfig{
        Limits: map[EndpointClass]Limit{
            ClassAuth:      {RequestsPerWindow: 10, Window: time.Minute},
            ClassSensitive: {RequestsPerWindow: 30, Window: time.Minute},
            ClassRead:      {RequestsPerWindow: 100, Window: time.Minute},
        },
        Global: GlobalLimit{
            PerInstance: 1000,
            PerSecond:   10000,
        },
    }
}
```

### TR-5: IP Extraction (Handle Proxies)

**Location:** `internal/platform/ratelimit/ip.go`

**Secure-by-Design:** IP extraction must validate against trusted proxy list. Never blindly trust X-Forwarded-For as attackers can spoof headers to bypass rate limits.

**Validation Order (per AGENTS.md Principle #5):**
1. **Origin:** Request must come from known proxy or direct connection
2. **Size:** Limit X-Forwarded-For header length (max 500 chars)
3. **Lexical:** Validate IP format (IPv4/IPv6)
4. **Syntax:** Ensure well-formed header structure
5. **Semantic:** Only trust XFF if RemoteAddr is in trusted proxy list

```go
// ClientIP is a validated domain primitive for client IP addresses.
// Enforces validity at creation time per AGENTS.md Principle #2.
type ClientIP struct {
    addr netip.Addr
}

// ExtractClientIP extracts and validates the client IP from a request.
// Only trusts X-Forwarded-For if the request came from a trusted proxy.
func ExtractClientIP(r *http.Request, trustedProxies []netip.Prefix) (ClientIP, error) {
    // 1. Parse RemoteAddr
    remoteIP, err := parseRemoteAddr(r.RemoteAddr)
    if err != nil {
        return ClientIP{}, err
    }

    // 2. Check if request came from trusted proxy
    xff := r.Header.Get("X-Forwarded-For")
    if xff == "" || !isTrustedProxy(remoteIP, trustedProxies) {
        return ClientIP{addr: remoteIP}, nil
    }

    // 3. Size limit (prevent header bombing)
    if len(xff) > 500 {
        return ClientIP{}, errors.New("X-Forwarded-For header too long")
    }

    // 4. Parse and validate first IP in chain
    ips := strings.Split(xff, ",")
    clientIP, err := netip.ParseAddr(strings.TrimSpace(ips[0]))
    if err != nil {
        return ClientIP{}, fmt.Errorf("invalid client IP in X-Forwarded-For: %w", err)
    }

    return ClientIP{addr: clientIP}, nil
}

func (c ClientIP) String() string { return c.addr.String() }
func (c ClientIP) Addr() netip.Addr { return c.addr }
```

---

## 5. Implementation Steps

### Phase 1: Basic Rate Limiting (4-5 hours)

1. Implement RateLimiter interface (in-memory token bucket)
2. Create rate limit middleware
3. Define endpoint classes and limits
4. Apply middleware to routes
5. Add rate limit headers to responses
6. Test with curl/bombardier

### Phase 2: Per-User Limiting (2-3 hours)

1. Extract user_id from JWT in middleware
2. Implement composite key (user_id:class)
3. Track user limits separately from IP
4. Add user quota headers
5. Test with multiple users

### Phase 3: Redis Integration (3-4 hours)

1. Implement RedisLimiter with sliding window
2. Write Lua script for atomic operations
3. Configure Redis connection pool
4. Migrate from in-memory to Redis
5. Test distributed rate limiting (multiple instances)

---

## 6. Acceptance Criteria

- [ ] Per-IP rate limiting enforced on all endpoints
- [ ] Per-user rate limiting enforced on authenticated endpoints
- [ ] Rate limit headers present in all responses
- [ ] 429 responses include Retry-After header
- [ ] Sliding window algorithm prevents boundary attacks
- [ ] Redis-backed limiter works across multiple instances
- [ ] Allowlist bypasses rate limits
- [ ] Global throttling prevents service overload
- [ ] Rate limit violations emit audit events
- [ ] Per-client_id rate limiting enforced on OAuth endpoints
- [ ] Confidential clients get higher limits than public clients
- [ ] Client rate limit violations emit audit events with anonymized client_id
- [ ] Rate limits configurable via environment variables
- [ ] Load test shows rate limits hold under 10,000 req/sec
- [ ] Sliding-window deque and time-wheel alternatives implemented with O(1) amortized ops and documented complexity
- [ ] Postgres-backed limiter with `INSERT ... ON CONFLICT`, hash partitioning, and EXPLAIN-verified indexes on `(key, window_end)`
- [ ] Multi-key resets are atomic (transactional) and abuse thresholds emit lockouts + audit

---

## 7. Testing Strategy

### Load Testing

Use `bombardier` or `wrk` to test rate limits:

```bash
# Test auth endpoint limit (10 req/min)
bombardier -c 20 -n 200 -m POST \
  -H "Content-Type: application/json" \
  -b '{"email":"test@example.com","client_id":"demo"}' \
  http://localhost:8080/auth/authorize

# Expected: First 10 succeed, rest 429
```

### Distributed Test

```bash
# Run 3 instances behind load balancer
# Each instance: 100 req/min local limit
# Global: 250 req/min

# Send 300 req/min from client
# Expected: 250 succeed, 50 rejected
```

### Boundary Attack Test

```bash
# Fixed window vulnerability: spike at boundary
# Fixed: 10 req/min → 10 at T=59s, 10 at T=61s = 20 in 2 sec

# Sliding window should prevent this
# Send 10 at T=59s, 5 at T=61s → only 5 succeed
```

### Security-Focused Tests

- Default-deny when limit/config is missing or invalid; audited denial.
- Atomicity under concurrency: remaining/reset values stay consistent when hit by concurrent requests.
- Allowlist expiry and bypass validated; expired entries do not bypass.
- Global throttle triggers 503 with Retry-After and audit when thresholds exceeded.
- Lockout/FR-2b authentication throttles enforce backoff and shared counters across endpoints.
- Postgres limiter tests cover partitioning/index effectiveness via EXPLAIN and correctness under concurrent writes.
- DSA tests compare deque vs time-wheel implementations for correctness and complexity bounds.

### Invariant-Focused Tests (per AGENTS.md Test Guidelines)

Tests should assert domain invariants, not implementation details:

```go
// Invariant: A key cannot exceed its limit within any window slice
func TestSlidingWindow_NeverExceedsLimit(t *testing.T) {
    // Property-based test: for any sequence of requests,
    // the count never exceeds limit within any contiguous window
}

// Invariant: RateLimitKey with empty identifier cannot be created
func TestRateLimitKey_EmptyIdentifierFails(t *testing.T) {
    _, err := NewRateLimitKey(ScopeIP, "", ClassAuth)
    require.Error(t, err)
}

// Invariant: RateLimitDecision is immutable after creation
func TestRateLimitDecision_Immutable(t *testing.T) {
    // Verify no setter methods exist; state cannot change
}

// Invariant: Allowlisted entries bypass limits but still emit audit
func TestAllowlist_BypassWithAudit(t *testing.T) {}

// Invariant: Circuit breaker opens after threshold failures
func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {}
```

---

## 8. API Examples

### Example 1: Rate Limit Headers

```bash
curl -i http://localhost:8080/auth/userinfo \
  -H "Authorization: Bearer eyJhbGc..."

# Response:
# HTTP/1.1 200 OK
# X-RateLimit-Limit: 100
# X-RateLimit-Remaining: 95
# X-RateLimit-Reset: 1735934400
```

### Example 2: Rate Limit Exceeded

```bash
# 11th request within 1 minute to auth endpoint

curl -i http://localhost:8080/auth/authorize

# Response:
# HTTP/1.1 429 Too Many Requests
# X-RateLimit-Limit: 10
# X-RateLimit-Remaining: 0
# X-RateLimit-Reset: 1735934400
# Retry-After: 45
#
# {"error":"rate_limit_exceeded","message":"Too many requests...","retry_after":45}
```

### Example 3: Allowlist IP

```bash
# Admin adds monitoring service to allowlist
curl -X POST http://localhost:8080/admin/rate-limit/allowlist \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "ip",
    "identifier": "192.168.1.100",
    "reason": "Internal monitoring"
  }'

# Now requests from 192.168.1.100 bypass rate limits
```

---

## 9. Future Enhancements

- Adaptive rate limiting (lower limits during attacks)
- Per-endpoint custom limits (not just classes)
- Rate limit analytics dashboard
- Geolocation-based limits (different limits per region)
- CAPTCHA challenge on repeated violations
- Machine learning-based anomaly detection
- Cost-based rate limiting (expensive ops cost more tokens)

---

## 10. GDPR/Privacy Compliance

### PII in Rate Limiting

IP addresses are considered personal data under GDPR (CJEU Breyer ruling, C-582/14).
Rate limiting logs MUST NOT contain raw IP addresses.

### Required Controls

1. **Log Anonymization:** All operational logs must use truncated IPs
   - IPv4: Zero last octet (e.g., `192.168.1.47` → `192.168.1.0`)
   - IPv6: Zero last 80 bits (e.g., show only /48 prefix)
2. **Error Responses:** Never return IP addresses in client-facing error responses
3. **Audit Events:** Use anonymized IP prefix as identifier

### Implementation

Use the `privacy.AnonymizeIP()` helper for all logged IP values:

```go
import "credo/internal/platform/privacy"

// Correct: anonymized
m.logger.Error("rate limit check failed", "error", err, "ip_prefix", privacy.AnonymizeIP(ip))

// Wrong: raw IP
m.logger.Error("rate limit check failed", "error", err, "ip", ip)
```

### Future Enhancement

See PRD-034 for tiered logging with pseudonymized security audit logs
and differential retention policies.

---

## References

- [IETF Draft: RateLimit Header Fields](https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers)
- [Stripe Rate Limiting](https://stripe.com/docs/rate-limits)
- [GitHub REST API Rate Limiting](https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting)

---

## Revision History

| Version | Date       | Author       | Changes                                                                                                         |
| ------- | ---------- | ------------ | --------------------------------------------------------------------------------------------------------------- |
| 1.9     | 2025-12-19 | Engineering  | Added FR-2c: Per-Client Rate Limiting for OAuth client_id with trust-based tiers (confidential vs public)       |
| 1.8     | 2025-12-19 | Engineering  | Added Section 10: GDPR/Privacy Compliance - IP anonymization requirements for logging |
| 1.7     | 2025-12-18 | Engineering  | Simplified TR-0: Replaced domain primitives with boundary validation strategy. Use simple string keys internally, validate at middleware/handler boundaries. Reduced complexity without sacrificing security. |
| 1.6     | 2025-12-18 | Security Eng | Secure-by-design review: trusted proxy validation in TR-5, mandatory in-memory fallback with circuit breaker in FR-7, invariant-focused tests, no-echo rule for error responses |
| 1.5     | 2025-12-18 | Security Eng | Added DSA/SQL requirements (deque/time-wheel, Postgres partitioning), atomic multi-key resets, expanded testing |
| 1.4     | 2025-12-18 | Security Eng | Added default-deny posture when limits missing, atomicity, and security-focused tests                           |
| 1.3     | 2025-12-17 | Engineering  | Add comprehensive error responses for FR-4, FR-5, FR-2b; add FR-7 failure mode                                  |
| 1.2     | 2025-12-16 | Engineering  | Add background refill/eviction requirement with metrics for token buckets                                       |
| 1.1     | 2025-12-12 | Product Team | Added OWASP authentication-specific throttling and lockout guidance                                             |
| 1.0     | 2025-12-12 | Product Team | Initial PRD                                                                                                     |
