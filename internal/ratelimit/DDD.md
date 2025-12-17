# DDD in the Rate Limiting Module

This document describes the Domain-Driven Design approach for the `internal/ratelimit` bounded context in Credo, implementing PRD-017: Rate Limiting & Abuse Prevention.

---

## 1) Bounded Context Definition

**Context:** `internal/ratelimit`

**Purpose:** Implement rate limiting and abuse prevention to protect the platform from:

- Brute force attacks on authentication endpoints
- Credential stuffing attacks
- DDoS and resource exhaustion
- API abuse and cost attacks
- Account enumeration

This is a distinct bounded context because rate limiting has its own vocabulary and invariants separate from authentication or authorization.

---

## 2) Ubiquitous Language Mapping

| Term | Code Location | Description |
|------|---------------|-------------|
| **Rate Limit** | `models.RateLimitResult` | The maximum requests allowed in a time window |
| **Endpoint Class** | `models.EndpointClass` | Category of endpoints (auth, sensitive, read, write) |
| **Sliding Window** | `store/bucket` | Algorithm for fair rate limiting without boundary attacks |
| **Allowlist** | `models.AllowlistEntry` | IPs or users exempt from rate limits |
| **Lockout** | `models.AuthLockout` | Temporary block after repeated auth failures |
| **Quota** | `models.APIKeyQuota` | Monthly request allocation for partner APIs |
| **Global Throttle** | `service.CheckGlobalThrottle` | DDoS protection via system-wide limits |

---

## 3) Domain Model

### Entities

- **AllowlistEntry**: Has identity (ID), lifecycle (expiration), tracks who created it and why
- **AuthLockout**: Tracks lockout state for an identifier, has temporal lifecycle
- **APIKeyQuota**: Tracks quota usage for a partner API key over a billing period

### Value Objects

- **EndpointClass**: Categorizes endpoints for differentiated limits (`auth`, `sensitive`, `read`, `write`)
- **RateLimitResult**: Immutable result of a rate limit check (allowed, remaining, reset time)
- **QuotaTier**: Partner API tier (`free`, `starter`, `business`, `enterprise`)

### Aggregate Roots

The rate limiting domain doesn't have traditional aggregates since state is transient (counters with TTL). However:

- **Rate limit counters** (sliding windows) are the primary stateful concept
- **Allowlist** manages a collection of AllowlistEntry entities

---

## 4) Domain Invariants vs API Input Rules

### Domain Invariants (must always hold)

- `AllowlistEntry.Identifier` cannot be empty
- `AllowlistEntry.Type` must be "ip" or "user_id"
- `AllowlistEntry.Reason` cannot be empty (audit requirement)
- Rate limit `Remaining` cannot be negative
- `AuthLockout.LockedUntil` if set, must be in the future when lockout is active

### API Input Rules (can change without data migration)

- IP format validation for allowlist
- UUID format for user_id allowlist entries
- ExpiresAt must be in the future when provided
- Rate limit values (requests per window) are configurable
- Progressive backoff timing (250ms → 500ms → 1s) is policy

---

## 5) Module Structure

```
internal/ratelimit/
├── DDD.md                    # This document
├── models/
│   ├── models.go             # Domain entities and value objects
│   ├── requests.go           # API request DTOs
│   └── responses.go          # API response DTOs
├── service/
│   ├── interfaces.go         # Store interfaces (BucketStore, AllowlistStore, etc.)
│   ├── config.go             # Configuration with defaults per PRD-017
│   ├── service.go            # Application service (orchestration)
│   └── service_test.go       # Service tests
├── store/
│   ├── bucket/
│   │   ├── store_memory.go   # In-memory sliding window (MVP)
│   │   └── store_memory_test.go
│   └── allowlist/
│       ├── store_memory.go   # In-memory allowlist (MVP)
│       └── store_memory_test.go
├── handler/
│   └── handler.go            # HTTP handlers for admin endpoints
└── middleware/
    └── ratelimit.go          # HTTP middleware for rate limiting
```

---

## 6) Layering

Following `AGENTS.md` rules:

### Middleware (`middleware/ratelimit.go`)
- HTTP concern: Extract IP, user ID from context
- Call service for rate limit checks
- Add rate limit headers to responses
- Return 429/503 when limits exceeded

### Handlers (`handler/handler.go`)
- HTTP concern: Parse JSON requests
- Call service for admin operations
- Map responses

### Service (`service/service.go`)
- Orchestration: Check allowlist, then rate limit
- Domain behavior: Progressive backoff calculation
- Error mapping: Internal errors → domain errors
- Audit: Emit events on violations and admin actions

### Stores (`store/`)
- Persistence: Sliding window counters, allowlist entries
- Return domain models, not persistence structs

---

## 7) Integration Points

### Consumes
- `internal/platform/middleware`: Extract client IP, user ID, request ID from context
- `internal/audit`: Emit audit events for violations
- `pkg/domain-errors`: Domain error codes

### Consumed By
- Router middleware chain: Apply rate limiting to all routes
- Auth module: Authentication-specific lockout integration
- Admin module: Allowlist management endpoints

---

## 8) Key Design Decisions

### Sliding Window over Token Bucket
- PRD-017 specifies sliding window to prevent boundary attacks
- More accurate rate distribution than fixed windows
- Redis implementation uses sorted sets for O(log N) complexity

### Composite Keys for Auth Lockout
- Per OWASP guidance: `{email}:{ip}` composite key
- Prevents attackers from trying different emails from same IP
- Prevents distributed attacks on single email

### Allowlist Before Rate Limit
- Allowlist check happens first (short-circuit for monitoring/internal services)
- Reduces load on rate limit stores for known-good traffic

### Progressive Backoff in Service Layer
- Backoff delays are applied in service, not middleware
- Allows for future async response patterns
- Keeps middleware focused on pass/fail decisions

---

## 9) Future Considerations

### Redis Implementation
- Replace in-memory stores with Redis for distributed deployments
- Lua scripts for atomic sliding window operations
- Separate Redis instance or cluster for rate limiting

### Adaptive Rate Limiting
- Lower limits automatically during detected attacks
- ML-based anomaly detection (PRD-023)

### Per-Endpoint Custom Limits
- Currently limits by class; may need per-endpoint overrides
- Consider endpoint registry with custom limits

---

## 10) PRD-017 Requirements Mapping

| Requirement | Implementation |
|-------------|----------------|
| FR-1: Per-IP Rate Limiting | `service.CheckIPRateLimit`, `middleware.RateLimit` |
| FR-2: Per-User Rate Limiting | `service.CheckUserRateLimit`, `middleware.RateLimitAuthenticated` |
| FR-2b: Auth Protections | `service.CheckAuthRateLimit`, `models.AuthLockout` |
| FR-3: Sliding Window | `store/bucket/store_memory.go` |
| FR-4: Allowlist Bypass | `store/allowlist`, `handler.HandleAddAllowlist` |
| FR-5: Partner Quotas | `models.APIKeyQuota`, `service.CheckAPIKeyQuota` |
| FR-6: Global Throttle | `service.CheckGlobalThrottle`, `middleware.GlobalThrottle` |
| TR-1: RateLimiter Interface | `service/interfaces.go` |
| TR-3: Middleware | `middleware/ratelimit.go` |
| TR-4: Configuration | `service/config.go` |

---

## 11) Implementation Status

### Completed (Stubs)
- [x] Domain models
- [x] Service interfaces
- [x] Service stub with method signatures
- [x] In-memory store stubs
- [x] Handler stubs
- [x] Middleware stubs
- [x] Feature file (Gherkin scenarios)
- [x] Test stubs

### TODO (Implementation)
- [ ] `InMemoryBucketStore.Allow` - sliding window algorithm
- [ ] `InMemoryAllowlistStore` - CRUD operations
- [ ] `Service.CheckIPRateLimit` - orchestration
- [ ] `Service.CheckUserRateLimit` - orchestration
- [ ] `Service.CheckBothLimits` - combined check
- [ ] `Service.CheckAuthRateLimit` - with lockout
- [ ] `Service.RecordAuthFailure` - lockout tracking
- [ ] `Service.GetProgressiveBackoff` - backoff calculation
- [ ] `Service.AddToAllowlist` - admin operation
- [ ] `Middleware.RateLimit` - apply to routes
- [ ] Handler implementations
- [ ] Cucumber step definitions
- [ ] Redis implementation (Phase 2)
