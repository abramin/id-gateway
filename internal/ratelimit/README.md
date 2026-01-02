# Rate Limiting Module

Implementation of PRD-017: Rate Limiting & Abuse Prevention.

---

## Domain Design

### Bounded Context

**Context:** `internal/ratelimit`

**Purpose:** Rate limiting and abuse prevention for the Credo platform:
- Per-IP and per-user rate limiting with sliding window algorithm
- Authentication-specific protections (lockouts, progressive backoff signals)
- Allowlist management for bypassing rate limits
- Partner API quotas for monthly usage tracking
- Global throttling for DDoS protection

### Key Domain Models

| Model              | Purpose                                           |
| ------------------ | ------------------------------------------------- |
| **AllowlistEntry** | Exempts IPs/users from rate limiting              |
| **AuthLockout**    | Authentication attempt limits and temporary locks |
| **APIKeyQuota**    | Monthly quota tracking for partner API keys       |
| **RateLimitKey**   | Value object for safe bucket key construction     |
| **RateLimitResult**| DTO encapsulating check outcome                   |

### Aggregates

**AllowlistEntry Aggregate**
- Lifecycle: created -> active -> expired
- One entry per (type, identifier) pair
- Expiration checked at query time via `IsExpiredAt(now)`

**AuthLockout Aggregate**
- State machine: unlocked -> soft lock -> hard lock
- Composite key: (username:IP) prevents cross-IP attacks
- Intent-revealing methods:
  - `RecordFailure(now)` - increment counters
  - `ShouldHardLock(threshold)` - decision point
  - `ApplyHardLock(duration, now)` - state transition
  - `IsLockedAt(now)` - current lock status
  - `RemainingAttempts(limit)` - for client feedback

**APIKeyQuota Aggregate**
- Monthly periods aligned to calendar month
- Tiers: free, starter, business, enterprise
- Overage policy per tier

### Invariants

- Allowlist identifiers must be valid (non-empty, valid IP format for `type=ip`)
- AuthLockout composite key (username:IP) prevents cross-IP attacks
- Rate limit keys sanitize colons to prevent injection (`user:admin` -> `user_admin`)
- Default-deny when endpoint class is missing from config

---

## Ports & Adapters

**Ports (Interfaces):**
- `AllowlistStore` - bypass list persistence
- `BucketStore` - rate limit counters (sliding window)
- `AuthLockoutStore` - auth failure tracking
- `QuotaStore` - monthly usage tracking
- `GlobalThrottleStore` - per-instance throttle counters

**Adapters:**
- PostgreSQL implementations for runtime persistence
- In-memory implementations retained for tests

---

## Key Design Decisions

**Fail-Open Behavior:** When rate limit checks fail, requests proceed by default (availability > strict enforcement). Middleware can be configured to fail-closed.

**Circuit Breaker + Fallback:** Middleware supports a circuit breaker and optional fallback limiter. The current server wiring uses PostgreSQL-backed stores without an in-memory fallback.

**Sliding Window Algorithm:** Fixed-size circular buffer (256 entries) per bucket. O(1) amortized per-operation complexity. Expired timestamps auto-cleaned during check.

**Global Throttle:** PostgreSQL-backed tumbling windows (per-second and per-hour) provide shared limits across instances.

**Backoff Signaling:** Auth lockout returns `Retry-After` hints; handlers do not sleep server-side.

**Key Collision Prevention:** `RateLimitKey` escapes colons in identifiers, preventing injection attacks.

---

## Overview

This module provides rate limiting and abuse prevention for the Credo platform:

- **Per-IP rate limiting** with configurable limits by endpoint class
- **Per-user rate limiting** for authenticated endpoints
- **Per-client rate limiting** for OAuth clients (confidential vs public)
- **Authentication lockout** for brute-force protection
- **Allowlist management** for bypassing rate limits
- **Partner API quotas** for monthly usage tracking
- **Global throttling** for DDoS protection

---

## Product Notes

- Sliding windows prevent boundary spikes common with fixed windows.
- Multiple layers (IP, user, client) allow different abuse patterns to be contained.
- Allowlist and reset endpoints give ops a manual escape hatch during incidents.

---

## Module Structure

```
internal/ratelimit/
├── admin/            # Admin services for allowlist/reset
├── config/           # Default limits and config
├── handler/          # HTTP handlers for admin endpoints
├── metrics/          # Prometheus metrics
├── middleware/       # HTTP middleware for rate limiting
├── models/           # Domain models, requests, responses
├── ports/            # Interface definitions
├── service/          # Focused services (requestlimit, authlockout, quota, etc.)
├── store/            # Persistence (PostgreSQL + test-only in-memory)
└── workers/          # Background cleanup workers
```

---

## Quick Start

### Apply middleware to routes

```go
import (
    rlMiddleware "credo/internal/ratelimit/middleware"
    "credo/internal/ratelimit/models"
    rlRequest "credo/internal/ratelimit/service/requestlimit"
    "credo/internal/ratelimit/store/bucket"
    "credo/internal/ratelimit/store/allowlist"
)

db := /* *sql.DB */
bucketStore := bucket.NewPostgres(db)
allowlistStore := allowlist.NewPostgres(db)

requestSvc, _ := rlRequest.New(bucketStore, allowlistStore)
limiter := rlMiddleware.NewLimiter(requestSvc, nil) // add globalthrottle service if used

mw := rlMiddleware.New(limiter, logger)

r.With(mw.RateLimit(models.ClassAuth)).Post("/auth/authorize", authHandler)
r.With(mw.RateLimitAuthenticated(models.ClassRead)).Get("/auth/userinfo", userinfoHandler)
```

### Register admin endpoints (allowlist + reset)

```go
import rlHandler "credo/internal/ratelimit/handler"

handler := rlHandler.New(adminSvc, logger)
handler.RegisterAdmin(adminRouter)
```

### Register quota admin endpoints (optional)

```go
import rlHandler "credo/internal/ratelimit/handler"

quotaHandler := rlHandler.NewQuotaHandler(quotaSvc, logger)
quotaHandler.RegisterAdmin(adminRouter)
```

**Note:** The default server wiring in `cmd/server/main.go` does not register these handlers.

---

## Rate Limit Tiers (Default Config)

### Per-IP Limits

| Endpoint Class | Rate Limit | Window |
|----------------|------------|--------|
| `auth`      | 10 req/min  | 1 min |
| `sensitive` | 30 req/min  | 1 min |
| `read`      | 100 req/min | 1 min |
| `write`     | 50 req/min  | 1 min |
| `admin`     | 10 req/min  | 1 min |

### Per-User Limits

| Endpoint Class | Rate Limit | Window |
|----------------|------------|--------|
| `auth`      | 50 req/hour  | 1 hour |
| `sensitive` | 20 req/hour  | 1 hour |
| `read`      | 200 req/hour | 1 hour |
| `write`     | 100 req/hour | 1 hour |
| `admin`     | 20 req/hour  | 1 hour |

### Per-Client Limits

| Client Type      | Rate Limit | Window |
|------------------|------------|--------|
| Confidential     | 100 req/min | 1 min |
| Public           | 30 req/min  | 1 min |

### Global Throttle (per instance)

- 1000 req/sec per instance
- 100000 req/hour per instance

---

## Response Headers

All responses include rate limit headers:

```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1735934400
```

When rate limit is exceeded (429 response):

```
Retry-After: 45
```

When using fallback limiter:

```
X-RateLimit-Status: degraded
```

---

## Admin API (Handlers)

### Allowlist

```bash
POST /admin/rate-limit/allowlist
{
  "type": "ip",
  "identifier": "192.168.1.100",
  "reason": "Internal monitoring service",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

```bash
DELETE /admin/rate-limit/allowlist
{
  "type": "ip",
  "identifier": "192.168.1.100"
}
```

### Reset Rate Limit

```bash
POST /admin/rate-limit/reset
{
  "type": "ip",
  "identifier": "192.168.1.100",
  "class": "auth"
}
```

### Quota Management (PRD-017 FR-5)

```bash
GET /admin/rate-limit/quota/{api_key}
POST /admin/rate-limit/quota/{api_key}/reset
GET /admin/rate-limit/quotas
PUT /admin/rate-limit/quota/{api_key}/tier
```

---

## Security Notes

- **Auth lockout** enforces soft/hard lock thresholds and reports `Retry-After` values.
- **RequiresCaptcha** is computed in the auth lockout model, but is not yet surfaced in auth HTTP responses.
- **Trusted proxy handling** prevents X-Forwarded-For spoofing (`pkg/platform/middleware/metadata`).
- **IP anonymization** in logs uses /24 (IPv4) or /48 (IPv6) truncation (`pkg/platform/privacy`).

---

## Known Gaps / Follow-ups

- PostgreSQL-backed stores are used in runtime wiring.
- Global throttle middleware is not wired in the default router.
- Quota handlers exist but are not registered by default.
- CAPTCHA requirement is computed but not surfaced in auth responses.
- Uses `X-RateLimit-*` headers instead of the IETF RateLimit header draft.

---

## Testing

```bash
# Run unit tests
go test ./internal/ratelimit/...

# Run feature tests
cd e2e && go test -v -tags=e2e
```

---

## References

- PRD: `docs/prd/PRD-017-Rate-Limiting-Abuse-Prevention.md`
- RateLimit headers draft (not implemented yet): `https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers`
- OWASP Authentication Cheat Sheet: `https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html`
