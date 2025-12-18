# Rate Limiting Module

Implementation of PRD-017: Rate Limiting & Abuse Prevention.

## Overview

This module provides rate limiting and abuse prevention for the Credo platform:

- **Per-IP rate limiting** with configurable limits by endpoint class
- **Per-user rate limiting** for authenticated endpoints
- **Authentication-specific protections** following OWASP guidelines
- **Allowlist management** for bypassing rate limits
- **Partner API quotas** for monthly usage tracking
- **Global throttling** for DDoS protection

## Module Structure

```
internal/ratelimit/
├── models/           # Domain models, requests, responses
├── service/          # Business logic and orchestration
├── store/            # Persistence (in-memory, Redis)
│   ├── bucket/       # Rate limit counters (sliding window)
│   └── allowlist/    # Allowlist entries
├── handler/          # HTTP handlers for admin endpoints
├── middleware/       # HTTP middleware for rate limiting
└── README.md        # This file
```

## Quick Start

### Apply middleware to routes

```go
import (
    rlMiddleware "credo/internal/ratelimit/middleware"
    rlService "credo/internal/ratelimit/service"
    "credo/internal/ratelimit/store/bucket"
    "credo/internal/ratelimit/store/allowlist"
)

// Create stores
bucketStore := bucket.NewInMemoryBucketStore()
allowlistStore := allowlist.NewInMemoryAllowlistStore()

// Create service
svc, _ := rlService.New(bucketStore, allowlistStore)

// Create middleware
mw := rlMiddleware.New(svc, logger)

// Apply to routes
r.With(mw.RateLimit(models.ClassAuth)).Post("/auth/authorize", authHandler)
r.With(mw.RateLimitAuthenticated(models.ClassRead)).Get("/auth/userinfo", userinfoHandler)
```

### Register admin endpoints

```go
import rlHandler "credo/internal/ratelimit/handler"

handler := rlHandler.New(svc, logger)
handler.RegisterAdmin(adminRouter)
```

## Rate Limit Tiers

### Per-IP Limits (PRD-017 FR-1)

| Endpoint Class | Rate Limit | Window | Example Endpoints |
|----------------|------------|--------|-------------------|
| `auth` | 10 req/min | 1 min | `/auth/authorize`, `/auth/token` |
| `sensitive` | 30 req/min | 1 min | `/consent`, `/vc/issue` |
| `read` | 100 req/min | 1 min | `/auth/userinfo` |
| `write` | 50 req/min | 1 min | General mutations |

### Per-User Limits (PRD-017 FR-2)

| Endpoint Class | Rate Limit | Window |
|----------------|------------|--------|
| Consent Operations | 50 req/hour | 1 hour |
| VC Issuance | 20 req/hour | 1 hour |
| Decision Evaluations | 200 req/hour | 1 hour |
| Data Export | 5 req/hour | 1 hour |

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

## Admin API

### Add to Allowlist

```bash
POST /admin/rate-limit/allowlist
{
  "type": "ip",
  "identifier": "192.168.1.100",
  "reason": "Internal monitoring service",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

### Remove from Allowlist

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

## Testing

```bash
# Run unit tests
go test ./internal/ratelimit/...

# Run feature tests (after implementing step definitions)
cd e2e && go test -v -tags=e2e
```

## References

- [PRD-017: Rate Limiting & Abuse Prevention](../../docs/prd/PRD-017-Rate-Limiting-Abuse-Prevention.md)
- [IETF RateLimit Header Draft](https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
