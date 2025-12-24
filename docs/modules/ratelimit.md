# Rate Limiting Module (PRD-017)

## Summary

The rate limiting module is Credo's bouncer at the door. It prevents abuse by limiting how many requests can come from a single source (IP address, user, OAuth client) within a time window. Without it, attackers could hammer the login endpoint thousands of times per second trying to guess passwords, or a single misbehaving application could overwhelm the system.

## Why this matters (product view)

- Protection from brute force attacks: Attackers can't try millions of password guesses.
- Fair resource sharing: One misbehaving client can't consume all system capacity.
- Cost control: External API calls (registries, SMS providers) have per-call costs; limiting protects budgets.
- Availability: System stays responsive even under attack or traffic spikes.
- Clear signals: Standard rate limit headers tell integrators exactly when they can retry.

## What was delivered

### Multi-Layer Rate Limiting
- **Per-IP limits**: Every IP address is limited by endpoint class (10/min for auth, 30/min for sensitive, 100/min for reads).
- **Per-user limits**: Authenticated users have separate limits (50 consent ops/hour, 100 registry lookups/hour, etc.).
- **Per-client limits**: OAuth clients are limited based on trust level (100/min for confidential, 30/min for public).
- **Global throttle**: Overall system-wide limit (1000/sec per instance) prevents complete overload.

### Sliding Window Algorithm
- **No boundary attacks**: Unlike fixed windows, sliding windows prevent "spike at minute boundary" exploits.
- **Smooth distribution**: Requests are fairly distributed over time.
- **Memory-efficient**: Sharded bucket store with LRU eviction bounds memory usage.

### Authentication Protection (OWASP-Compliant)
- **Progressive lockout**: After 5 failed attempts in 15 minutes, authentication is blocked.
- **Hard lockout**: After 10 failures in 24 hours, 15-minute hard lock.
- **Progressive backoff**: Response delays increase (250ms, 500ms, 1s) after failures.
- **Generic error messages**: Same error message for invalid username vs. wrong password (prevents enumeration).

### Admin Controls
- **Allowlist**: Trusted IPs can bypass rate limits (monitoring services, internal systems).
- **Rate limit reset**: Admins can clear limits for specific IPs or users.
- **Expiring entries**: Allowlist entries can have automatic expiration.

### Standard Headers
All responses include:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1735934400
Retry-After: 45 (on 429)
```

## Benefits

| Feature | Benefit | Who cares |
|---------|---------|-----------|
| Per-IP limits | Blocks brute force from single source | Security teams |
| Per-user limits | Prevents account abuse | Security, billing |
| Per-client limits | Isolates misbehaving applications | Operations, security |
| Sliding window | No boundary attack exploits | Security teams |
| Auth lockout | Slows credential stuffing | Security teams |
| Progressive backoff | Further slows automated attacks | Security teams |
| Standard headers | Integrators know when to retry | Developers, partners |
| Allowlist | Trusted services aren't blocked | Operations |
| Memory-bounded store | Predictable resource usage | Operations |

## Design decisions explained

### Why sliding window instead of fixed window?
With fixed 1-minute windows, an attacker could send 10 requests at second 59, then 10 more at second 61 - 20 requests in 2 seconds while "respecting" a 10/minute limit. Sliding windows count requests in a rolling window, preventing this boundary exploit.

### Why multiple limit layers (IP, user, client)?
Different attack types require different defenses:
- IP limits block anonymous attackers
- User limits prevent authenticated abuse
- Client limits isolate compromised OAuth apps
All layers must pass; the most restrictive wins.

### Why different limits for confidential vs. public OAuth clients?
Confidential clients (server-side apps with secure secret storage) are more trustworthy than public clients (SPAs, mobile apps). Public clients have higher abuse risk since their code is visible to attackers.

### Why sharded bucket store with LRU eviction?
Under attack, thousands of IPs might hit the system. Without memory bounds, the rate limit store could exhaust memory. Sharding (32 shards) reduces lock contention; LRU eviction ensures memory stays bounded.

### Why progressive backoff for auth failures?
Each delay doubles the time between attempts. This makes automated attacks impractical (millions of attempts would take years) while having minimal impact on legitimate users who occasionally mistype passwords.

### Why generic error messages for auth failures?
"Invalid username" vs. "wrong password" lets attackers enumerate valid accounts. Using the same error for both prevents this attack while still being helpful ("invalid credentials").

## Security highlights

- **OWASP-compliant auth protection**: Lockouts, backoff, generic errors per OWASP Authentication Cheat Sheet.
- **Privacy-preserving**: IP addresses are anonymized in logs (last octet zeroed).
- **Audit trail**: All rate limit violations logged for security review.
- **No bypass via header spoofing**: X-Forwarded-For only trusted from known proxies.
- **Constant-time lockout checks**: Prevents timing attacks to discover locked accounts.

## Integration points

- Middleware wraps all HTTP handlers.
- Integrates with auth service for lockout coordination.
- Metrics exposed for monitoring:
  - `credo_ratelimit_requests_total`
  - `credo_ratelimit_blocks_total`
  - `credo_ratelimit_auth_lockouts_total`
- HTTP endpoints:
  - `POST /admin/rate-limit/allowlist` - Add to allowlist
  - `DELETE /admin/rate-limit/allowlist/{id}` - Remove from allowlist
  - All protected endpoints return rate limit headers

## Known gaps / follow-ups

- **Circuit breaker**: Design documented but not fully implemented. Should open after Redis failures.
- **Quota HTTP handlers**: Service layer complete but not wired to HTTP endpoints (FR-5 partner quotas).
- **Redis backing**: Currently in-memory; needs Redis for multi-instance deployments.
- **CAPTCHA trigger**: Should require CAPTCHA after 3 consecutive lockouts (specified but not wired).
