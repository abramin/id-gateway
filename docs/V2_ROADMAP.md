# V2 Roadmap: Pragmatic Improvements (Not an Auth0 Clone)

**Status:** Post-MVP Enhancement Plan
**Target:** Demonstrate production readiness without over-engineering
**Timeline:** 2-3 weeks after V1 completion
**Last Updated:** 2025-12-03

---

## Philosophy

V2 focuses on making the gateway **more realistic** and **more operationally credible** without trying to become a full OIDC provider or identity platform. The goal is to deepen realism in the areas that matter for interviews:

- ✅ **Do:** Real JWT signing, queue-backed audit, database persistence, observability
- ❌ **Don't:** Full OIDC certification, social login, password management, complex UX

**Key Insight:** Interviewers want to see you understand **production concerns** (tokens, persistence, monitoring, policy), not that you can recreate Auth0.

---

## Prerequisites

Before starting V2, complete:
- ✅ All V1 PRDs implemented (11 HTTP endpoints functional)
- ✅ `make test` passes with >80% coverage
- ✅ Complete end-to-end flow works (auth → consent → registry → VC → decision → audit)
- ✅ Regulated mode minimizes PII correctly

**Estimated V1 time:** 27-39 hours (3-5 days) - see `docs/prd/README.md`

---

## V2 Feature Roadmap

### Priority Ordering

Implement in this order to maximize interview value with minimal effort:

1. **Signed JWT Tokens + JWKS** (P0 - foundational for everything else)
2. **Real Database for Core Stores** (P0 - shows persistence patterns)
3. **Basic Observability** (P0 - shows operational awareness)
4. **Queue-backed Audit Pipeline** (P1 - demonstrates async patterns)
5. **Stronger Session & Token Model** (P1 - shows auth hygiene)
6. **Policy-Driven Decisions** (P2 - shows flexibility)
7. **External OIDC Provider Integration Story** (P2 - shows architectural judgment)

---

## 1. Signed JWT Tokens + JWKS

**Priority:** P0 (Critical)
**Time Estimate:** 4-6 hours
**Depends On:** None (foundational)

### What to Add

**Token Signing:**
- Replace "todo-access" and "todo-id" tokens with real **signed JWTs**
- Use `github.com/golang-jwt/jwt/v5` or `github.com/lestrrat-go/jwx/v2`
- Generate RSA 2048-bit keypair on server startup (or load from config)
- Sign access tokens with RS256 (or ES256 for smaller tokens)
- Include standard claims: `iss`, `sub`, `aud`, `exp`, `iat`, `jti`

**JWKS Endpoint:**
- Expose `GET /.well-known/jwks.json` endpoint
- Return public key in JWK format with `kid` (key ID)
- Support key rotation: old key kept for validation only

**Token Structure:**

```json
{
  "iss": "id-gateway",
  "sub": "user_123",
  "aud": ["demo-client"],
  "exp": 1735934400,
  "iat": 1735930800,
  "jti": "token_abc123",
  "scope": "openid profile",
  "email": "user@example.com"
}
```

### Implementation Steps

1. **Phase 1: Key Management (1-2 hours)**
   - Add `internal/platform/crypto/keys.go`
   - Generate RSA keypair on startup
   - Store private key in memory (later: KMS integration)
   - Expose public key as JWK

2. **Phase 2: Token Signing (2-3 hours)**
   - Update `auth/service.go` Token() method
   - Sign access token with private key
   - Create ID token with OIDC-specific claims
   - Set proper expiry (1 hour for access, 5 min for ID)

3. **Phase 3: JWKS Endpoint (1 hour)**
   - Add `GET /.well-known/jwks.json` handler
   - Return public key in JWK format
   - Include `kid`, `kty`, `use`, `alg`, `n`, `e` fields

4. **Phase 4: Token Validation (Optional)**
   - Add middleware to validate JWT on protected endpoints
   - Verify signature, expiry, audience

### Acceptance Criteria

- [ ] Access tokens are valid JWT format
- [ ] Tokens can be decoded at jwt.io
- [ ] JWKS endpoint returns valid JWK
- [ ] Tokens expire after configured duration
- [ ] Each token has unique `jti` (prevents replay)
- [ ] Signing uses RS256 or ES256

### Why It Matters for Interviews

**Shows you understand:**
- Real token-based auth patterns (not just opaque strings)
- Public-key cryptography for distributed systems
- JWKS for downstream service validation
- Token structure and standard claims

**Interview talking points:**
- "We use RS256 for asymmetric signing so downstream services can validate tokens without secret sharing"
- "JWKS endpoint enables zero-trust architecture - services fetch our public key independently"
- "We include `jti` for replay attack prevention via token blacklisting"

---

## 2. Real Database for Core Stores

**Priority:** P0 (Critical)
**Time Estimate:** 8-12 hours
**Depends On:** None (parallel with #1)

### What to Add

**Database:**
- Migrate from in-memory stores to **PostgreSQL**
- Use schema migrations with **golang-migrate/migrate** or **Atlas**
- Write raw SQL queries with **sqlc** for type-safe query generation
- Keep in-memory implementations for testing

**Stores to Migrate:**
- `UserStore` → `users` table
- `SessionStore` → `sessions` table
- `ConsentStore` → `consent_records` table
- `VCStore` → `verifiable_credentials` table
- `AuditStore` → `audit_events` table (append-only)

**Registry Cache:**
- Keep in-memory with TTL (5 min) - no persistence needed
- Or use Redis for distributed caching

### Schema Design

```sql
-- users table
CREATE TABLE users (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    verified BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- sessions table
CREATE TABLE sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
    requested_scope TEXT[],
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

-- consent_records table
CREATE TABLE consent_records (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
    purpose VARCHAR(50) NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE(user_id, purpose, granted_at)
);

-- verifiable_credentials table
CREATE TABLE verifiable_credentials (
    id VARCHAR(64) PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    subject VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
    issuer VARCHAR(100) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    claims JSONB NOT NULL,
    revoked BOOLEAN DEFAULT false
);

-- audit_events table (append-only, no updates/deletes)
CREATE TABLE audit_events (
    id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    user_id VARCHAR(64),
    action VARCHAR(100) NOT NULL,
    purpose VARCHAR(50),
    decision VARCHAR(50),
    reason TEXT,
    request_id VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_audit_user_id ON audit_events(user_id);
CREATE INDEX idx_audit_timestamp ON audit_events(timestamp);
```

### Implementation Steps

1. **Phase 1: Setup (2-3 hours)**
   - Add Postgres dependency: `go get github.com/lib/pq`
   - Add migration tool: `go get -tags 'postgres' github.com/golang-migrate/migrate/v4`
   - Create `migrations/` directory
   - Add connection pool configuration

2. **Phase 2: Migrations (2-3 hours)**
   - Write up/down migrations for each table
   - Test migrations locally with `make migrate-up`
   - Add `make migrate-down` for rollback

3. **Phase 3: Postgres Implementations (4-6 hours)**
   - Create `internal/auth/store_postgres.go`
   - Create `internal/consent/store_postgres.go`
   - Create `internal/evidence/vc/store_postgres.go`
   - Create `internal/audit/store_postgres.go`
   - Use sqlc or hand-written SQL with proper error handling

4. **Phase 4: Integration (1-2 hours)**
   - Update `cmd/server/main.go` to use Postgres stores
   - Add database health check
   - Keep in-memory stores for tests

### Acceptance Criteria

- [ ] All stores use Postgres in production mode
- [ ] Migrations run cleanly (up and down)
- [ ] Connection pool configured (max 10 connections)
- [ ] Transactions used for multi-table operations
- [ ] Tests still use in-memory stores
- [ ] Data persists across server restarts
- [ ] Proper foreign key constraints
- [ ] Indexes on lookup columns

### Why It Matters for Interviews

**Shows you understand:**
- Database schema design for identity systems
- Transaction boundaries and ACID guarantees
- Migration strategies and rollback procedures
- Connection pooling and resource management
- Separation of test infrastructure

**Interview talking points:**
- "We use foreign key cascades for GDPR data deletion - delete user, all consents auto-delete"
- "Audit table is append-only with no UPDATE/DELETE permissions - compliance requirement"
- "We keep in-memory stores for tests to avoid DB dependencies in CI/CD"

---

## 3. Basic Observability

**Priority:** P0 (Critical)
**Time Estimate:** 3-5 hours
**Depends On:** None

### What to Add

**Structured Logging:**
- Replace `log.Printf` with structured logger: `github.com/rs/zerolog` or `go.uber.org/zap`
- Include correlation ID in all logs
- Log levels: DEBUG, INFO, WARN, ERROR
- JSON format for production, pretty print for dev

**Metrics:**
- Add Prometheus metrics: `github.com/prometheus/client_golang`
- Expose `GET /metrics` endpoint
- Track:
  - HTTP request duration (histogram)
  - Request count by endpoint and status (counter)
  - Registry call duration and errors (histogram + counter)
  - Decision outcomes by status (counter)
  - Audit queue lag (gauge)

**Request Tracing (Optional):**
- Add correlation ID to all requests
- Include in logs, audit events, error responses
- Use `X-Request-ID` header or generate UUID

### Metrics to Implement

```go
var (
    httpDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "http_request_duration_seconds",
            Help: "HTTP request duration",
        },
        []string{"method", "endpoint", "status"},
    )

    registryDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "registry_call_duration_seconds",
            Help: "Registry call duration",
        },
        []string{"registry_type"},
    )

    decisionCount = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "decisions_total",
            Help: "Total decisions made",
        },
        []string{"purpose", "status"},
    )
)
```

### Implementation Steps

1. **Phase 1: Structured Logging (1-2 hours)**
   - Replace logger in `internal/platform/logger/`
   - Add correlation ID middleware
   - Update all log calls to use structured fields

2. **Phase 2: Metrics (2-3 hours)**
   - Add Prometheus dependencies
   - Create metrics package
   - Instrument HTTP handlers
   - Instrument registry calls
   - Expose /metrics endpoint

3. **Phase 3: Testing (1 hour)**
   - Verify metrics appear at /metrics
   - Test with curl or Prometheus scraper

### Acceptance Criteria

- [ ] All logs use structured format (JSON in prod)
- [ ] Correlation ID in all logs and responses
- [ ] /metrics endpoint returns Prometheus format
- [ ] Key metrics tracked (HTTP, registry, decisions)
- [ ] Metrics include proper labels
- [ ] No sensitive data in logs (no PII, no tokens)

### Why It Matters for Interviews

**Shows you understand:**
- Operational visibility requirements
- Monitoring and alerting patterns
- Structured logging best practices
- SLI/SLO foundations

**Interview talking points:**
- "We use histograms for latency to track p50/p95/p99 percentiles"
- "Correlation IDs enable tracing requests across microservices"
- "We never log PII - only user IDs and pseudonymous identifiers"

---

## 4. Queue-backed Audit Pipeline

**Priority:** P1 (High)
**Time Estimate:** 4-6 hours
**Depends On:** #2 (Postgres for durable audit storage)

### What to Add

**Queue:**
- Replace synchronous audit writes with queue
- Options:
  - **NATS** (lightweight, in-process option)
  - **Redis Streams** (if you already have Redis)
  - **Buffered Go channel** (simplest, good enough for demo)

**Worker:**
- Background goroutine that consumes from queue
- Writes batches to Postgres AuditStore
- Handles errors with retry + dead-letter queue

**Benefits:**
- Decouples request latency from audit persistence
- Survives temporary database outages
- Demonstrates async processing patterns

### Architecture

```
Handler
   ↓ (non-blocking)
Publisher.Emit() → [Queue] → Worker → Postgres
                      ↓                   ↓
                    (if fail)          Success
                      ↓
                   [DLQ]
```

### Implementation Steps

1. **Phase 1: Queue Abstraction (1-2 hours)**
   - Create `internal/audit/queue.go` interface
   - Implement buffered channel version
   - Add queue metrics (depth, lag)

2. **Phase 2: Worker (2-3 hours)**
   - Create `internal/audit/worker.go`
   - Batch writes (flush every 100 events or 5 seconds)
   - Add retry logic with exponential backoff
   - Add dead-letter queue for failed events

3. **Phase 3: Integration (1 hour)**
   - Update Publisher.Emit() to push to queue
   - Start worker in main.go
   - Add graceful shutdown (drain queue)

### Acceptance Criteria

- [ ] Audit events written asynchronously
- [ ] Queue depth tracked in metrics
- [ ] Worker retries failed writes
- [ ] Dead-letter queue captures permanent failures
- [ ] Graceful shutdown drains queue
- [ ] No audit events lost during normal operation

### Why It Matters for Interviews

**Shows you understand:**
- Asynchronous processing patterns
- Reliability vs latency tradeoffs
- Queue-based architectures
- Graceful degradation

**Interview talking points:**
- "We queue audit events to avoid blocking user requests on slow database writes"
- "DLQ captures malformed events for debugging without crashing the worker"
- "We batch writes to reduce database load while maintaining low latency"

---

## 5. Stronger Session & Token Model

**Priority:** P1 (High)
**Time Estimate:** 5-7 hours
**Depends On:** #1 (JWT tokens), #2 (Database)

### What to Add

**Refresh Tokens:**
- Long-lived refresh tokens (30 days)
- Short-lived access tokens (1 hour)
- Refresh token rotation on use
- Store refresh tokens in database

**Token Revocation:**
- Revocation list or "last valid time" per user
- Check on token validation
- Support "revoke all sessions" for user

**Enhanced Validation:**
- Validate `aud` (audience) claim
- Validate `exp` (expiry)
- Check token not revoked
- Verify signature

### Token Flow

```
1. Login: Issue access token (1h) + refresh token (30d)
2. Access expires: Use refresh token to get new access token
3. Refresh used: Rotate refresh token (issue new one, invalidate old)
4. Security event: Revoke all refresh tokens for user
```

### Implementation Steps

1. **Phase 1: Refresh Token Model (2-3 hours)**
   - Add `refresh_tokens` table
   - Generate and store refresh tokens
   - Return in `/auth/token` response

2. **Phase 2: Refresh Endpoint (1-2 hours)**
   - Add `POST /auth/refresh` endpoint
   - Validate refresh token
   - Issue new access + refresh token pair
   - Invalidate old refresh token

3. **Phase 3: Revocation (2-3 hours)**
   - Add revocation check to token validation
   - Add `POST /auth/revoke` endpoint
   - Support revoking single token or all tokens

### Acceptance Criteria

- [ ] Access tokens expire after 1 hour
- [ ] Refresh tokens work for 30 days
- [ ] Refresh token rotation on use
- [ ] Revoked tokens fail validation
- [ ] Revoke all sessions works
- [ ] Proper error messages for expired/revoked tokens

### Why It Matters for Interviews

**Shows you understand:**
- Token lifecycle management
- Security hygiene (rotation, revocation)
- Stateful vs stateless auth tradeoffs
- Incident response (revoke compromised tokens)

**Interview talking points:**
- "We rotate refresh tokens to limit window of compromise"
- "Revocation list enables immediate token invalidation for security incidents"
- "Short-lived access tokens reduce blast radius of token theft"

---

## 6. Policy-Driven Decisions (Lightweight)

**Priority:** P2 (Nice to Have)
**Time Estimate:** 4-6 hours
**Depends On:** #5 (decision engine must be complete)

### What to Add

**Policy Configuration:**
- Extract decision rules to YAML/JSON config
- Rules map `purpose` → required evidence + conditions
- Support simple boolean logic (AND/OR)
- Reload policy without restart

**Example Policy:**

```yaml
purposes:
  age_verification:
    evidence:
      - citizen_valid: true
      - is_over_18: true
      - has_credential: true
    rules:
      - if: sanctions_listed
        then: fail
        reason: "sanctioned"
      - if: NOT has_credential
        then: pass_with_conditions
        reason: "missing_credential"
        conditions: ["obtain_age_credential"]
      - else: pass

  high_value_transfer:
    evidence:
      - citizen_valid: true
      - sanctions_listed: false
    rules:
      - if: sanctions_listed
        then: fail
      - if: is_pep AND context.amount > 10000
        then: pass_with_conditions
        conditions: ["manual_review"]
      - else: pass
```

### Implementation Steps

1. **Phase 1: Policy Model (2-3 hours)**
   - Define policy structure in Go
   - Load from YAML file
   - Validate policy on startup

2. **Phase 2: Policy Engine (2-3 hours)**
   - Interpret policy rules
   - Evaluate conditions against evidence
   - Return decision outcome

3. **Phase 3: Testing (1 hour)**
   - Test multiple policy files
   - Verify rule evaluation

### Acceptance Criteria

- [ ] Policies loaded from external file
- [ ] Rules evaluated correctly
- [ ] New purposes can be added without code changes
- [ ] Policy validation on startup
- [ ] Clear error messages for invalid policies

### Why It Matters for Interviews

**Shows you understand:**
- Separation of policy and code
- Flexibility for business rules
- Collaboration with non-technical teams (risk, compliance)
- Configuration as code

**Interview talking points:**
- "We externalize policy so risk teams can update rules without redeploying"
- "Policy versioning enables A/B testing of risk postures"
- "Declarative rules are easier to audit than imperative code"

---

## 7. External OIDC Provider Integration Story

**Priority:** P2 (Documentation + Light Code)
**Time Estimate:** 2-3 hours (mostly docs)
**Depends On:** None

### What to Add

**Documentation:**
- Document integration patterns with real OIDC providers
- Explain when to build vs integrate
- Architecture diagram showing gateway behind Keycloak/Auth0

**Light Implementation:**
- Feature flag: `USE_EXTERNAL_OIDC=true`
- If enabled, validate tokens from external provider
- Skip internal user/session creation
- Focus on consent/evidence/decision only

### Architecture Diagrams

**Current (Self-Contained):**
```
User → Gateway (auth+consent+evidence+decision)
```

**Production (Integrated):**
```
User → Keycloak (auth) → Gateway (consent+evidence+decision)
                           ↓
                  Verify Keycloak JWT
```

### Implementation

Add `docs/EXTERNAL_OIDC_INTEGRATION.md`:

```markdown
# External OIDC Provider Integration

## Overview
In production, the ID Gateway delegates authentication to a real OIDC provider (Keycloak, Auth0, Okta) and focuses on its core competencies: consent, evidence gathering, and decision making.

## Integration Pattern

1. **User Login:** Handled by external OIDC provider
2. **Token Issuance:** Provider issues JWT with user claims
3. **Gateway Validation:** Gateway validates JWT signature via JWKS
4. **Consent Check:** Gateway manages consent separately
5. **Evidence Gathering:** Gateway calls registries, issues VCs
6. **Decision:** Gateway evaluates using its policy engine

## Configuration

```yaml
auth:
  mode: external_oidc
  issuer: https://keycloak.example.com/realms/demo
  jwks_url: https://keycloak.example.com/realms/demo/protocol/openid-connect/certs
  audience: id-gateway
```

## Why External OIDC?

- **Focus:** Gateway focuses on regulated identity workflows, not general-purpose auth
- **Compliance:** Leverage provider's security certifications
- **Features:** Get MFA, social login, password policies for free
- **Separation:** Auth concerns separate from identity verification

## When to Build Internal Auth

- **Demo/Testing:** Simplifies local development
- **Specific Requirements:** Unusual auth flows not supported by providers
- **Cost:** Very high scale where per-user fees matter
```

### Acceptance Criteria

- [ ] Documentation explains integration patterns
- [ ] Architecture diagrams show both modes
- [ ] Feature flag implemented (even if not fully functional)
- [ ] Clear guidance on when to build vs integrate

### Why It Matters for Interviews

**Shows you understand:**
- Build vs buy decisions
- When to integrate vs reinvent
- Architectural flexibility
- Real-world tradeoffs

**Interview talking points:**
- "We built auth for the demo, but production would use Keycloak to avoid reinventing OAuth2"
- "The gateway's value is in consent + evidence + decisions, not in being an identity provider"
- "We designed for integration from day one - feature flag switches auth mode"

---

## Summary: Why This V2 is Enough

### What You'll Have Built

After V1 + V2, your gateway will demonstrate:

✅ **Real Auth:** JWT tokens with JWKS, not toy strings
✅ **Persistence:** Postgres with migrations, not in-memory maps
✅ **Observability:** Structured logs, metrics, correlation IDs
✅ **Async Processing:** Queue-backed audit pipeline
✅ **Token Hygiene:** Refresh tokens, revocation, expiry
✅ **Flexibility:** Policy-driven decisions
✅ **Architectural Maturity:** Integration story with external OIDC

### What You're NOT Building (By Design)

❌ Full OIDC certification
❌ Social login integrations
❌ Password management and reset flows
❌ Multi-factor authentication
❌ User account management UI
❌ Email verification flows
❌ Custom OAuth scopes and claims
❌ Rate limiting and DDoS protection (mention as "would add Cloudflare")
❌ Multi-tenancy

### Interview Value

**For Backend Engineer roles:**
- Shows end-to-end thinking (auth → storage → observability)
- Demonstrates production concerns (JWT, Postgres, metrics)
- Proves async processing understanding (queue-backed audit)

**For Identity/Auth Engineer roles:**
- Shows token lifecycle mastery (issue, refresh, revoke)
- Demonstrates regulated domain awareness (consent, audit, minimization)
- Proves integration vs build-your-own judgment

**For Senior Engineer roles:**
- Shows architectural tradeoffs (V1 simplicity → V2 realism)
- Demonstrates incremental improvement strategy
- Proves scope management (enough but not too much)

---

## Implementation Timeline

**Total V2 Time:** 28-43 hours (3.5-5 days)

### Week 1: Foundation
- Days 1-2: Signed JWT + JWKS (4-6h) + Database migration (8-12h)
- Days 3-4: Observability (3-5h) + Queue-backed audit (4-6h)

### Week 2: Enhancement
- Days 1-2: Session & token model (5-7h)
- Day 3: Policy-driven decisions (4-6h)
- Day 4: External OIDC docs (2-3h)

### Week 3: Polish
- Testing, documentation, cleanup

---

## Getting Started with V2

1. **Read this roadmap** completely
2. **Complete V1 first** (all PRDs implemented)
3. **Start with #1** (Signed JWT) - foundational for everything else
4. **Add #2** (Database) next - enables persistence for all features
5. **Continue in priority order**

---

## References

- **V1 PRDs:** `docs/prd/README.md` - Implement these first
- **Architecture:** `docs/architecture.md` - System design
- **Productionization:** `docs/productionization.md` - Full production checklist
- **Tutorial:** `docs/TUTORIAL.md` - Step-by-step learning guide

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-03 | Product Team | Initial V2 Roadmap |
