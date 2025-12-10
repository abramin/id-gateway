# V2+ Roadmap: Production & Advanced Features

**Status:** Post-Core Enhancement Plan
**Target:** Production readiness + distinctive showcase features
**Timeline:** 3-6 weeks after core PRD-001 through PRD-007 completion
**Last Updated:** 2025-12-06

---

## Philosophy

V2+ transforms Credo from a functional prototype into:

1. **Production-ready system** with operational maturity
2. **Distinctive platform** with advanced features that differentiate from "another Auth0 clone"

---

## Prerequisites

Before starting V2+, complete:

- ✅ All core PRDs implemented (PRD-001 through PRD-007)
- ✅ `make test` passes with >80% coverage
- ✅ Complete end-to-end flow works
- ✅ Regulated mode minimizes PII correctly

**Core System Time:** 48-61 hours (6-8 days)

---

## Development Tracks

V2+ consists of THREE parallel tracks that can be pursued simultaneously:

### Track A: Production Hardening (MUST DO)

**Priority:** P0 (Critical)
**Time:** 28-43 hours (3.5-5 days)
**Goal:** Make system operationally credible

### Track B: Operational Excellence (RECOMMENDED)

**Priority:** P1 (High)
**Time:** 15-25 hours (2-3 days)
**Goal:** Demonstrate scalability awareness

### Track C: Advanced/Showcase Features (DIFFERENTIATOR)

**Priority:** P1-P3 (varies by feature)
**Time:** 40-100 hours (5-12 days, pick 2-3 features)
**Goal:** Stand out from "basic auth gateway" projects

---

# Track A: Production Hardening (MUST DO)

## A1. Signed JWT Tokens + JWKS

**Priority:** P0 (Critical)
**Time Estimate:** 4-6 hours
**Depends On:** None (foundational)

### What to Add

**Token Signing:**

- Replace "todo-access" and "todo-id" tokens with real **signed JWTs**
- Use `github.com/golang-jwt/jwt/v5` or `github.com/lestrrat-go/jwx/v2`
- Generate RSA 2048-bit keypair on server startup
- Sign access tokens with RS256 (or ES256)
- Include standard claims: `iss`, `sub`, `aud`, `exp`, `iat`, `jti`

**JWKS Endpoint:**

- Expose `GET /.well-known/jwks.json` endpoint
- Return public key in JWK format with `kid`
- Support key rotation

**Token Structure:**

```json
{
  "iss": "credo",
  "sub": "user_123",
  "aud": ["demo-client"],
  "exp": 1735934400,
  "iat": 1735930800,
  "jti": "token_abc123",
  "scope": "openid profile"
}
```

### Implementation Steps

1. **Phase 1: Key Management** (1-2h)

   - Add `internal/platform/crypto/keys.go`
   - Generate RSA keypair on startup
   - Expose public key as JWK

2. **Phase 2: Token Signing** (2-3h)

   - Update `auth/service.go` Token() method
   - Sign tokens with private key
   - Set proper expiry

3. **Phase 3: JWKS Endpoint** (1h)
   - Add `GET /.well-known/jwks.json` handler

### Acceptance Criteria

- [ ] Tokens are valid JWT format
- [ ] Tokens can be decoded at jwt.io
- [ ] JWKS endpoint returns valid JWK
- [ ] Each token has unique `jti`

---

## A2. Real Database (PostgreSQL)

**Priority:** P0 (Critical)
**Time Estimate:** 8-12 hours
**Depends On:** None

### What to Add

**Database:**

- Migrate from in-memory stores to **PostgreSQL**
- Use schema migrations with **golang-migrate/migrate**
- Write SQL queries with **sqlc** for type safety
- Keep in-memory implementations for testing

**Stores to Migrate:**

- UserStore → `users` table
- SessionStore → `sessions` table
- ConsentStore → `consent_records` table
- VCStore → `verifiable_credentials` table
- AuditStore → `audit_events` table

### Schema Design

```sql
CREATE TABLE users (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    verified BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
    requested_scope TEXT[],
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE TABLE consent_records (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
    purpose VARCHAR(50) NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE(user_id, purpose, granted_at)
);

CREATE TABLE audit_events (
    id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    user_id VARCHAR(64),
    action VARCHAR(100) NOT NULL,
    purpose VARCHAR(50),
    decision VARCHAR(50),
    reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_audit_user_id ON audit_events(user_id);
CREATE INDEX idx_audit_timestamp ON audit_events(timestamp);
```

### Acceptance Criteria

- [ ] All stores use Postgres in production
- [ ] Migrations run cleanly
- [ ] Connection pool configured
- [ ] Data persists across restarts
- [ ] Foreign key constraints enforced

---

## A3. Basic Observability

**Priority:** P0 (Critical)
**Time Estimate:** 3-5 hours
**Depends On:** None

### What to Add

**Structured Logging:**

- Replace `log.Printf` with `github.com/rs/zerolog` or `go.uber.org/zap`
- Include correlation ID in all logs
- JSON format for production

**Metrics:**

- Add Prometheus metrics: `github.com/prometheus/client_golang`
- Expose `GET /metrics` endpoint
- Track:
  - HTTP request duration (histogram)
  - Request count by endpoint (counter)
  - Decision outcomes (counter)
  - Audit queue lag (gauge)

### Acceptance Criteria

- [ ] Structured logs in JSON format
- [ ] Correlation IDs in all logs
- [ ] Prometheus metrics exposed
- [ ] Key metrics tracked

---

## A4. Queue-Backed Audit Pipeline

**Priority:** P1 (High)
**Time Estimate:** 4-6 hours
**Depends On:** A2 (Database)

### What to Add

- In-memory channel-based queue for audit events
- Background worker to drain queue → database
- Graceful shutdown drains queue
- Retry on transient failures
- Dead-letter queue for permanent failures

### Implementation

```go
type AuditQueue struct {
    events chan audit.Event
    store  audit.Store
    wg     sync.WaitGroup
}

func (q *AuditQueue) Start(ctx context.Context) {
    q.wg.Add(1)
    go q.worker(ctx)
}

func (q *AuditQueue) worker(ctx context.Context) {
    defer q.wg.Done()
    for {
        select {
        case event := <-q.events:
            _ = q.store.Write(ctx, event) // Retry logic
        case <-ctx.Done():
            return
        }
    }
}
```

### Acceptance Criteria

- [ ] Audit events written asynchronously
- [ ] Worker retries failed writes
- [ ] Graceful shutdown drains queue
- [ ] No audit events lost

---

## A5. Stronger Session & Token Model

**Priority:** P1 (High)
**Time Estimate:** 5-7 hours
**Depends On:** A1 (JWT), A2 (Database)

### What to Add

**Refresh Tokens:**

- Long-lived refresh tokens (30 days)
- Short-lived access tokens (1 hour)
- Refresh token rotation on use
- Store refresh tokens in database

**Token Revocation:**

- Revocation list or "last valid time" per user
- Check on token validation
- Support "revoke all sessions"

### Token Flow

```
1. Login: Issue access (1h) + refresh (30d)
2. Access expires: Use refresh → new access
3. Refresh used: Rotate refresh token
4. Security event: Revoke all tokens
```

### Acceptance Criteria

- [ ] Access tokens expire after 1 hour
- [ ] Refresh tokens work for 30 days
- [ ] Token rotation on use
- [ ] Revoked tokens fail validation

---

## A6. External OIDC Integration Documentation

**Priority:** P2 (Nice to Have)
**Time Estimate:** 2-3 hours
**Depends On:** None

### What to Add

**Documentation:**

- Document integration with Keycloak/Auth0
- Explain when to build vs integrate
- Architecture diagrams

**Architecture:**

```
User → Keycloak (auth) → Gateway (consent+evidence+decision)
                          ↓
                 Verify Keycloak JWT
```

### Acceptance Criteria

- [ ] Documentation explains integration
- [ ] Architecture diagrams show both modes
- [ ] Clear guidance on build vs integrate

---

# Track B: Operational Excellence (RECOMMENDED)

See `SYSTEM_DESIGN_ROADMAP.md` for full details:

## B1. Rate Limiting & DDoS Protection

**Time:** 3-5 hours

- Token bucket algorithm per IP
- Global rate limiting
- Document: "Would add Cloudflare in production"

## B2. Advanced Monitoring

**Time:** 4-6 hours

- Distributed tracing (OpenTelemetry)
- Error tracking (Sentry)
- Alerting rules

## B3. Caching Layer

**Time:** 3-4 hours

- Redis for registry responses
- Cache invalidation strategy

## B4. Health Checks & Readiness

**Time:** 2-3 hours

- `/health` endpoint (liveness)
- `/ready` endpoint (readiness)
- Database connection check

## B5. Configuration Management

**Time:** 2-3 hours

- Environment-based config
- Secrets management
- Config validation

---

# Track C: Advanced/Showcase Features (DIFFERENTIATOR)

These features make the project stand out from "basic auth gateways". Pick 2-3 based on target job market.

## C1. Cryptographic Audit Trail (Merkle Tree)

**PRD:** PRD-006B
**Priority:** P1 (High - Easiest Advanced Feature)
**Time Estimate:** 8-12 hours
**Depends On:** A2 (Database), PRD-006 (Audit)

### What It Adds

- **Cryptographically verifiable audit logs** using Merkle trees
- Each audit entry hashed with previous entries
- Tampering detection (any modification breaks the tree)
- Proof generation for individual events
- Verification endpoint

### Why First

- Easiest advanced feature
- Clear value proposition
- Relevant to fintech, healthcare, compliance
- Strong resume line

### Resume Impact

"Built cryptographically verifiable audit system using Merkle trees for tamper-proof logging in identity verification gateway."

### Implementation Highlights

```go
type MerkleAudit struct {
    Root      []byte       // Current root hash
    Leaves    [][]byte     // Leaf hashes
    Proofs    []MerkleProof
}

func (m *MerkleAudit) Append(event audit.Event) error {
    leaf := hashEvent(event)
    m.Leaves = append(m.Leaves, leaf)
    m.Root = computeRoot(m.Leaves)
    return nil
}

func (m *MerkleAudit) GenerateProof(eventID string) MerkleProof {
    // Generate Merkle proof for event
}
```

---

## C2. Automated GDPR/CCPA Compliance

**PRD:** PRD-008
**Priority:** P1 (High - Practical & Relevant)
**Time Estimate:** 12-16 hours
**Depends On:** PRD-006 (Audit), PRD-007 (Data Rights)

### What It Adds

- **Real-time compliance checking** against GDPR/CCPA rules
- Automated data retention policies
- Policy-driven data minimization
- Compliance reports and alerts
- Data subject rights automation

### Why Second

- Practical and relevant to EU jobs
- Shows understanding of real-world constraints
- Builds on existing audit/data rights work

### Resume Impact

"Implemented automated GDPR/CCPA compliance engine with real-time policy enforcement and data retention management."

### Features

```yaml
compliance_policies:
  gdpr:
    data_minimization: true
    purpose_limitation: true
    retention:
      consent_records: 2_years
      audit_logs: 7_years
    automated_deletion: true

  ccpa:
    opt_out_sale: true
    right_to_delete: true
    right_to_know: true
```

---

## C3. ML-Based Risk Scoring

**PRD:** PRD-007B
**Priority:** P2 (Medium - Technical Showcase)
**Time Estimate:** 14-18 hours
**Depends On:** PRD-005 (Decision Engine), PRD-006 (Audit)

### What It Adds

- **Machine learning risk scoring** for identity verification
- Train on historical audit data
- Fraud detection and prevention
- Risk scores feed into decision engine
- Model explainability (SHAP values)

### Why Third

- Shows polyglot skills (Go + Python)
- Trendy (AI/ML integration)
- Moderate complexity

### Resume Impact

"Integrated ML-based fraud detection with adaptive risk scoring (Go microservices + Python ML pipeline) into identity verification system."

### Tech Stack

- **ML:** XGBoost/LightGBM (Gradient Boosting)
- **Serving:** Go service wraps Python via gRPC
- **Features:** Email domain age, device fingerprint, velocity
- **Explainability:** SHAP for feature importance

```
Risk Score: 0.23 (low risk)
Top Features:
  - email_domain_age: 3650 days → reduces risk (-0.12)
  - first_verification: true → increases risk (+0.08)
  - credential_confidence: 0.95 → reduces risk (-0.05)
```

---

## C4. Decentralized Identity (DIDs)

**PRD:** PRD-009
**Priority:** P2 (Medium - Emerging Standard)
**Time Estimate:** 16-20 hours
**Depends On:** PRD-001 (Auth), PRD-004 (VCs)

### What It Adds

- **W3C Decentralized Identifiers (DIDs)** implementation
- User-controlled identity independent of providers
- Support for `did:key` and `did:web` methods
- DID-based authentication
- Issue VCs to DIDs instead of internal IDs

### Why Fourth

- Emerging W3C standard
- Shows forward thinking
- Relevant to identity startups (Digidentity)

### Resume Impact

"Built identity verification gateway using W3C Decentralized Identifiers (DIDs) for user-controlled, portable identity."

### DID Example

```
DID: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK

DID Document:
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:key:z6Mk...",
  "verificationMethod": [{
    "id": "did:key:z6Mk...#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:key:z6Mk...",
    "publicKeyMultibase": "z6MkhaX..."
  }],
  "authentication": ["did:key:z6Mk...#key-1"]
}
```

---

## C5. Zero-Knowledge Proofs

**PRD:** PRD-010
**Priority:** P3 (Low - Most Advanced)
**Time Estimate:** 20-24 hours
**Depends On:** PRD-004 (VCs), PRD-009 (DIDs - optional)

### What It Adds

- **Zero-knowledge proofs** for privacy-preserving verification
- Prove "age > 18" without revealing birthdate
- Prove "income > $50k" without revealing exact salary
- Bulletproofs for range proofs
- Cryptographic privacy guarantees

### Why Last

- Most technically impressive
- Requires solid cryptographic foundation
- Complex implementation

### Resume Impact

"Implemented zero-knowledge proofs (Bulletproofs/Rust) for privacy-preserving age verification in identity gateway."

### ZK Example

```
User: "I want to prove I'm over 18"
Private Input: birthdate = 1985-03-15
Public Output: age >= 18 (TRUE)

Proof:
- Size: ~2KB
- Generation: <500ms
- Verification: <50ms
- Zero-knowledge: Verifier learns ONLY that age >= 18
```

---

## C6. Enhanced Verifiable Credentials

**PRD:** PRD-004B
**Priority:** P1 (High - Standards Compliance)
**Time Estimate:** 10-14 hours
**Depends On:** PRD-004 (VCs)

### What It Adds

- **BBS+ Signatures** for selective disclosure
- **Status List 2021** for revocation
- JSON-LD context support
- VC-JWT format
- Credential schemas

### Resume Impact

"Implemented W3C Verifiable Credentials with BBS+ signatures for selective disclosure and privacy-preserving credential sharing."

---

## C7. Cerbos-Based Authorization

**PRD:** PRD-005B
**Priority:** P1 (High - Industry Standard)
**Time Estimate:** 6-8 hours
**Depends On:** PRD-005 (Decision Engine)

### What It Adds

- **Cerbos** policy engine integration
- External policy management
- RBAC + ABAC support
- Policy testing framework
- Audit trail for authorization

### Resume Impact

"Integrated Cerbos authorization engine with attribute-based access control (ABAC) and external policy management."

---

# Implementation Timeline

## Minimum Viable V2 (3-4 weeks)

### Week 1: Production Hardening (Track A)

- **Days 1-2:** JWT + JWKS (4-6h) + PostgreSQL (8-12h)
- **Days 3-4:** Observability (3-5h) + Audit Queue (4-6h)
- **Day 5:** Token Refresh & Revocation (5-7h)

**Deliverable:** Production-ready gateway

### Week 2: First Showcase Feature (Track C)

- **Days 1-3:** Cryptographic Audit (PRD-006B) - 8-12 hours
- **Days 4-5:** Testing, documentation, polish

**Deliverable:** Gateway with Merkle tree audit

### Week 3: Second Showcase Feature (Track C)

- **Days 1-4:** GDPR Automation (PRD-008) - 12-16 hours
- **Day 5:** Testing, documentation

**Deliverable:** Gateway with compliance automation

### Week 4: Polish & Documentation

- Integration testing
- Performance optimization
- Comprehensive documentation
- Demo preparation

## Extended V2+ (4-6 weeks)

Add Week 5-6 for:

- **Third showcase feature** (ML Risk Scoring or DIDs)
- **Operational excellence** (rate limiting, caching, monitoring)
- **Advanced testing** (load tests, security audit)

---

# Feature Selection Strategy

## By Job Market

### Backend/Distributed Systems Roles

**Priorities:**

1. Production Hardening (Track A) - ALL
2. Merkle Tree Audit (C1)
3. Cerbos Authorization (C7)
4. Operational Excellence (B1-B5)

**Why:** Emphasizes system design, scalability, operational maturity

### Privacy/Compliance Roles

**Priorities:**

1. Production Hardening (Track A) - ALL
2. GDPR Automation (C2)
3. Zero-Knowledge Proofs (C5)
4. Merkle Tree Audit (C1)

**Why:** Emphasizes privacy, compliance, cryptography

### Fintech/Security Roles

**Priorities:**

1. Production Hardening (Track A) - ALL
2. ML Risk Scoring (C3)
3. Merkle Tree Audit (C1)
4. Enhanced VCs (C6)

**Why:** Emphasizes fraud detection, security, audit trails

### Identity/Web3 Startups

**Priorities:**

1. Production Hardening (Track A) - ALL
2. Decentralized Identity (C4)
3. Zero-Knowledge Proofs (C5)
4. Enhanced VCs (C6)

**Why:** Emphasizes emerging standards, decentralization, cryptography

---

# Success Criteria

## Production Ready (Track A Complete)

- [ ] JWT tokens signed and verifiable
- [ ] PostgreSQL persistence working
- [ ] Structured logging with correlation IDs
- [ ] Prometheus metrics exposed
- [ ] Queue-backed audit pipeline
- [ ] Token refresh and revocation
- [ ] Documentation for external OIDC

## Operationally Mature (Track B Complete)

- [ ] Rate limiting implemented
- [ ] Distributed tracing configured
- [ ] Redis caching layer
- [ ] Health checks functional
- [ ] Config management externalized

## Showcase Complete (2-3 Track C Features)

- [ ] Each feature has comprehensive documentation
- [ ] Performance benchmarks documented
- [ ] Security considerations addressed
- [ ] Integration tests passing
- [ ] Demo-ready with clear examples

---

# What You're NOT Building

**By Design** - These are explicitly out of scope:

❌ Full OIDC certification (use Keycloak instead)
❌ Social login integrations (delegate to external provider)
❌ Password management UI
❌ Multi-factor authentication
❌ Email verification flows
❌ User account management portal
❌ Multi-tenancy (can add later if needed)
❌ Mobile SDK (server-side focus)

**Reason:** Focus on distinctive identity verification features, not generic auth features.

---

# Revision History

| Version | Date       | Author       | Changes                                                               |
| ------- | ---------- | ------------ | --------------------------------------------------------------------- |
| 1.0     | 2025-12-03 | Product Team | Initial V2 Roadmap                                                    |
| 2.0     | 2025-12-06 | Product Team | Reorganized into tracks, added advanced features (DIDs, ZK, ML, GDPR) |
