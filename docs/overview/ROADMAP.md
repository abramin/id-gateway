# Roadmap: Production & Advanced Features

**Status:** Phase-based delivery (source of truth: `../prd/README.md`)
**Target:** MVP (Phases 0-2) -> Production Baseline (Phase 3) -> Advanced Packs (Phases 4-8)
**Timeline:** MVP ~45-60 days (110-150h effort); Production Baseline ~75-100 days (180-240h effort); Full program ~260-345 days (part-time)
**Estimation Model:** Based on Phase 0 actuals: 4-5x calendar multiplier (part-time), 1.5-2x effort multiplier (complexity)
**Last Updated:** 2025-12-24

---

## Philosophy

This roadmap transforms Credo from a functional prototype into:

1. **Production-ready system** with operational maturity
2. **Distinctive platform** with advanced features that differentiate from "another Auth0 clone"

**Note:** Phase sequencing and acceptance criteria live in `../prd/README.md`. This roadmap summarizes delivery tracks and packaging.

---

## Prerequisites

Before starting Phase 3+ work, complete Phase 0-2 PRDs:

- Required: PRD-001, PRD-001B, PRD-016, PRD-026A, PRD-017, PRD-002
- Required: PRD-003, PRD-004, PRD-005, PRD-006
- Required: PRD-019, PRD-020, PRD-028 (Performance Optimization), PRD-007
- Required: `make test` passes (coverage target defined per PRD)
- Required: Complete end-to-end flow works
- Required: Regulated mode minimizes PII correctly

**MVP System Time:** ~110-150 hours effort (45-60 days calendar at part-time pace)

---

## Development Tracks

The delivery plan consists of THREE parallel tracks that can be pursued simultaneously:

### Track A: Production Hardening (MUST DO)

**Priority:** P0 (Critical)
**Time:** 72-110 hours effort (30-45 days calendar)
**PRDs:** PRD-018, PRD-021, PRD-022, PRD-015, PRD-005B, PRD-028 (Security Enhancements)
**Goal:** Beta-ready system with notifications, recovery, MFA, and policy controls

### Track B: Operational Excellence (RECOMMENDED)

**Priority:** P1 (High)
**Time:** 30-45 hours effort (12-18 days calendar)
**PRDs:** PRD-019, PRD-020, PRD-028 (Performance Optimization), PRD-007
**Goal:** Operational baseline with versioning, SRE, performance, and data rights

### Track C: Advanced/Showcase Features (DIFFERENTIATOR)

**Priority:** P1-P3 (varies by feature)
**Time:** 70-140+ hours effort (Phase 4-8, pick packs)
**PRDs:** Phases 4-8 (Assurance, Decentralized, Integrations, Differentiation, Banking Identity)
**Goal:** Stand out from "basic auth gateway" projects

**Note:** Detailed sections below predate some PRD expansions. If conflicts exist, PRD specs in `../prd/` take precedence.

---

# Track A: Production Hardening (MUST DO)

## A1. Signed JWT Tokens + JWKS

**Priority:** P0 (Critical)
**Time Estimate:** 6-9 hours effort (3-4 days calendar)
**Depends On:** None (foundational)

### What to Add

**Current state:**

- Access and ID tokens are HS256-signed JWTs via `internal/jwt_token`.

**Upgrade (planned):**

- Migrate to asymmetric signing (RS256/ES256) with key rotation.
- Generate RSA/ECDSA keypair on server startup (or load from KMS).
- Keep standard claims: `iss`, `sub`, `aud`, `exp`, `iat`, `jti`.

**JWKS Endpoint:**

- Expose `GET /.well-known/jwks.json`
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
   - Generate or load keypair on startup
   - Expose public key as JWK

2. **Phase 2: Token Signing** (2-3h)

   - Update token creation to use RS256/ES256
   - Sign tokens with private key
   - Set proper expiry

3. **Phase 3: JWKS Endpoint** (1h)
   - Add `GET /.well-known/jwks.json` handler

### Acceptance Criteria

- [ ] Tokens are valid JWT format
- [ ] Tokens can be decoded at jwt.io with public key
- [ ] JWKS endpoint returns valid JWK
- [ ] Each token has unique `jti`

---

## A2. Real Database (PostgreSQL)

**Priority:** P0 (Critical)
**Time Estimate:** 12-18 hours effort (5-7 days calendar)
**Depends On:** None

### What to Add

**Database:**

- Migrate from in-memory stores to **PostgreSQL**
- Use schema migrations with **golang-migrate/migrate**
- Write SQL queries with **sqlc** for type safety
- Keep in-memory implementations for testing
- Defer consent projection/TR-6 work until after Postgres is in place (Phase 3 perf/hardening)

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
  - Outbox backlog/age (gauge)

**Dashboards:**

- Add a basic Grafana dashboard for core service health
- Include panels for request rate/latency, auth success rate, and error rate

### Acceptance Criteria

- [ ] Structured logs in JSON format
- [ ] Correlation IDs in all logs
- [ ] Prometheus metrics exposed
- [ ] Key metrics tracked
- [ ] Grafana dashboard with core panels available in dev

---

## A4. Queue-Backed Audit Pipeline

**Priority:** P1 (High)
**Time Estimate:** 4-6 hours
**Depends On:** A2 (Database)

### What to Add

- Outbox table for audit events
- Worker to publish outbox entries → Kafka
- Consumer to materialize Kafka events → audit_events
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

See `../prd/README.md` for Phase 2 scope and acceptance criteria:

## B1. Rate Limiting & Abuse Prevention (PRD-017, Phase 0)

**Time:** 8-10 hours

- Sliding window limits per IP/user/client_id
- Global throttling, allowlist, and Retry-After headers
- Audit events and load-test verification

## B2. API Versioning & Lifecycle (PRD-019)

**Time:** 3-4 hours

- URL-based versioning with deprecation headers
- Sunset/deprecation policy and documentation

## B3. Operational Readiness & SRE (PRD-020)

**Time:** 8-12 hours

- Health checks, backups, DR plan, and runbooks
- SLOs and operational dashboards

## B4. Performance Optimization (PRD-028)

**Time:** 4-6 hours

- Auth/token hot path optimizations
- Cache and pooling strategy

## B5. User Data Rights (PRD-007)

**Time:** 4-6 hours

- GDPR export and deletion workflows
- Audit coverage for data rights actions

---

# Track C: Advanced/Showcase Features (DIFFERENTIATOR)

These features make the project stand out from "basic auth gateways". Pick 2-3 based on target audience and deployment needs.

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
- Clear differentiator

### Value Highlight

Built cryptographically verifiable audit system using Merkle trees for tamper-proof logging in identity verification gateway.

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

- Practical and relevant to EU regulatory environments
- Shows understanding of real-world constraints
- Builds on existing audit/data rights work

### Value Highlight

Implemented automated GDPR/CCPA compliance engine with real-time policy enforcement and data retention management.

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

---

## C8. Consent-as-a-Service Platform

**PRD:** PRD-029
**Priority:** P2 (Strategic)
**Time Estimate:** 12-16 hours
**Depends On:** PRD-002 (Consent), PRD-018 (Notifications)

### What It Adds

- **Multi-tenant consent delegation** where third-party apps integrate with Credo as their consent hub
- Unified user consent dashboard across all connected services
- Cross-service consent revocation with webhook notifications
- GDPR Article 7 compliance-as-a-service

### Why Strategic

- No competitor offers consent-as-a-service
- Positions Credo as a consent hub, not just an identity provider
- Enterprise value for platforms managing multiple applications

---

## C9. Portable Trust Score

**PRD:** PRD-030
**Priority:** P2 (Strategic)
**Time Estimate:** 14-18 hours
**Depends On:** PRD-004 (VCs), PRD-005 (Decision), PRD-010 (ZKP)

### What It Adds

- **Privacy-preserving reputation score** that travels with users
- Trust score components: verification level, credential count, account age, attestations
- ZKP-provable score (prove score > threshold without revealing inputs)
- Cross-service score sharing via verifiable credentials
- Score decay over time for freshness

### Why Strategic

- Enables "prove once, trust everywhere" across services
- Reduces verification costs for low-risk operations
- No competitor offers ZKP-based portable trust scores

---

## C10. Compliance-as-Code Templates

**PRD:** PRD-031
**Priority:** P2 (Strategic - Early Start)
**Time Estimate:** 10-14 hours
**Depends On:** PRD-002 (Consent), PRD-006 (Audit), PRD-007 (Data Rights)

### What It Adds

- **Pre-built compliance templates** for GDPR, CCPA, HIPAA, PCI-DSS, SOC2
- One-click compliance setup for new tenants
- Template composition (e.g., GDPR + PCI for EU fintech)
- Compliance status endpoint showing current configuration
- YAML-based template definitions for customization

### Why Strategic

- Immediate enterprise value (can start after Phase 2)
- Reduces compliance setup from weeks to minutes
- Differentiates from Auth0/Okta which lack compliance templates

---

## C11. Privacy-Preserving Analytics

**PRD:** PRD-032
**Priority:** P2 (Strategic)
**Time Estimate:** 16-20 hours
**Depends On:** PRD-006 (Audit), PRD-010 (ZKP)

### What It Adds

- **Differential privacy** for aggregate analytics queries
- Privacy budget management limiting total information disclosure
- Query audit trail showing who asked what
- User transparency (what queries touched my data)
- Suppression of small groups to prevent re-identification

### Why Strategic

- Enables business insights without PII access
- GDPR Article 25 data protection by design
- No competitor offers privacy-preserving analytics for identity data

---

## C12. Federated Trust Network

**PRD:** PRD-033
**Priority:** P3 (Strategic - Most Advanced)
**Time Estimate:** 18-24 hours
**Depends On:** PRD-004 (VCs), PRD-009 (DIDs), PRD-010 (ZKP)

### What It Adds

- **Web of trust** where verified users vouch for others
- ZKP vouches that prove relationship without revealing identity
- Weighted trust scoring based on voucher reputation
- Conditional verification (N vouches = verified for purpose X)
- Fraud prevention: circular vouching detection, velocity limits

### Why Strategic

- Reduces verification costs using social trust
- Solves cold start problem for new users
- Creates network effects and user stickiness

---

## C13. Assurance Pack (Biometrics, Fraud, Residency, Adaptive Auth)

**PRDs:** PRD-013, PRD-023, PRD-024, PRD-027
**Priority:** P1 (Regulated Industries)
**Time Estimate:** 34-50 hours
**Depends On:** PRD-001, PRD-003, PRD-005, PRD-006

### What It Adds

- Biometric verification and liveness checks
- Fraud detection and security intelligence signals
- Data residency controls and cross-border logging
- Risk-based adaptive authentication

---

## C14. Banking Identity Pack

**PRDs:** PRD-039, PRD-035, PRD-036, PRD-037, PRD-038
**Priority:** P1 (Fintech/Banking)
**Time Estimate:** 68-88 hours
**Depends On:** PRD-001, PRD-021, PRD-018

### What It Adds

- SCA orchestration and step-up flows
- Identity assurance levels and legal entity modeling
- Multi-party approvals and delegated authority

---

# Implementation Timeline

## Phase 0-2: MVP (9-12 days)

- Phase 0 (4-5 days): PRD-001, PRD-001B, PRD-016, PRD-026A, PRD-017, PRD-002
- Phase 1 (3-4 days): PRD-003, PRD-004, PRD-005, PRD-006
- Phase 2 (2.5-3.5 days): PRD-019, PRD-020, PRD-028 (Performance Optimization), PRD-007

**Deliverable:** MVP complete (core identity flow + operational baseline)

## Phase 3: Production Hardening (6-8 days)

- PRD-018, PRD-021, PRD-022, PRD-015, PRD-005B, PRD-028 (Security Enhancements)
- TR-6 consent projections (defer if needed)

**Deliverable:** Production baseline

## Phases 4-8: Advanced Packs (29-57 days)

- Phase 4 (7.5-10.5 days): PRD-013, PRD-023, PRD-006B, PRD-007B, PRD-008, PRD-024, PRD-027
- Phase 5 (6-7 days): PRD-004B, PRD-009, PRD-010
- Phase 6 (6-8 days): PRD-011, PRD-012, PRD-014, PRD-025, PRD-026
- Phase 7 (9-12 days): PRD-029, PRD-030, PRD-031, PRD-032, PRD-033
- Phase 8 (8.5-11 days): PRD-039, PRD-035, PRD-036, PRD-037, PRD-038

**Deliverable:** Full platform and banking identity packs

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

- [ ] Notifications, MFA, and account recovery flows live (PRD-018/021/022)
- [ ] Policy engines integrated and audited (PRD-015/005B)
- [ ] Security enhancements applied (PRD-028 Security Enhancements)
- [ ] Consent projection/TR-6 implemented or explicitly deferred
- [ ] Phase 0-2 prerequisites complete

## Operationally Mature (Track B Complete)

- [ ] API versioning and deprecation headers (PRD-019)
- [ ] Operational readiness: health checks, backups, DR, runbooks (PRD-020)
- [ ] Performance optimizations validated (PRD-028 Performance)
- [ ] GDPR data rights workflows complete (PRD-007)
- [ ] Rate limiting & abuse prevention verified (PRD-017)

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
❌ Consumer-facing account management portal
❌ Mobile SDK (server-side focus)

**Reason:** Focus on distinctive identity verification features, not generic auth features.

---

# System Evolution Phases

> _Merged from SYSTEM_DESIGN_ROADMAP.md_

This section describes how Credo will evolve from a secure, correct core into a fully articulated system-design showcase. Each phase highlights specific engineering principles: scalability, resilience, performance, observability, and operational clarity.

## Phase 1: Core Gateway (Security and Correctness)

See main [Architecture document](../engineering/architecture.md)

## Phase 2: Modular Service Boundaries

The next step introduces internal decomposition. Identity systems grow easier to reason about when concerns are separated.

### Planned Components

- **auth-service**: login, consent, code issuance
- **token-service**: exchange, introspection, refresh
- **session-store**: sessions, device binding
- **audit-log-service**: append-only security events

### Design Focus

- Clearly documented internal APIs (OpenAPI)
- Sync vs async communication choices
- Start using a lightweight event bus for audit and session-change events

This phase demonstrates boundary design, blast radius control, and the rationale behind dividing services.

## Phase 3: High-Load Read Path and Caching Strategy

Token verification and session introspection are the highest-volume operations for an ID gateway. This phase showcases performance reasoning.

### Additions

- Fast introspection endpoint
- Local in-memory caching for token and session reads
- Optional distributed cache (Redis) for shared state

### Tradeoffs to Document

- Latency vs correctness
- Cache invalidation strategies
- Memory footprint vs throughput
- Handling partial failures (cache miss storms, Redis failover)

## Phase 4: Storage Architecture and Consistency Model

Identity systems mix durable identity data with ephemeral authorization data.

### Storage Model

- **Postgres**: identity records requiring strong consistency
- **Redis**: volatile, high-throughput token/session state

### Design Notes

- Schema design and migrations
- Rationale for separating durable vs ephemeral storage
- Failure-mode analysis: what happens when Redis fails, or Postgres fails over
- Consistency guarantees and where they matter

## Phase 5: Containerization and Multi-Service Runtime

At this point, the gateway splits into multiple running services.

### Deliverables

- Docker Compose environment running all components
- Health and readiness checks
- Reverse proxy or API gateway layer for routing and rate limiting

### Design Topics

- Readiness vs liveness semantics
- Graceful shutdown and in-flight request handling
- Local dev parity with future Kubernetes deployments

## Phase 6: Kubernetes + Terraform

The system moves into a realistic orchestration model.

### Kubernetes Additions

- Deployments and Services per component
- Ingress controller for routing
- HPA configuration with reasoning (CPU, RPS, token ops)
- StatefulSet for Postgres
- Secret management strategy (sealed-secrets or external-secrets)

### Terraform

- Infrastructure as code for cluster, network, storage and IAM primitives
- Modular structure reflecting cloud-native design

## Phase 7: Observability and Reliability Engineering

An identity service must be observable and measurable.

### Additions

- Prometheus metrics (auth success rate, latency distribution, token refresh behaviour)
- Structured logs with correlation IDs
- Defined SLOs and error budgets
- Simple chaos experiments (kill a pod, observe recovery)
- SLO/SLI dashboards and alerting for production readiness

## Phase 8: Final Architectural Narrative

The project concludes with a formal system design document for architecture reviews and stakeholder communication.

### Document Sections

- Architecture overview and key decision rationale
- Scaling model and capacity estimate
- Caching and consistency analysis
- Failure modes and mitigations
- Security model and threat analysis
- Testing strategy (BDD, contract tests, attack-path demos)
- Deployment evolution from local to k8s
- Extension roadmap (OIDC federation, MFA, device identity)

---

# Module Adoption Guide

> _Merged from MODULE_BUNDLES.md_

This section explains how to consume the platform as composable modules while keeping a cohesive identity/evidence core.

## Core Identity Plane (MVP)

**Phase 0-2: Foundation → Operational Baseline**

- PRD-001: Authentication & Session Management
- PRD-001B: Admin - User Deletion
- PRD-016: Token Lifecycle & Revocation
- PRD-026A: Tenant & Client Management (MVP)
- PRD-017: Rate Limiting & Abuse Prevention
- PRD-002: Consent Management
- PRD-003: Registry Integration (evidence orchestrator, provider chains)
- PRD-004: Verifiable Credentials issuance/validation
- PRD-005: Decision Engine
- PRD-006: Audit & Compliance Baseline
- PRD-019: API Versioning & Lifecycle Management
- PRD-020: Operational Readiness & SRE
- PRD-028: Performance Optimization
- PRD-007: User Data Rights (GDPR)

**Use when:** You need the foundational identity workflow end-to-end.

## Infrastructure Layer (Production Prerequisites)

**Phase 0-3: Operational readiness and security**

- PRD-018: Notification Service (Email/SMS/Webhooks)
- PRD-019: API Versioning & Lifecycle Management
- PRD-020: Operational Readiness & SRE
- PRD-021: Multi-Factor Authentication
- PRD-022: Account Recovery & Credential Management
- PRD-015: Credo Policy Engine (Internal PDP)
- PRD-005B: Cerbos Authorization (External PDP)
- PRD-028: Security Enhancements

**Use when:** Deploying to production, need operational maturity and security hardening.

## Assurance Pack (Risk & Compliance)

**Phase 4: Regulated industries, high-assurance requirements**

- PRD-013: Biometric Verification
- PRD-023: Fraud Detection & Security Intelligence
- PRD-006B: Cryptographic Audit (Merkle trees)
- PRD-007B: ML Risk Scoring
- PRD-008: GDPR/CCPA Automation
- PRD-024: Data Residency & Sovereignty
- PRD-027: Risk Based Adaptive Authentication

**Use when:** You need higher assurance, fraud/risk scoring, and automated compliance.

## Decentralized Identity Pack

**Phase 5: Web3, privacy-preserving identity**

- PRD-004B: Enhanced VCs (BBS+, Status List)
- PRD-009: Decentralized Identifiers (DIDs)
- PRD-010: Zero-Knowledge Proofs

**Use when:** Your trust model requires DIDs/ZKPs or privacy-preserving proofs.

## Integrations & Developer Experience Pack

**Phase 6: Ecosystem, partner integrations, operations UI**

- PRD-011: Internal TCP Event Ingester
- PRD-012: Cloud Connectors / Audit & Identity Event Export
- PRD-014: Client SDKs & Platform Integration
- PRD-025: Developer Sandbox & Testing
- PRD-026: Admin Dashboard & Operations UI

**Use when:** Building partner ecosystem, improving developer experience, or need operations tooling.

## Differentiation Pack (Strategic)

**Phase 7: Unique market differentiators**

- PRD-029: Consent-as-a-Service (multi-tenant consent delegation)
- PRD-030: Portable Trust Score (ZKP-provable reputation)
- PRD-031: Compliance-as-Code Templates (GDPR/CCPA/HIPAA/PCI presets)
- PRD-032: Privacy-Preserving Analytics (differential privacy)
- PRD-033: Federated Trust Network (web of trust with ZKP vouching)

**Use when:** Differentiating from Auth0/Okta/Keycloak with unique capabilities no competitor offers.

**Early Start Options:**

- PRD-029 and PRD-031 can start after Phase 2 (no ZKP dependency)
- PRD-030, PRD-032, PRD-033 require Phase 5 ZKP foundation

## Banking Identity Pack (Fintech/Banking)

**Phase 8: Banking identity capabilities**

- PRD-039: SCA Orchestration (PSD2)
- PRD-035: Identity Assurance Levels
- PRD-036: Legal Entity Identity & Representation
- PRD-037: Multi-Party Authorization
- PRD-038: Delegated Authority

**Use when:** Targeting fintech/banking identity gateway requirements.

## Adoption Timeline

| Milestone                 | Timeline   | PRDs                                        |
| ------------------------- | ---------- | ------------------------------------------- |
| Minimal Viable Product    | 9-12 days  | Phases 0-2 (Core Identity Plane)            |
| Production Baseline       | 15-20 days | + Phase 3 (Infrastructure Layer)            |
| Regulated Ready           | 23-30 days | + Phase 4 (Assurance Pack)                  |
| Full Platform             | 35-46 days | + Phases 5-6 (Decentralized + Integrations) |
| Strategic Differentiation | 44-58 days | + Phase 7 (Differentiation Pack)            |
| Banking Identity          | 52-69 days | + Phase 8 (Banking Identity Pack)           |

---

# Revision History

| Version | Date       | Author       | Changes                                                                                                                                          |
| ------- | ---------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1.0     | 2025-12-03 | Product Team | Initial V2 Roadmap                                                                                                                               |
| 2.0     | 2025-12-06 | Product Team | Reorganized into tracks, added advanced features (DIDs, ZK, ML, GDPR)                                                                            |
| 3.0     | 2025-12-17 | Engineering  | Consolidated: merged SYSTEM_DESIGN_ROADMAP.md and MODULE_BUNDLES.md                                                                              |
| 3.1     | 2025-12-17 | Engineering  | Added Phase 7 Differentiation Pack (C8-C12): Consent-as-a-Service, Trust Score, Compliance Templates, Privacy Analytics, Federated Trust Network |
| 3.2     | 2025-12-23 | Engineering  | Aligned roadmap with Phase 0-8 PRDs, added Banking Identity pack, refreshed timelines                                                            |
