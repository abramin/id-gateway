# Product Requirements Documents (PRDs)

**Credo Implementation Specifications**
**Version:** 2.5
**Last Updated:** 2025-12-23

This directory contains technical product requirements for implementing Credo system. Each PRD is written for developers and provides detailed specifications, API contracts, data models, and acceptance criteria.

---

## Overview

Credo is a **regulated identity and authorization system** that:

- Authenticates users (OIDC-lite) with MFA and token lifecycle management
- Manages purpose-based consent with CQRS read models
- Integrates with external registries (citizen data, sanctions)
- Issues verifiable credentials (standard + enhanced with BBS+)
- Makes authorization decisions based on evidence with pluggable policy engines
- Maintains comprehensive audit trails with cryptographic verification
- Supports GDPR data rights (export, deletion, data residency)
- Provides fraud detection, biometric verification, and ML risk scoring
- Enables decentralized identity (DIDs, ZK proofs)
- Offers developer-friendly integrations (SDKs, webhooks, sandbox)
- Validates API contracts with godog-based E2E feature tests in `e2e/`

---

## PRD Index

### Phase 0: Foundation (MVP Prerequisites) - P0 Critical

| PRD                                                       | Feature                             | Status         | Est. Time | Dependencies |
| --------------------------------------------------------- | ----------------------------------- | -------------- | --------- | ------------ |
| [PRD-001](./PRD-001-Authentication-Session-Management.md) | Authentication & Session Management | 🟢 Done        | 13-14h    | None         |
| [PRD-001B](./PRD-001B-Admin-User-Deletion.md)             | Admin - User Deletion               | 🟢 Done        | 1h        | PRD-001      |
| [PRD-016](./PRD-016-Token-Lifecycle-Revocation.md) 🆕     | Token Lifecycle & Revocation        | ⚠️ Mostly Done | 6-8h      | PRD-001      |
| [PRD-026A](./PRD-026A-Tenant-Client-Management.md) 🆕     | Tenant & Client Management (MVP)    | 🟢 Done        | 8-10h     | PRD-001, 016 |
| [PRD-026B](./PRD-026B-Tenant-Client-Lifecycle.md) 🆕      | Tenant & Client Lifecycle           | 🔵 Not Started | 2-3h      | PRD-026A     |
| [PRD-017](./PRD-017-Rate-Limiting-Abuse-Prevention.md) 🆕 | Rate Limiting & Abuse Prevention    | ⚠️ Mostly Done | 8-10h     | PRD-001, 016 |
| [PRD-002](./PRD-002-Consent-Management.md)                | Consent Management System           | 🟢 Done        | 5-7h      | PRD-001      |

**Phase 0 Total:** ~34-42 hours (4-5 days)

---

### Phase 1: Core Identity Plane (MVP Core) - P0 Critical

| PRD                                            | Feature                     | Status         | Est. Time | Dependencies |
| ---------------------------------------------- | --------------------------- | -------------- | --------- | ------------ |
| [PRD-003](./PRD-003-Registry-Integration.md)   | Registry Integration        | 🔵 Not Started | 7-9h      | PRD-001, 002 |
| [PRD-004](./PRD-004-Verifiable-Credentials.md) | Verifiable Credentials      | 🔵 Not Started | 6-8h      | PRD-001, 003 |
| [PRD-005](./PRD-005-Decision-Engine.md)        | Decision Engine             | 🔵 Not Started | 5-7h      | PRD-001-004  |
| [PRD-006](./PRD-006-Audit-Compliance.md)       | Audit & Compliance Baseline | 🔵 Not Started | 8-10h     | PRD-001-005  |

**Phase 1 Total:** ~26-34 hours (3-4 days)

---

### Phase 2: Operational Baseline (Production Prerequisites) - P0 Critical

| PRD                                                  | Feature                             | Status         | Est. Time | Dependencies |
| ---------------------------------------------------- | ----------------------------------- | -------------- | --------- | ------------ |
| [PRD-019](./PRD-019-API-Versioning-Lifecycle.md) 🆕  | API Versioning & Lifecycle          | 🔵 Not Started | 3-4h      | None         |
| [PRD-020](./PRD-020-Operational-Readiness-SRE.md) 🆕 | Operational Readiness & SRE         | 🔵 Not Started | 8-12h     | PRD-006      |
| [PRD-028](./PRD-028-Performance-Optimization.md) 🆕  | Auth/Token Performance Enhancements | 🔵 Not Started | 4-6h      | PRD-001, 016 |
| [PRD-007](./PRD-007-User-Data-Rights.md)             | User Data Rights (GDPR)             | 🔵 Not Started | 4-6h      | PRD-001-006  |

**Phase 2 Total:** ~19-28 hours (2.5-3.5 days)

**🎉 MVP COMPLETE: ~73-95 hours (9-12 days)**

---

### Phase 3: Production Hardening (Beta Ready) - P0-P1

| PRD                                                     | Feature                                   | Status         | Est. Time | Dependencies           |
| ------------------------------------------------------- | ----------------------------------------- | -------------- | --------- | ---------------------- |
| [PRD-018](./PRD-018-Notification-Service.md) 🆕         | Notification Service (Email/SMS/Webhooks) | 🔵 Not Started | 10-14h    | PRD-001, 002           |
| [PRD-021](./PRD-021-Multi-Factor-Authentication.md) 🆕  | Multi-Factor Authentication               | 🔵 Not Started | 10-14h    | PRD-001, 016, 018      |
| [PRD-022](./PRD-022-Account-Recovery-Credentials.md) 🆕 | Account Recovery & Credentials            | 🔵 Not Started | 6-8h      | PRD-001, 018           |
| [PRD-015](./PRD-015-Credo-Policy-Engine.md)             | Credo Policy Engine (Internal PDP)        | 🔵 Not Started | 16-20h    | PRD-005                |
| [PRD-005B](./PRD-005B-Cerbos-Authorization.md)          | Cerbos Authorization (External PDP)       | 🔵 Not Started | 6-8h      | PRD-005                |
| [PRD-028](./PRD-028-Security-Enhancements.md) 🆕        | Security Enhancements (Completed Core)    | 🔵 Not Started | 4-6h      | 1, 1B, 2, 16, 26A      |
| ↳ TR-6 (Projections)                                    | Consent projection/read-model perf        | ⏩ Defer       | 6-8h      | PRD-002, A2 (Postgres) |

**Phase 3 Total:** ~48-64 hours (6-8 days)

**🚀 PRODUCTION BASELINE COMPLETE: ~121-159 hours (15-20 days)**

---

### Phase 4: Assurance Pack (Regulated Industries) - P1

| PRD                                                              | Feature                                 | Status         | Est. Time | Dependencies |
| ---------------------------------------------------------------- | --------------------------------------- | -------------- | --------- | ------------ |
| [PRD-013](./PRD-013-Biometric-Verification.md)                   | Biometric Verification                  | 🔵 Not Started | 8-12h     | PRD-001, 003 |
| [PRD-023](./PRD-023-Fraud-Detection-Security-Intelligence.md) 🆕 | Fraud Detection & Security Intelligence | 🔵 Not Started | 10-14h    | PRD-001, 005 |
| [PRD-006B](./PRD-006B-Cryptographic-Audit.md)                    | Cryptographic Audit (Merkle Trees)      | 🔵 Not Started | 8-12h     | PRD-006      |
| [PRD-007B](./PRD-007B-ML-Risk-Scoring.md)                        | ML-Based Risk Scoring                   | 🔵 Not Started | 14-18h    | PRD-005, 006 |
| [PRD-008](./PRD-008-GDPR-CCPA-Automation.md)                     | GDPR/CCPA Automation                    | 🔵 Not Started | 12-16h    | PRD-006, 007 |
| [PRD-024](./PRD-024-Data-Residency-Sovereignty.md) 🆕            | Data Residency & Sovereignty            | 🔵 Not Started | 8-12h     | PRD-001, 006 |
| [PRD-024](./PRD-027-Risk-Based-Adaptive-Authentication.md) 🆕    | Risk Based Adaptive Authentication      | 🔵 Not Started | 8-12h     | PRD-001, 006 |

**Phase 4 Total:** ~60-84 hours (7.5-10.5 days)

---

### Phase 5: Decentralized Pack (Web3 & Privacy) - P2-P3

| PRD                                                       | Feature                          | Status         | Est. Time | Dependencies |
| --------------------------------------------------------- | -------------------------------- | -------------- | --------- | ------------ |
| [PRD-004B](./PRD-004B-Enhanced-Verifiable-Credentials.md) | Enhanced VCs (BBS+, Status List) | 🔵 Not Started | 10-14h    | PRD-004      |
| [PRD-009](./PRD-009-Decentralized-Identity-DIDs.md)       | Decentralized Identity (DIDs)    | 🔵 Not Started | 16-20h    | PRD-001, 004 |
| [PRD-010](./PRD-010-Zero-Knowledge-Proofs.md)             | Zero-Knowledge Proofs            | 🔵 Not Started | 20-24h    | PRD-004, 005 |

**Phase 5 Total:** ~46-58 hours (6-7 days)

---

### Phase 6: Integrations Pack (Ecosystem & DX) - P1-P2

| PRD                                                                        | Feature                            | Status         | Est. Time | Dependencies |
| -------------------------------------------------------------------------- | ---------------------------------- | -------------- | --------- | ------------ |
| [PRD-011](./PRD-011-Internal-TCP-Event-Ingester.md)                        | Internal TCP Event Ingester        | 🔵 Not Started | 8-12h     | PRD-006      |
| [PRD-012](./PRD-012-Cloud-Connectors-Credo-Audit-Identity-Event-Export.md) | Cloud Connectors & Webhooks        | 🔵 Not Started | 10-14h    | PRD-006, 011 |
| [PRD-014](./PRD-014-Client-SDKs-Platform-Integration.md)                   | Client SDKs & Platform Integration | 🔵 Not Started | 10-14h    | PRD-001-005  |
| [PRD-025](./PRD-025-Developer-Sandbox-Testing.md) 🆕                       | Developer Sandbox & Testing        | 🔵 Not Started | 6-8h      | PRD-001-005  |
| [PRD-026](./PRD-026-Admin-Dashboard-Operations-UI.md) 🆕                   | Admin Dashboard & Operations UI    | 🔵 Not Started | 12-16h    | PRD-001-007  |

**Phase 6 Total:** ~46-64 hours (6-8 days)

---

### Phase 7: Differentiation Pack (Strategic) - P2-P3

| PRD                                                | Feature                      | Status         | Est. Time | Dependencies      |
| -------------------------------------------------- | ---------------------------- | -------------- | --------- | ----------------- |
| [PRD-029](./PRD-029-Consent-as-a-Service.md) 🆕    | Consent-as-a-Service         | 🔵 Not Started | 12-16h    | PRD-002, 018      |
| [PRD-030](./PRD-030-Portable-Trust-Score.md) 🆕    | Portable Trust Score         | 🔵 Not Started | 14-18h    | PRD-004, 005, 010 |
| [PRD-031](./PRD-031-Compliance-Templates.md) 🆕    | Compliance-as-Code Templates | 🔵 Not Started | 10-14h    | PRD-002, 006, 007 |
| [PRD-032](./PRD-032-Privacy-Analytics.md) 🆕       | Privacy-Preserving Analytics | 🔵 Not Started | 16-20h    | PRD-006, 010      |
| [PRD-033](./PRD-033-Federated-Trust-Network.md) 🆕 | Federated Trust Network      | 🔵 Not Started | 18-24h    | PRD-004, 009, 010 |

**Phase 7 Total:** ~70-92 hours (9-12 days)

> **Note:** PRD-029 and PRD-031 can start after Phase 2 (no ZKP dependency). PRD-030, 032, 033 require Phase 5 completion.

---

### Phase 8: Banking Identity Pack (Fintech/Banking) - P1

| PRD                                                         | Feature                              | Status         | Est. Time | Dependencies          |
| ----------------------------------------------------------- | ------------------------------------ | -------------- | --------- | --------------------- |
| [PRD-039](./PRD-039-SCA-Orchestration.md) 🆕                | SCA Orchestration (PSD2)             | 🔵 Not Started | 14-18h    | PRD-001, 021, 018     |
| [PRD-035](./PRD-035-Identity-Assurance-Levels.md) 🆕        | Identity Assurance Levels            | 🔵 Not Started | 10-14h    | PRD-004, 003          |
| [PRD-036](./PRD-036-Legal-Entity-Identity.md) 🆕            | Legal Entity Identity & Representation| 🔵 Not Started | 14-18h    | PRD-026A, 035         |
| [PRD-037](./PRD-037-Multi-Party-Authorization.md) 🆕        | Multi-Party Authorization            | 🔵 Not Started | 18-22h    | PRD-036, 021, 039     |
| [PRD-038](./PRD-038-Delegated-Authority.md) 🆕              | Delegated Authority (Power of Attorney)| 🔵 Not Started | 12-16h   | PRD-036, 037          |

**Phase 8 Total:** ~68-88 hours (8.5-11 days)

> **Note:** Phase 8 is designed for fintech/banking use cases. PRD-039 (SCA) is the foundation and can start after Phase 3. Other PRDs build on it progressively. This pack enables Credo to serve as an identity gateway for business banking platforms like Qonto.

---

## Timeline Summary

| Phase | Description     | PRDs                  | Time   | Cumulative   | Milestone             |
| ----- | --------------- | --------------------- | ------ | ------------ | --------------------- |
| 0     | Foundation      | 1, 16, 17, 2          | 32-39h | 32-39h       | Auth + Security       |
| 1     | Core Identity   | 3, 4, 5, 6            | 26-34h | 58-73h       | Full Identity Flow    |
| 2     | Operational     | 19, 20, 28, 7         | 19-28h | **77-101h**  | **MVP** ✅            |
| 3     | Hardening       | 18, 21, 22, 15, 5B    | 48-64h | **125-165h** | **Production** 🚀     |
| 4     | Assurance       | 13, 23, 6B, 7B, 8, 24 | 60-84h | 185-249h     | Regulated Ready       |
| 5     | Decentralized   | 4B, 9, 10             | 46-58h | 231-307h     | Web3 Features         |
| 6     | Integrations    | 11, 12, 14, 25, 26    | 46-64h | 277-371h     | Full Platform         |
| 7     | Differentiation | 29, 30, 31, 32, 33    | 70-92h | 347-463h     | Strategic Edge        |
| 8     | Banking Identity| 35, 36, 37, 38, 39    | 68-88h | **415-551h** | **Banking Gateway** 🏦|

**Total System Time:** ~415-551 hours (52-69 days)

---

## Strategic Implementation Approach

### Phases 0-2: MVP Path (9-12 days)

**Goal:** Production-ready core identity system with operational prerequisites

**Phase 0: Foundation (4-5 days)**
Establish authentication, token management, security controls, and consent (projections deferred to later perf phase):

- PRD-001: Full authentication flow (login, sessions, OIDC-lite)
- PRD-016: Token refresh, revocation, session management
- PRD-017: Rate limiting with sliding window algorithm (DDoS protection)
- PRD-002: Consent management with CQRS read models

**Phase 1: Core Identity Plane (3-4 days)**
Build identity issuance and decision capabilities:

- PRD-003: Citizen + sanctions registry integration
- PRD-004: Verifiable credential issuance (standard VCs)
- PRD-005: Evidence-based decision engine with Redis caching
- PRD-006: Audit logging with event streaming (outbox pattern)

**Phase 2: Operational Baseline (2.5-3.5 days)**
Production operational requirements and performance hardening:

- PRD-019: API versioning (/v1/, deprecation headers)
- PRD-020: Health checks, backup/DR, SLAs, runbooks
- PRD-028: Auth/token performance optimizations (caches, sweepers, pooling)
- PRD-007: GDPR data export/deletion

**MVP Deliverables:**

- Authenticate users, issue credentials, make decisions, log everything
- Token lifecycle with refresh/revoke
- Rate limiting protecting all endpoints
- Operational health checks and monitoring
- GDPR-compliant data rights

---

### Phase 3: Production Hardening (6-8 days)

**Goal:** Beta-ready system with security hardening and policy engine

Add production security and notifications:

- PRD-018: Notification service (email/SMS via SendGrid/Twilio, webhooks with HMAC)
- PRD-021: Multi-factor authentication (TOTP, SMS/Email OTP, backup codes)
- PRD-022: Account recovery (password reset, account unlock, email verification)
- PRD-015: Credo Policy Engine (internal PDP with Rego evaluation)
- PRD-005B: Cerbos Authorization (external PDP integration)

**Production Baseline Deliverables:**

- Complete authentication with MFA and account recovery flows
- Notification infrastructure for user communications
- Dual policy engines (internal + external) for flexible authorization
- Ready for regulated beta deployment

---

### Phases 4-7: Advanced Features (29-40 days)

**Phase 4: Assurance Pack (7.5-10.5 days)**
Regulated industry requirements:

- PRD-013: Biometric verification (face matching, liveness detection)
- PRD-023: Fraud detection (impossible travel, velocity checks, device fingerprinting)
- PRD-006B: Cryptographic audit (Merkle trees for tamper-proof logs)
- PRD-007B: ML risk scoring (anomaly detection, adaptive scoring)
- PRD-008: GDPR/CCPA automation (retention policies, breach detection)
- PRD-024: Data residency (regional stores, cross-border transfer logging)

**Phase 5: Decentralized Pack (6-7 days)**
Web3 and privacy-preserving features:

- PRD-004B: Enhanced VCs (BBS+ signatures, status lists, selective disclosure)
- PRD-009: DIDs (W3C standard, did:key, did:web methods)
- PRD-010: Zero-knowledge proofs (age verification, credential proofs without disclosure)

**Phase 6: Integrations Pack (6-8 days)**
Ecosystem and developer experience:

- PRD-011: TCP event ingester (internal message bus for high-volume events)
- PRD-012: Cloud connectors (AWS/Azure/GCP webhook export)
- PRD-014: Client SDKs (TypeScript/React, Python, Go SDKs)
- PRD-025: Developer sandbox (test environment, mock data, API explorer)
- PRD-026: Admin dashboard (operations UI for user/session/consent management)

**Phase 7: Differentiation Pack (9-12 days)**
Strategic differentiation features that set Credo apart from competitors:

- PRD-029: Consent-as-a-Service (multi-tenant consent delegation, unified dashboard)
- PRD-030: Portable Trust Score (ZKP-provable reputation, cross-service sharing)
- PRD-031: Compliance-as-Code Templates (GDPR, CCPA, HIPAA, PCI-DSS presets)
- PRD-032: Privacy-Preserving Analytics (differential privacy, aggregate insights without PII)
- PRD-033: Federated Trust Network (peer vouching, web of trust with ZKP)

---

## Storage Evolution Philosophy

### In-Memory First, Production Storage Later

The codebase intentionally uses **in-memory stores** through Phases 0-1, introducing PostgreSQL and Redis only at Phase 2 (Operational Baseline). This design:

- Keeps development fast (no external dependencies during initial development)
- Makes tests deterministic and quick
- Uses interfaces throughout, so swapping `inmemory.Store` to `postgres.Store` is DI wiring only
- Defers infrastructure complexity until functionality is proven

### Transition Triggers

| When you need... | Introduce... | Phase |
|------------------|--------------|-------|
| Multi-instance deployment | Redis (rate limiting, sessions) | Phase 2 |
| Data durability | PostgreSQL (users, consents, audit) | Phase 2 |
| Backup/DR capabilities | PostgreSQL | Phase 2 |
| GDPR compliance | PostgreSQL (data export requires persistence) | Phase 2 |

See [PRD-020: Storage Infrastructure Transition](./PRD-020-Operational-Readiness-SRE.md#1b-storage-infrastructure-transition) for detailed guidance and decision matrix.

---

## Implementation Order Rationale

### Dependency-Driven Sequencing

**Phase 0-2 (MVP):** Focus on vertical slice through core identity flow

- Authentication → Token management → Rate limiting → Consent establishes security baseline
- Registry → Credentials → Decision → Audit completes identity issuance
- Operational readiness (health checks, versioning, GDPR) enables production deployment

**Phase 3 (Production Hardening):** Add essential production security

- Notifications (PRD-018) must come before MFA (PRD-021) which needs SMS/Email
- Account recovery (PRD-022) requires notification service
- Policy engines (PRD-015, 005B) build on Decision Engine (PRD-005) completed in Phase 1

**Phase 4-6 (Advanced):** Specialized capabilities with optional adoption

- Assurance Pack targets regulated industries (finance, healthcare)
- Decentralized Pack targets Web3 and privacy-focused applications
- Integrations Pack provides ecosystem connectivity and developer experience

**Phase 7 (Differentiation):** Unique market positioning

- Consent-as-a-Service and Compliance Templates can start after Phase 2 (no ZKP dependency)
- Trust Score, Privacy Analytics, and Trust Network require Phase 5's ZKP foundation
- These features differentiate Credo from Auth0/Okta/Keycloak

**Phase 8 (Banking Identity):** Fintech/Banking-specific features (8.5-11 days)

- SCA Orchestration (PRD-039) is the PSD2-compliant step-up auth foundation
- Identity Assurance Levels (PRD-035) enables tiered KYC for transaction limits
- Legal Entity Identity (PRD-036) models companies, directors, and signatories
- Multi-Party Authorization (PRD-037) implements maker-checker and M-of-N approvals
- Delegated Authority (PRD-038) enables vacation coverage and power-of-attorney patterns
- These features position Credo as an identity gateway for business banking (Qonto-style)

### Module Bundle Alignment

Module bundles organize PRDs by deployment scenario:

- **Core Identity Plane:** Phases 0-2 (MVP)
- **Infrastructure Layer:** Phases 0-3 (operational + security)
- **Assurance Pack:** Phase 4 (regulated industries)
- **Decentralized Pack:** Phase 5 (Web3)
- **Integrations Pack:** Phase 6 (ecosystem)
- **Differentiation Pack:** Phase 7 (strategic positioning)
- **Banking Identity Pack:** Phase 8 (fintech/banking)

See [ROADMAP.md](../ROADMAP.md#module-adoption-guide) for detailed bundle compositions.

---

## Adoption Guidance

### For Startups (9-12 days → MVP)

Implement Phases 0-2:

- Core authentication with MFA support via PRD-016 token lifecycle
- Rate limiting prevents abuse from day one
- Basic consent and audit for compliance
- Operational health checks enable monitoring

**Skip:** Advanced features (Phases 4-6) until product-market fit

### For Regulated Industries (15-20 days → Production Baseline)

Implement Phases 0-3, then add Phase 4 Assurance Pack:

- Full production hardening with MFA, notifications, account recovery
- Policy engines for complex authorization rules
- Biometric verification, fraud detection, cryptographic audit
- Data residency for EU compliance

**Skip:** Decentralized features (Phase 5) unless required

### For Identity-as-a-Service (34-46 days → Full Platform)

Implement all phases:

- Complete production system (Phases 0-3)
- Assurance Pack for enterprise customers (Phase 4)
- Decentralized features for Web3 differentiation (Phase 5)
- SDKs, sandbox, admin UI for developer experience (Phase 6)

---

## Technical Requirements by PRD

### Authentication & Identity (Phase 0-1)

- **PRD-001:** JWT tokens (HS256), bcrypt password hashing, Redis sessions, OIDC-lite endpoints
- **PRD-016:** Refresh token rotation, token revocation RFC 7009, TRL interface (Redis), JTI claims
- **PRD-003:** HTTP registry clients with circuit breaker, mock/live registry adapters
- **PRD-004:** W3C Verifiable Credentials (VC-JWT format), JSON-LD context, credential signing

### Authorization & Policy (Phase 1, 3)

- **PRD-005:** Evidence-based decision engine, Redis caching, structured logging
- **PRD-015:** Rego policy language (OPA), internal PDP evaluation, policy versioning
- **PRD-005B:** Cerbos external PDP integration, gRPC client, policy bundles

### Consent & Audit (Phase 0-1)

- **PRD-002:** CQRS read models (consent projections), event sourcing, PostgreSQL write/read stores
- **PRD-006:** Event streaming (Kafka/NATS), outbox pattern, 4-tier storage (Write/Hot/Warm/Cold)

### Infrastructure & Operations (Phase 0-3)

- **PRD-017:** Sliding window rate limiter, Redis Lua scripts, distributed counters
- **PRD-018:** Email (SendGrid/SES), SMS (Twilio/SNS), webhook HMAC signatures, retry queues
- **PRD-019:** URL-based API versioning, deprecation headers (Sunset, Deprecation)
- **PRD-020:** Kubernetes health probes, PostgreSQL backup to S3, DR plan (RTO: 4h, RPO: 1h)
- **PRD-021:** TOTP (RFC 6238), SMS/Email OTP, backup codes, device fingerprinting
- **PRD-022:** Password reset tokens, account unlock with cooldown, email verification

### Security & Assurance (Phase 4)

- **PRD-013:** Face matching (AWS Rekognition/Azure Face API), liveness detection, biometric templates
- **PRD-023:** Impossible travel detection, velocity checks, device fingerprinting, MaxMind GeoIP
- **PRD-006B:** Merkle tree audit logs, cryptographic verification, tamper detection
- **PRD-007B:** Scikit-learn anomaly detection, model training pipeline, adaptive scoring
- **PRD-008:** GDPR retention policies, breach detection, automated compliance reports
- **PRD-024:** Regional PostgreSQL instances (EU/US/Asia), cross-border transfer logging

### Compliance & Data Rights (Phase 2, 4)

- **PRD-007:** GDPR data export (JSON), deletion with cascade, consent withdrawal
- **PRD-008:** Automated data retention, breach detection (15min SLA), monthly compliance reports

### Decentralized Identity (Phase 5)

- **PRD-004B:** BBS+ signatures (selective disclosure), status lists (bitstring), revocation
- **PRD-009:** W3C DIDs (did:key, did:web), DID documents, resolution
- **PRD-010:** ZK-SNARKs (gnark library), age verification circuits, proof generation/verification

### Integrations & Developer Experience (Phase 6)

- **PRD-011:** TCP event ingester, NATS/Kafka producer, high-volume event handling
- **PRD-012:** AWS/Azure/GCP webhook connectors, S3/Blob Storage export
- **PRD-014:** TypeScript/React SDK with OAuth 2.0, Python/Go SDKs, API client libraries
- **PRD-025:** Sandbox environment (sandbox.credo.dev), test data generator, Swagger API explorer
- **PRD-026:** React admin UI, user/session/consent management, system health dashboard (Grafana)

---

## Testing Strategy

### Unit Tests

Each module follows BDD-style testing with gomock:

```go
// Given: known state or mocks
mockStore := mocks.NewMockUserStore(ctrl)
mockStore.EXPECT().FindByEmail(ctx, "user@example.com").Return(&domain.User{...}, nil)

// When: service method invoked
result, err := authService.Login(ctx, "user@example.com", "password")

// Then: assert results
assert.NoError(t, err)
assert.Equal(t, expectedToken, result.AccessToken)
```

### Integration Tests (E2E)

Godog feature tests in `e2e/` validate API contracts:

```gherkin
Feature: Authentication Flow
  Scenario: Successful login
    Given a registered user "alice@example.com"
    When I POST /auth/login with valid credentials
    Then I receive a 200 response
    And the response contains an access_token
```

Run with: `make test-e2e`

### Load Tests (Future)

- k6 scripts for performance testing
- Target: p95 < 200ms for auth endpoints
- Throughput: 1000 req/s sustained

---

## Architecture References

- **[architecture.md](../architecture.md):** System design, CQRS patterns, event streaming
- **[ROADMAP.md](../ROADMAP.md):** Implementation timeline, module bundles, adoption guide
- **[AGENTS.md](../../AGENTS.md):** Module structure rules, testing conventions, service layer patterns

---

## Glossary

- **PDP:** Policy Decision Point (evaluates authorization policies)
- **CQRS:** Command Query Responsibility Segregation (separate read/write models)
- **TRL:** Token Revocation List (registry of revoked tokens)
- **TOTP:** Time-based One-Time Password (RFC 6238, for MFA)
- **DID:** Decentralized Identifier (W3C standard, self-sovereign identity)
- **VC:** Verifiable Credential (W3C standard, portable identity claims)
- **ZK Proof:** Zero-Knowledge Proof (prove statement without revealing underlying data)
- **BBS+:** Boneh-Boyen-Shacham signatures (enable selective disclosure of credential attributes)

---

## Revision History

| Version | Date       | Changes                                                                                   |
| ------- | ---------- | ----------------------------------------------------------------------------------------- |
| 2.5     | 2025-12-23 | Added PRD-026B (Tenant & Client Lifecycle) to Phase 0                                     |
| 2.4     | 2025-12-21 | Added Storage Evolution Philosophy section (in-memory first, transition triggers)          |
| 2.3     | 2025-12-17 | Added Phase 7: Differentiation Pack (PRD-029 through PRD-033)                             |
| 2.2     | 2025-12-17 | Moved PRD-028 from Phase 0 to Phase 2 (performance after functionality)                   |
| 2.1     | 2025-12-16 | Added PRD-028 (Auth/Token performance), updated Phase 0 timelines/index, refreshed totals |
| 2.0     | 2025-12-12 | Added 11 new PRDs (16-26); restructured into 6 phases; updated timelines                  |
| 1.1     | 2025-12-11 | Added PRD-015 (Policy Engine); updated advanced feature sequencing                        |
| 1.0     | 2025-12-10 | Initial PRD suite (PRD-001 through PRD-014)                                               |

---

## Questions or Contributions

For questions about PRD implementation:

1. Check [architecture.md](../architecture.md) for system design context
2. Review [AGENTS.md](../../AGENTS.md) for module structure rules
3. Consult specific PRD for detailed acceptance criteria

For suggesting new PRDs or modifications:

1. Identify dependency on existing PRDs
2. Propose phase assignment (0-6) based on complexity and dependencies
3. Estimate implementation time (be realistic about learning curve)

---

**Credo Identity Platform: Complete Technical Specification Suite**
