# Product Requirements Documents (PRDs)

**Credo Implementation Specifications**

This directory contains technical product requirements for implementing Credo system. Each PRD is written for developers and provides detailed specifications, API contracts, data models, and acceptance criteria.

---

## Overview

Credo is a **regulated identity and authorization system** that:

- Authenticates users (OIDC-lite)
- Manages purpose-based consent
- Integrates with external registries (citizen data, sanctions)
- Issues verifiable credentials
- Makes authorization decisions based on evidence
- Maintains comprehensive audit trails
- Supports GDPR data rights (export, deletion)
- **NEW:** Advanced privacy-preserving features (ZK proofs, DIDs, ML risk scoring)
- Validates API contracts with godog-based E2E feature tests in `e2e/`

---

## PRD Index

### Core Features (V1 - Baseline System)

| PRD                                                       | Feature                                    | Priority | Status          | Est. Time   |
| --------------------------------------------------------- | ------------------------------------------ | -------- | --------------- | ----------- |
| [PRD-001](./PRD-001-Authentication-Session-Management.md) | Authentication & Session Management        | P0       | 🟢 Done         | 13-14 hours |
| [PRD-002](./PRD-002-Consent-Management.md)                | Consent Management System                  | P0       | 🟡 In Progress  | 5-7 hours   |
| [PRD-003](./PRD-003-Registry-Integration.md)              | Registry Integration (Citizen & Sanctions) | P0       | 🟡 To Implement | 7-9 hours   |
| [PRD-004](./PRD-004-Verifiable-Credentials.md)            | Verifiable Credentials                     | P0       | 🟡 To Implement | 6-8 hours   |
| [PRD-005](./PRD-005-Decision-Engine.md)                   | Decision Engine                            | P0       | 🟡 To Implement | 5-7 hours   |
| [PRD-006](./PRD-006-Audit-Compliance.md)                  | Audit & Compliance Logging                 | P0       | 🟡 To Implement | 8-10 hours  |
| [PRD-007](./PRD-007-User-Data-Rights.md)                  | User Data Rights (GDPR)                    | P1       | 🟡 To Implement | 4-6 hours   |

**Core System Time:** ~48-61 hours (6-8 days)

### Advanced Features (V2+ - Showcase & Production)

| PRD                                                                        | Feature                           | Priority | Status         | Est. Time   |
| -------------------------------------------------------------------------- | --------------------------------- | -------- | -------------- | ----------- |
| [PRD-004B](./PRD-004B-Enhanced-Verifiable-Credentials.md)                  | Enhanced VCs (BBS+, Status List)  | P1       | 🔵 Not Started | 10-14 hours |
| [PRD-005B](./PRD-005B-Cerbos-Authorization.md)                             | Cerbos-Based Authorization        | P1       | 🔵 Not Started | 6-8 hours   |
| [PRD-006B](./PRD-006B-Cryptographic-Audit.md)                              | Cryptographic Audit (Merkle Tree) | P1       | 🔵 Not Started | 8-12 hours  |
| [PRD-007B](./PRD-007B-ML-Risk-Scoring.md)                                  | ML-Based Risk Scoring             | P2       | 🔵 Not Started | 14-18 hours |
| [PRD-008](./PRD-008-GDPR-CCPA-Automation.md)                               | Automated GDPR/CCPA Compliance    | P1       | 🔵 Not Started | 12-16 hours |
| [PRD-009](./PRD-009-Decentralized-Identity-DIDs.md)                        | Decentralized Identity (DIDs)     | P2       | 🔵 Not Started | 16-20 hours |
| [PRD-010](./PRD-010-Zero-Knowledge-Proofs.md)                              | Zero-Knowledge Proofs             | P3       | 🔵 Not Started | 20-24 hours |
| [PRD-011](./PRD-011-Internal-TCP-Event-Ingester.md)                        | Internal TCP Event Ingester       | P1       | 🔵 Not Started | 8-12 hours  |
| [PRD-012](./PRD-012-Cloud-Connectors-Credo-Audit-Identity-Event-Export.md) | Cloud Connectors- Audit Export    | P1       | 🔵 Not Started | ?           |

**Advanced Features Time:** ~94-124 hours (11-15 days)

**Total System Time:** ~142-185 hours (18-23 days)

---

## Strategic Implementation Approach

### Phase 1: Core System (6-8 days)

**Goal:** Build functional identity gateway with basic features

Implement PRDs 001-007 to establish:

- User authentication and session management
- Consent-based data processing
- Registry integration for identity verification
- Verifiable credential issuance
- Authorization decision engine
- Audit logging and GDPR compliance

**Deliverable:** Working identity gateway with all baseline features

### Phase 2: Production Readiness (3-5 days)

**Goal:** Make system operationally credible (see V2_ROADMAP.md)

- Signed JWT tokens + JWKS
- PostgreSQL persistence
- Structured logging & metrics
- Queue-backed audit pipeline
- Token refresh & revocation

**Deliverable:** Production-ready gateway with operational maturity

### Phase 3: Advanced Features - Showcase Track (10-14 days)

**Goal:** Add distinctive features that differentiate from "another Auth0 clone"

**Recommended Priority Order:**

1. **PRD-006B: Cryptographic Audit Trail** (8-12 hours) - **START HERE**

   - **Why first:** Easiest advanced feature, clear value
   - **Impact:** Tamper-proof audit logs using Merkle trees
   - **Resume line:** "Built cryptographically verifiable audit system"
   - **Best for:** Fintech, healthcare, compliance-heavy domains

2. **PRD-008: GDPR/CCPA Automation** (12-16 hours) - **DO SECOND**

   - **Why second:** Practical, relevant to EU, builds on audit
   - **Impact:** Real-time compliance checking, automated data retention
   - **Resume line:** "Implemented automated GDPR/CCPA compliance engine"
   - **Best for:** European companies, privacy-focused organizations

3. **PRD-007B: ML-Based Risk Scoring** (14-18 hours) - **DO THIRD**

   - **Why third:** Shows polyglot skills (Go + Python), trendy (AI/ML)
   - **Impact:** Learning fraud detection, adaptive risk assessment
   - **Resume line:** "Integrated ML-based risk scoring into decision engine"
   - **Best for:** Fintech, e-commerce, fraud prevention roles

4. **PRD-009: Decentralized Identity (DIDs)** (16-20 hours) - **DO FOURTH**

   - **Why fourth:** Emerging standard, shows forward thinking
   - **Impact:** W3C-standard DIDs, user-controlled identity
   - **Resume line:** "Built identity gateway using W3C Decentralized Identifiers"
   - **Best for:** Blockchain/Web3 companies, identity startups (Digidentity)

5. **PRD-010: Zero-Knowledge Proofs** (20-24 hours) - **DO LAST**
   - **Why last:** Most technically impressive, requires solid foundation
   - **Impact:** Privacy-preserving age verification (prove "over 18" without revealing birthdate)
   - **Resume line:** "Implemented zero-knowledge proofs for privacy-preserving verification"
   - **Best for:** Privacy-focused companies, cutting-edge identity solutions

---

## Recommended Implementation Order

### Core System (Must Complete First)

Implement PRDs in this sequence to minimize dependencies and enable incremental testing:

#### Phase 1: Foundation (Days 1-2)

**Goal:** Establish authentication and consent mechanisms

1. **PRD-001: Authentication & Session Management** ✅ COMPLETE

   - Why first: Everything depends on user authentication
   - Deliverable: Users can log in and get tokens

2. **PRD-002: Consent Management** 🟡 IN PROGRESS
   - Why second: Required before processing any user data
   - Deliverable: Users can grant/revoke consent for purposes

#### Phase 2: Evidence Gathering (Day 2-3)

**Goal:** Integrate with external data sources

3. **PRD-003: Registry Integration** (4-6 hours)

   - Why third: Provides evidence for decisions
   - Deliverable: Lookup citizen and sanctions records

4. **PRD-004: Verifiable Credentials** (3-5 hours)
   - Why fourth: Portable evidence that depends on registry data
   - Deliverable: Issue and verify credentials

#### Phase 3: Decision Logic (Day 3-4)

**Goal:** Combine evidence and make authorization decisions

5. **PRD-005: Decision Engine** (5-7 hours)
   - Why fifth: Orchestrates all previous components
   - Deliverable: Evaluate authorization decisions

#### Phase 4: Compliance (Day 4-5)

**Goal:** Audit trail and user data rights

6. **PRD-006: Audit & Compliance** (3-4 hours)

   - Why sixth: Adds audit logging to all previous handlers
   - Deliverable: All operations emit audit events

7. **PRD-007: User Data Rights** (4-5 hours)
   - Why last: Depends on all stores being complete
   - Deliverable: Users can delete all their data

### Advanced Features (After Core Complete)

#### Track A: Production Hardening (Priority)

Follow V2_ROADMAP.md for operational maturity features

#### Track B: Showcase Features (Differentiation)

**For Backend/Distributed Systems Roles:**

- Start with: PRD-006B (Merkle Tree Audit)
- Then add: PRD-005B (Cerbos Authorization)

**For Privacy/Compliance Roles:**

- Start with: PRD-008 (GDPR Automation)
- Then add: PRD-010 (Zero-Knowledge Proofs)

**For Fintech/Security Roles:**

- Start with: PRD-007B (ML Risk Scoring)
- Then add: PRD-006B (Cryptographic Audit)

**For Identity/Web3 Startups:**

- Start with: PRD-009 (DIDs)
- Then add: PRD-010 (Zero-Knowledge Proofs)

---

## What Each PRD Contains

Every PRD includes:

### 1. Overview

- Problem statement
- Goals and non-goals
- User stories

### 2. Functional Requirements

- API specifications (HTTP endpoints)
- Input/output examples
- Business logic step-by-step
- Error cases

### 3. Technical Requirements

- Data models (Go structs)
- Storage interfaces
- Service layer design
- HTTP handler signatures

### 4. Implementation Steps

- Phase-by-phase guide
- Estimated time per phase
- Dependencies between components

### 5. Acceptance Criteria

- Checklist of what "done" means
- Must pass before moving to next PRD

### 6. Testing Guide

- Unit test scenarios
- Integration test flows
- Manual curl commands for testing

### 7. Future Enhancements

- Out-of-scope features for later
- Production-ready improvements

---

## How to Use These PRDs

### For Product Managers:

- Review functional requirements to understand features
- Validate API contracts match business needs
- Adjust acceptance criteria as needed
- Track implementation progress via checklist

### For Developers:

1. **Read PRD completely** before coding
2. **Understand dependencies** - implement in order above
3. **Follow Technical Requirements** exactly (data models, interfaces)
4. **Use Implementation Steps** as your task breakdown
5. **Test incrementally** - use curl commands after each handler
6. **Check Acceptance Criteria** before marking as done

### For QA Engineers:

- Use Testing sections to create test plans
- Validate all acceptance criteria are testable
- Create automated tests based on examples
- Test edge cases mentioned in Error Cases

---

## Cross-Cutting Concerns

These patterns apply across ALL PRDs:

### Error Handling

```go
// Use typed errors from pkg/errors
return errors.NewGatewayError(errors.CodeMissingConsent, "...", nil)

// Map to HTTP status in handlers
writeError(w, err) // Automatically maps to 400/401/403/404/500
```

### Regulated Mode

```go
// Check regulatedMode flag before returning data
if h.regulatedMode {
    record = MinimizeCitizenRecord(record, true)
}
```

### Consent Enforcement

```go
// Before processing user data
err := h.consentService.Require(ctx, userID, consent.ConsentPurposeRegistryCheck)
if err != nil {
    writeError(w, err) // Returns 403
    return
}
```

### Audit Logging

```go
// After every sensitive operation
_ = h.auditPublisher.Emit(ctx, audit.Event{
    ID:        uuid.New().String(),
    Timestamp: time.Now(),
    UserID:    userID,
    Action:    "registry_citizen_checked",
    Purpose:   "registry_check",
    Decision:  "checked",
    Reason:    "identity_verification",
})
```

---

## Testing Strategy

### Unit Tests

- Test service methods in isolation
- Mock store dependencies
- Test business logic edge cases
- Located in: `internal/<package>/<file>_test.go`

### Integration Tests

- Test complete HTTP flows
- Use in-memory stores (no mocks needed)
- Test error paths (missing consent, invalid data)
- Located in: `test/integration_test.go`

### Manual Testing

- Use curl commands from PRDs
- Test in both regular and regulated mode
- Verify audit events emitted
- Follow testing sections in each PRD

### End-to-End Flow Test

```bash
# Complete happy path
./test/e2e_test.sh

# Should test:
# 1. Authorize → Token → UserInfo
# 2. Grant consent
# 3. Lookup registry
# 4. Issue VC
# 5. Evaluate decision
# 6. Export audit log
# 7. Delete user data
```

---

## Success Metrics

### Core System Complete When:

- [ ] All 11 HTTP endpoints return 200/201 (not 501)
- [ ] `make test` passes with >80% coverage
- [ ] `make lint` passes with no errors
- [ ] Complete flow works end-to-end
- [ ] All acceptance criteria checked off
- [ ] Regulated mode minimizes PII correctly
- [ ] Audit logs capture all sensitive operations

### Production Ready When (V2):

- [ ] JWT tokens signed and verifiable
- [ ] PostgreSQL persistence working
- [ ] Structured logging with correlation IDs
- [ ] Prometheus metrics exposed
- [ ] Queue-backed audit pipeline
- [ ] Token refresh and revocation

### Showcase Complete When:

- [ ] 2-3 advanced features implemented
- [ ] Each feature has distinctive resume line
- [ ] Documentation explains cryptographic/technical details
- [ ] Live demo available
- [ ] Performance benchmarks documented

---

## Dependencies

### Already Implemented ✅

- Domain models (User, Session, ConsentRecord, etc.)
- Store interfaces (UserStore, SessionStore, etc.)
- In-memory store implementations
- Error type system
- Config loading
- HTTP router scaffolding
- Makefile (build, test, run)

### Core Features To Implement 🟡

- All HTTP handler logic (11 endpoints)
- Service method implementations
- Evidence orchestration in decision engine
- Audit event emission across handlers
- Data deletion logic

### Advanced Features To Implement 🔵

- Merkle tree audit trail
- ML risk scoring engine
- GDPR compliance automation
- W3C DID implementation
- Zero-knowledge proof circuits
- Cerbos policy engine integration

---

## Resume Impact

### Core System (Baseline)

"Built identity verification gateway with OIDC auth, consent management, verifiable credentials, and decision engine. Go, PostgreSQL, Docker, 80%+ test coverage."

### With Merkle Tree Audit

"...with **cryptographically verifiable audit system using Merkle trees** for tamper-proof logging."

### With GDPR Automation

"...with **automated GDPR/CCPA compliance checking** and real-time policy enforcement."

### With ML Risk Scoring

"...with **ML-based fraud detection** and adaptive risk scoring (Go + Python)."

### With DIDs

"...using **W3C Decentralized Identifiers (DIDs)** for user-controlled identity."

### With Zero-Knowledge Proofs

"...with **zero-knowledge proofs** for privacy-preserving age verification (Bulletproofs/Rust)."

---

## Getting Help

### Resources:

- **Architecture:** `docs/architecture.md` - System design and patterns
- **V2 Roadmap:** `docs/V2_ROADMAP.md` - Production readiness features
- **System Design:** `docs/SYSTEM_DESIGN_ROADMAP.md` - Scalability and observability

## Revision History

| Version | Date       | Author       | Changes                                                        |
| ------- | ---------- | ------------ | -------------------------------------------------------------- |
| 1.0     | 2025-12-03 | Product Team | Initial PRD suite                                              |
| 2.0     | 2025-12-06 | Product Team | Added advanced features (DIDs, ZK proofs, ML, GDPR automation) |
