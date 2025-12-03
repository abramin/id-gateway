# Product Requirements Documents (PRDs)

**ID Gateway Implementation Specifications**

This directory contains technical product requirements for implementing the ID Gateway system. Each PRD is written for developers and provides detailed specifications, API contracts, data models, and acceptance criteria.

---

## Overview

The ID Gateway is a **regulated identity and authorization system** that:
- Authenticates users (OIDC-lite)
- Manages purpose-based consent
- Integrates with external registries (citizen data, sanctions)
- Issues verifiable credentials
- Makes authorization decisions based on evidence
- Maintains comprehensive audit trails
- Supports GDPR data rights (export, deletion)

---

## PRD Index

| PRD | Feature | Priority | Status | Est. Time |
|-----|---------|----------|--------|-----------|
| [PRD-001](./PRD-001-Authentication-Session-Management.md) | Authentication & Session Management | P0 | 🟡 To Implement | 4-6 hours |
| [PRD-002](./PRD-002-Consent-Management.md) | Consent Management System | P0 | 🟡 To Implement | 4-6 hours |
| [PRD-003](./PRD-003-Registry-Integration.md) | Registry Integration (Citizen & Sanctions) | P0 | 🟡 To Implement | 4-6 hours |
| [PRD-004](./PRD-004-Verifiable-Credentials.md) | Verifiable Credentials | P0 | 🟡 To Implement | 3-5 hours |
| [PRD-005](./PRD-005-Decision-Engine.md) | Decision Engine | P0 | 🟡 To Implement | 5-7 hours |
| [PRD-006](./PRD-006-Audit-Compliance.md) | Audit & Compliance Logging | P0 | 🟡 To Implement | 3-4 hours |
| [PRD-007](./PRD-007-User-Data-Rights.md) | User Data Rights (GDPR) | P1 | 🟡 To Implement | 4-5 hours |

**Total Estimated Time:** ~27-39 hours (3-5 days for single developer)

---

## Recommended Implementation Order

Implement PRDs in this sequence to minimize dependencies and enable incremental testing:

### Phase 1: Foundation (Days 1-2)
**Goal:** Establish authentication and consent mechanisms

1. **PRD-001: Authentication & Session Management** (4-6 hours)
   - Why first: Everything depends on user authentication
   - Deliverable: Users can log in and get tokens
   - Test: `curl POST /auth/authorize`, `POST /auth/token`, `GET /auth/userinfo`

2. **PRD-002: Consent Management** (4-6 hours)
   - Why second: Required before processing any user data
   - Deliverable: Users can grant/revoke consent for purposes
   - Test: `curl POST /auth/consent`, `POST /auth/consent/revoke`

### Phase 2: Evidence Gathering (Day 2-3)
**Goal:** Integrate with external data sources

3. **PRD-003: Registry Integration** (4-6 hours)
   - Why third: Provides evidence for decisions
   - Deliverable: Lookup citizen and sanctions records
   - Test: `curl POST /registry/citizen`, `POST /registry/sanctions`
   - Note: Test both regulated and non-regulated modes

4. **PRD-004: Verifiable Credentials** (3-5 hours)
   - Why fourth: Portable evidence that depends on registry data
   - Deliverable: Issue and verify credentials
   - Test: `curl POST /vc/issue`, `POST /vc/verify`

### Phase 3: Decision Logic (Day 3-4)
**Goal:** Combine evidence and make authorization decisions

5. **PRD-005: Decision Engine** (5-7 hours)
   - Why fifth: Orchestrates all previous components
   - Deliverable: Evaluate authorization decisions
   - Test: `curl POST /decision/evaluate` with various scenarios
   - Challenge: Most complex, involves all services

### Phase 4: Compliance (Day 4-5)
**Goal:** Audit trail and user data rights

6. **PRD-006: Audit & Compliance** (3-4 hours)
   - Why sixth: Adds audit logging to all previous handlers
   - Deliverable: All operations emit audit events, users can export logs
   - Test: Perform flow, then `curl GET /me/data-export`

7. **PRD-007: User Data Rights** (4-5 hours)
   - Why last: Depends on all stores being complete
   - Deliverable: Users can delete all their data
   - Test: `curl DELETE /me`, verify deletion

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

### User Extraction from Token
```go
// Standard pattern for all handlers
authHeader := r.Header.Get("Authorization")
if authHeader == "" {
    writeError(w, errors.NewGatewayError(errors.CodeUnauthorized, "Missing authorization header", nil))
    return
}

token := strings.TrimPrefix(authHeader, "Bearer ")
user, err := h.authService.UserInfo(ctx, token)
if err != nil {
    writeError(w, err)
    return
}
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

Implementation is complete when:
- [ ] All 11 HTTP endpoints return 200/201 (not 501)
- [ ] `make test` passes with >80% coverage
- [ ] `make lint` passes with no errors
- [ ] Complete flow works end-to-end
- [ ] All acceptance criteria checked off
- [ ] Regulated mode minimizes PII correctly
- [ ] Audit logs capture all sensitive operations
- [ ] Documentation updated (if needed)

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

### To Implement 🟡
- All HTTP handler logic (11 endpoints)
- Service method implementations
- Evidence orchestration in decision engine
- Audit event emission across handlers
- Data deletion logic

---

## Getting Help

### Resources:
- **Tutorial:** `docs/TUTORIAL.md` - Step-by-step learning guide
- **Architecture:** `docs/architecture.md` - System design and patterns

### Common Questions:

**Q: Do I need to implement PRDs in exact order?**
A: Yes, follow the dependency order. Auth → Consent → Registry → VC → Decision → Audit → Data Rights.

**Q: Can I skip testing?**
A: No. Test each PRD before moving to next. Bugs compound quickly.

**Q: Should I implement all features in a PRD?**
A: Implement functional requirements. Future enhancements are optional.

**Q: What if I find an issue in a PRD?**
A: Document it in code comments and proceed with best judgment. PRDs are guidelines.

**Q: How do I handle errors not listed in PRD?**
A: Use appropriate error code from `pkg/errors` and return clear message.

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-03 | Product Team | Initial PRD suite |
