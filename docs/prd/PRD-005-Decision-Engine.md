# PRD-005: Decision Engine

**Status:** Implementation Required
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Last Updated:** 2025-12-18

---

## 1. Overview

### Problem Statement

The gateway must make authorization decisions by combining evidence from multiple sources (registries, VCs, user attributes) and applying business rules. This is the core "allow/deny" logic that answers: "For user U, doing action A, for purpose P, with evidence E, is this allowed?"

### Goals

- Implement decision evaluation endpoint
- Orchestrate evidence gathering (registry + VC checks)
- Apply business rules based on purpose
- Return structured decision outcomes (pass/fail/conditional)
- Support multiple decision purposes (age_verification, sanctions_screening, etc.)
- Derive non-PII attributes for decision making

### Non-Goals

- Machine learning / AI-based decisions
- Risk scoring algorithms
- Complex rule engines (Drools, etc.)
- Dynamic rule updates at runtime
- Multi-step decision workflows
- Appeal/override mechanisms

---

## 2. User Stories

**As a** client application
**I want to** evaluate whether a user is authorized for an action
**So that** I can allow or deny access based on business rules

**As a** compliance officer
**I want to** decisions to be auditable and traceable
**So that** I can prove we followed proper authorization logic

**As a** developer
**I want to** decisions to clearly state why they passed or failed
**So that** I can debug and improve the system

---

## 3. Functional Requirements

### FR-1: Evaluate Decision

**Endpoint:** `POST /decision/evaluate`

**Description:** Evaluate an authorization decision by gathering evidence and applying rules for the specified purpose.

**Input:**

```json
{
  "purpose": "age_verification",
  "context": {
    "national_id": "123456789"
  }
}
```

**Output (Success - Pass):**

```json
{
  "status": "pass",
  "reason": "all_checks_passed",
  "conditions": [],
  "evidence": {
    "citizen_valid": true,
    "sanctions_listed": false,
    "has_credential": true,
    "is_over_18": true
  },
  "evaluated_at": "2025-12-03T10:00:00Z"
}
```

**Output (Fail - Sanctioned):**

```json
{
  "status": "fail",
  "reason": "sanctioned",
  "conditions": [],
  "evidence": {
    "sanctions_listed": true
  },
  "evaluated_at": "2025-12-03T10:00:00Z"
}
```

**Output (Pass with Conditions):**

```json
{
  "status": "pass_with_conditions",
  "reason": "missing_credential",
  "conditions": ["obtain_age_credential"],
  "evidence": {
    "citizen_valid": true,
    "sanctions_listed": false,
    "has_credential": false
  },
  "evaluated_at": "2025-12-03T10:00:00Z"
}
```

**Business Logic:**

1. Extract user from bearer token
2. Require consent for `ConsentPurposeDecision` (optional for MVP)
3. Parse purpose and context from request
4. **Gather Evidence** based on purpose:
   - For "age_verification":
     - Get national_id from context
     - Fetch citizen record: `registryService.Citizen(nationalID)`
     - Fetch sanctions record: `registryService.Sanctions(nationalID)`
     - Check for AgeOver18 VC: `vcStore.FindByUserAndType(userID, "AgeOver18")`
   - For "sanctions_screening":
     - Get national_id from context
     - Fetch sanctions record only
5. **Derive Identity Attributes:**
   - Parse DateOfBirth from citizen record
   - Calculate IsOver18: `age >= 18`
   - Create DerivedIdentity (no PII, only computed flags)
6. **Build DecisionInput:**
   ```go
   DecisionInput{
       UserID: userID,
       Purpose: purpose,
       SanctionsListed: sanctions.Listed,
       CitizenValid: citizen.Valid,
       HasCredential: vcExists,
       DerivedIdentity: DerivedIdentity{
           IsOver18: isOver18,
       },
   }
   ```
7. **Call Decision Service:**
   `outcome := decisionService.Evaluate(ctx, input)`
8. **Emit Audit Event:**
   ```go
   audit.Event{
       Action: "decision_made",
       UserID: userID,
       Purpose: purpose,
       Decision: outcome.Status,
       Reason: outcome.Reason,
   }
   ```
9. Return decision outcome

**Validation:**

- purpose is required and non-empty
- context.national_id is required for age_verification

**Error Cases:**

- 401 Unauthorized: Invalid bearer token
- 400 Bad Request: Missing purpose or required context
- 504 Gateway Timeout: Registry unavailable
- 500 Internal Server Error: Store or service failure

---

## 4. Decision Rules by Purpose

### Purpose: "age_verification"

**Evidence Required:**

- Citizen record (valid, date of birth)
- Sanctions record (listed status)
- AgeOver18 VC (optional)

**Rules:**

1. IF sanctions.Listed == true → **FAIL** (reason: "sanctioned")
2. IF citizen.Valid == false → **FAIL** (reason: "invalid_citizen")
3. IF derived.IsOver18 == false → **FAIL** (reason: "underage")
4. IF hasCredential == true → **PASS** (reason: "all_checks_passed")
5. ELSE → **PASS_WITH_CONDITIONS** (reason: "missing_credential", conditions: ["obtain_age_credential"])

### Purpose: "sanctions_screening"

**Evidence Required:**

- Sanctions record only

**Rules:**

1. IF sanctions.Listed == true → **FAIL** (reason: "sanctioned")
2. ELSE → **PASS** (reason: "not_sanctioned")

### Purpose: "high_value_transfer" (Future)

**Evidence Required:**

- Citizen record
- Sanctions record
- Transaction amount from context

**Rules:**

1. IF sanctions.Listed == true → **FAIL** (reason: "sanctioned")
2. IF citizen.Valid == false → **FAIL** (reason: "invalid_citizen")
3. IF amount > 10000 AND isPEP == true → **PASS_WITH_CONDITIONS** (reason: "manual_review_required", conditions: ["compliance_review"])
4. ELSE → **PASS** (reason: "approved")

---

## 5. Technical Requirements

### TR-1: Data Models

**Location:** `internal/decision/models.go`

```go
type DecisionStatus string

const (
    DecisionPass              DecisionStatus = "pass"
    DecisionPassWithConditions               = "pass_with_conditions"
    DecisionFail                             = "fail"
)

type DecisionInput struct {
    UserID          string
    Purpose         string
    SanctionsListed bool
    CitizenValid    bool
    HasCredential   bool
    DerivedIdentity DerivedIdentity
    Context         map[string]any // Extra data (amount, country, etc.)
}

type DerivedIdentity struct {
    PseudonymousID string // Hash of user ID
    IsOver18       bool
    // No PII fields (no name, DOB, etc.)
}

type DecisionOutcome struct {
    Status     DecisionStatus
    Reason     string
    Conditions []string // e.g., ["obtain_credential", "manual_review"]
}
```

### TR-2: Service Layer

**Location:** `internal/decision/service.go`

```go
type Service struct {
    registry *registry.Service
    vcStore  vc.Store
    auditor  audit.Publisher
    now      func() time.Time
}

func (s *Service) Evaluate(ctx context.Context, in DecisionInput) (DecisionOutcome, error) {
    // Apply rules based on purpose
    if in.SanctionsListed {
        return DecisionOutcome{Status: DecisionFail, Reason: "sanctioned"}, nil
    }
    if !in.CitizenValid {
        return DecisionOutcome{Status: DecisionFail, Reason: "invalid_citizen"}, nil
    }
    if !in.DerivedIdentity.IsOver18 {
        return DecisionOutcome{Status: DecisionFail, Reason: "underage"}, nil
    }
    if in.HasCredential {
        return DecisionOutcome{Status: DecisionPass, Reason: "all_checks_passed"}, nil
    }
    return DecisionOutcome{
        Status: DecisionPassWithConditions,
        Reason: "missing_credential",
        Conditions: []string{"obtain_age_credential"},
    }, nil
}
```

### TR-3: Identity Derivation

**Location:** `internal/decision/models.go`

```go
func DerivedIdentityFromCitizen(citizen *registry.CitizenRecord) DerivedIdentity {
    return DerivedIdentity{
        PseudonymousID: hashUserID(citizen.NationalID), // Hash for privacy
        IsOver18:       deriveIsOver18(citizen.DateOfBirth),
    }
}

func deriveIsOver18(dob string) bool {
    birthDate, err := time.Parse("2006-01-02", dob)
    if err != nil {
        return false
    }
    age := time.Now().Year() - birthDate.Year()
    // Account for birthday not yet passed this year
    if time.Now().YearDay() < birthDate.YearDay() {
        age--
    }
    return age >= 18
}
```

### TR-4: HTTP Handler

**Location:** `internal/transport/http/handlers_decision.go`

```go
func (h *Handler) handleDecisionEvaluate(w http.ResponseWriter, r *http.Request) {
    // 1. Extract user from token
    // 2. Parse request (purpose, context)
    // 3. Gather evidence based on purpose
    // 4. Build DecisionInput
    // 5. Call decisionService.Evaluate()
    // 6. Emit audit event
    // 7. Return JSON response
}
```

### TR-5: CQRS & Read-Optimized Projections

**Objective:** Keep write-side decision orchestration isolated from read-optimized evidence lookups and decision history.

- **Write Model:** The HTTP handler + service orchestrate registry/VC/audit lookups and emit `decision_made` events to the
  audit/event bus. Canonical decision inputs/outputs remain in the service layer.
- **Read Model:** Maintain a denormalized projection for "recent decisions by user+purpose" in a NoSQL/TTL store (Redis,
  DynamoDB, or Mongo) to power fast re-checks and idempotent retries. Projection fields: `user_id`, `purpose`, `status`,
  `reason`, `conditions`, `evaluated_at`, `evidence_hash`.
- **Evidence Caches:** Registry and VC results used during evaluation SHOULD be cached in the same NoSQL tier with short TTLs to
  avoid repeated upstream calls during an evaluation burst.
- **Event Transport:** Prefer Kafka/NATS for `decision_made` events so downstream risk scoring, audit indexing, and replay tools
  can subscribe without coupling to HTTP handlers; use an outbox pattern to avoid lost events under failure.
- **Consistency:** Write path is source of truth; read model is eventually consistent (≤1s lag). On cache miss or suspected
  staleness, fall back to canonical evaluation or rebuild projection from audit log replay.

### TR-6: Secure-by-Design Evaluation

- Rule graphs must be modeled as DAGs with cycle detection at construction time; evaluation order determined by topological sort with memoization for shared sub-rules.
- Default deny when required evidence (consent, registry response, VC) is absent, stale, or unverifiable; handlers cannot bypass this by passing raw maps.
- Execution must be deterministic (no timing-based branching); include a bounded LRU cache for rule results with defined eviction.
- Policies/rules are published as signed, immutable bundles (versioned); service only loads validated signatures and emits audit events on publish/activation.
- Inputs must be value objects (purpose enum, tenant/user IDs, evidence structs stripped of PII). Reject unvalidated maps in service boundaries.

---

## 6. Implementation Steps

1. **Phase 1:** Evidence Orchestration (2-3 hours)
   - In handleDecisionEvaluate, call registryService for citizen/sanctions
   - Check vcStore for existing credentials
   - Build DecisionInput struct
2. **Phase 2:** Decision Service Enhancement (1 hour)
   - Implement rule logic for each purpose
   - Return structured outcomes
3. **Phase 3:** Identity Derivation (1 hour)
   - Implement DerivedIdentityFromCitizen()
   - Implement deriveIsOver18() with proper date math
4. **Phase 4:** Audit Integration (30 min)
   - Emit decision_made events with outcome
5. **Phase 5:** Testing (1-2 hours)
   - Unit tests for rule logic
   - Integration tests for complete flow
   - Manual testing with various scenarios

---

## 7. Acceptance Criteria

- [ ] Decision evaluates pass for compliant users with credentials
- [ ] Decision fails for sanctioned users
- [ ] Decision fails for users under 18
- [ ] Decision passes with conditions for users without VCs
- [ ] All decisions emit audit events with outcome
- [ ] Evidence gathering handles registry errors gracefully
- [ ] Derived identity contains no PII
- [ ] Code passes tests and lint

---

## 8. Testing

```bash
# Grant consent
curl -X POST http://localhost:8080/auth/consent \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"purposes": ["registry_check", "vc_issuance"]}'

# Issue VC first
curl -X POST http://localhost:8080/vc/issue \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type": "AgeOver18", "national_id": "123456789"}'

# Evaluate decision (should pass)
curl -X POST http://localhost:8080/decision/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "purpose": "age_verification",
    "context": {"national_id": "123456789"}
  }'

# Expected: {"status": "pass", "reason": "all_checks_passed"}

# Test without VC (should pass with conditions)
# Use different user who hasn't issued VC
curl -X POST http://localhost:8080/decision/evaluate \
  -H "Authorization: Bearer $TOKEN2" \
  -d '{
    "purpose": "age_verification",
    "context": {"national_id": "987654321"}
  }'

# Expected: {"status": "pass_with_conditions", "reason": "missing_credential"}
```

---

## 9. Future Enhancements

- Rule engine (externalized rules in JSON/YAML)
- Risk scoring (ML-based fraud detection)
- Multi-step workflows (require multiple checks)
- Decision caching (cache outcomes for short period)
- Override mechanisms (manual approval)
- A/B testing of rule variants

---

## References

- Existing Code: `internal/decision/`

---

## Revision History

| Version | Date       | Author       | Changes                                    |
| ------- | ---------- | ------------ | ------------------------------------------ |
| 1.2     | 2025-12-18 | Security Eng | Added secure-by-design evaluation (DAG, default-deny, signed policy bundles) |
| 1.0     | 2025-12-03 | Product Team | Initial PRD                                |
| 1.1     | 2025-12-12 | Engineering  | Add TR-5 CQRS & Read-Optimized Projections |
