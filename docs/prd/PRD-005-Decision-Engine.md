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
     - Execute evidence lookups in parallel (errgroup or equivalent) with shared context cancellation on first failure/timeout; emit per-source latency/cache metrics.
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

- Evidence gathering MUST be orchestrated in the service layer (not handlers) via a helper that runs registry and VC lookups concurrently using a shared `context.Context` (errgroup preferred) with early cancellation on first error/timeout.
- Emit per-source spans/metrics (latency, cache hit/miss) and map infra/store errors to domain errors before rule evaluation.
- Handlers remain thin: parse/validate, call orchestrator + evaluator, emit audit event, return response.

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
- Rule persistence uses normalized tables with versioning and immutability constraints; published rules are append-only with `CHECK` constraints for bounds and `EXPLAIN`-verified indexes for lookups.

### TR-7: SQL Query Patterns & Database Design

**Objective:** Demonstrate intermediate-to-advanced SQL capabilities when implementing decision persistence and analytics.

**Query Patterns Required:**

- **CTEs for Rule Chain Resolution:** Use Common Table Expressions to recursively resolve rule dependencies:

  ```sql
  WITH RECURSIVE rule_chain AS (
    SELECT id, parent_id, rule_name, 1 AS depth
    FROM decision_rules WHERE id = :root_rule_id
    UNION ALL
    SELECT r.id, r.parent_id, r.rule_name, rc.depth + 1
    FROM decision_rules r
    JOIN rule_chain rc ON r.parent_id = rc.id
    WHERE rc.depth < 10
  )
  SELECT * FROM rule_chain ORDER BY depth;
  ```

- **Window Functions for Decision Analytics:** Use `RANK()`, `LAG()`, `LEAD()` for decision history analysis:

  ```sql
  SELECT user_id, purpose, status,
         LAG(status) OVER (PARTITION BY user_id, purpose ORDER BY evaluated_at) AS prev_status,
         RANK() OVER (PARTITION BY purpose ORDER BY evaluated_at DESC) AS recency_rank,
         COUNT(*) OVER (PARTITION BY user_id, purpose) AS total_decisions
  FROM decision_history
  WHERE evaluated_at > NOW() - INTERVAL '30 days';
  ```

- **CASE Statements for Status Categorization:**

  ```sql
  SELECT purpose,
         COUNT(*) AS total,
         SUM(CASE WHEN status = 'pass' THEN 1 ELSE 0 END) AS passed,
         SUM(CASE WHEN status = 'fail' THEN 1 ELSE 0 END) AS failed,
         SUM(CASE WHEN status = 'pass_with_conditions' THEN 1 ELSE 0 END) AS conditional
  FROM decision_history
  GROUP BY purpose
  HAVING COUNT(*) > 10;
  ```

- **Correlated Subqueries for Evidence Freshness:**

  ```sql
  SELECT d.id, d.user_id, d.evaluated_at,
         (SELECT MAX(e.fetched_at) FROM evidence_cache e
          WHERE e.user_id = d.user_id AND e.evidence_type = 'citizen') AS last_citizen_check
  FROM decision_history d
  WHERE d.status = 'fail';
  ```

- **Self-Joins for Decision Comparison:**
  ```sql
  SELECT curr.id, curr.user_id, curr.status AS current_status, prev.status AS previous_status
  FROM decision_history curr
  LEFT JOIN decision_history prev
    ON curr.user_id = prev.user_id
    AND curr.purpose = prev.purpose
    AND prev.evaluated_at = (
      SELECT MAX(evaluated_at) FROM decision_history
      WHERE user_id = curr.user_id AND purpose = curr.purpose AND evaluated_at < curr.evaluated_at
    )
  WHERE curr.status != COALESCE(prev.status, curr.status);
  ```

**Database Design:**

- **Normalized Rule Tables (3NF):** Separate `decision_rules`, `rule_conditions`, `rule_actions` tables with foreign key constraints
- **Covering Indexes:** Composite indexes on `(user_id, purpose, evaluated_at)` verified via `EXPLAIN ANALYZE`
- **Partitioning:** Decision history partitioned by month using range partitioning for efficient time-based queries
- **Foreign Key Constraints:** `ON DELETE RESTRICT` for rule references to prevent orphaned conditions

---

**SQL Indexing Enhancements (from "Use The Index, Luke"):**

**Join Strategy Comparison for Rule Resolution:**

```sql
-- WHY THIS MATTERS: Rule chain queries can use different join strategies.
-- Understanding when PostgreSQL chooses Nested Loop vs Hash Join helps optimization.

-- Nested Loop Join (good for small outer + indexed inner):
-- EXPLAIN shows: "Nested Loop" when inner table is small and indexed
SET enable_hashjoin = OFF;
EXPLAIN ANALYZE
SELECT r.*, rc.condition_type
FROM decision_rules r
JOIN rule_conditions rc ON r.id = rc.rule_id
WHERE r.purpose = 'age_verification';
-- Works well when: r filtered to few rows, rc has index on (rule_id)

-- Hash Join (good for large tables without index on join key):
SET enable_nestloop = OFF;
EXPLAIN ANALYZE
SELECT r.*, rc.condition_type
FROM decision_rules r
JOIN rule_conditions rc ON r.id = rc.rule_id;
-- Works well when: both tables are large, no filtering

-- For rule chains: Nested Loop is typically better because:
-- 1. Rules are filtered by purpose/status (small result set)
-- 2. Rule conditions indexed by rule_id
-- 3. Recursive CTEs build small working sets per iteration
```

**Index Design for Decision History (High-Write Table):**

```sql
-- WHY THIS MATTERS: decision_history receives an INSERT for every evaluation.
-- Too many indexes slow down writes. Choose indexes carefully.

-- ANTI-PATTERN: Over-indexing high-write table
CREATE INDEX idx_dh_user ON decision_history (user_id);
CREATE INDEX idx_dh_purpose ON decision_history (purpose);
CREATE INDEX idx_dh_status ON decision_history (status);
CREATE INDEX idx_dh_evaluated ON decision_history (evaluated_at);
-- 4 indexes = 4x write overhead for every INSERT

-- SOLUTION: Minimal indexes covering actual query patterns
CREATE INDEX idx_dh_user_purpose_time ON decision_history (user_id, purpose, evaluated_at DESC);
-- Covers: user history, user+purpose history, recent decisions by user
-- Single index serves multiple query patterns

-- For analytics queries (infrequent), use the composite index:
SELECT * FROM decision_history
WHERE user_id = :uid AND purpose = 'age_verification'
ORDER BY evaluated_at DESC LIMIT 10;
-- Uses: idx_dh_user_purpose_time (one index scan)
```

**EXPLAIN ANALYZE Evidence for Rule Queries:**

```sql
-- Verify recursive CTE uses index for each iteration:
EXPLAIN (ANALYZE, BUFFERS)
WITH RECURSIVE rule_chain AS (
  SELECT id, parent_id, rule_name, 1 AS depth
  FROM decision_rules WHERE id = :root_rule_id
  UNION ALL
  SELECT r.id, r.parent_id, r.rule_name, rc.depth + 1
  FROM decision_rules r
  JOIN rule_chain rc ON r.parent_id = rc.id
  WHERE rc.depth < 10
)
SELECT * FROM rule_chain ORDER BY depth;

-- Look for:
-- "Index Scan on decision_rules" at each recursion level
-- NOT: "Seq Scan on decision_rules"
-- Buffers: shared hit > read (cache efficiency)

-- Verify decision history query uses composite index:
EXPLAIN (ANALYZE, BUFFERS)
SELECT user_id, purpose, status, evaluated_at
FROM decision_history
WHERE user_id = :uid AND purpose = 'age_verification'
ORDER BY evaluated_at DESC
LIMIT 10;

-- Expected:
-- "Index Scan Backward using idx_dh_user_purpose_time"
-- Limit does not require reading all matching rows
```

---

**Acceptance Criteria (SQL):**

- [ ] Rule chain resolution uses recursive CTE with depth limit
- [ ] Decision analytics queries use window functions for trend analysis
- [ ] Status aggregation uses CASE with GROUP BY/HAVING
- [ ] Evidence freshness checks use correlated subqueries
- [ ] Decision comparison uses self-joins
- [ ] **NEW:** Recursive CTE shows "Index Scan" for each iteration in EXPLAIN ANALYZE
- [ ] **NEW:** Decision history uses single composite index (not multiple single-column)
- [ ] **NEW:** Join strategy appropriate for query size (Nested Loop for filtered, Hash for bulk)
- [ ] **NEW:** INSERT latency for decision_history <10ms p99 under load

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
- [ ] Evidence gathering runs registry + VC lookups in parallel with shared context cancellation and traces/metrics per source
- [ ] Decision passes with conditions for users without VCs
- [ ] All decisions emit audit events with outcome
- [ ] Evidence gathering handles registry errors gracefully
- [ ] Derived identity contains no PII
- [ ] Code passes tests and lint
- [ ] Rule graph evaluated via DAG topological sort with cycle detection and memoization; complexity and cache eviction documented
- [ ] Rules persisted in normalized, versioned tables with immutability constraints and `CHECK` bounds; indexes validated with EXPLAIN
- [ ] Policy bundles are signed/immutable with audit on publish

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

| Version | Date       | Author       | Changes                                                                                    |
| ------- | ---------- | ------------ | ------------------------------------------------------------------------------------------ |
| 1.6     | 2025-12-21 | Engineering  | Enhanced TR-7: Added join strategy comparison, index design for high-write tables, EXPLAIN |
| 1.5     | 2025-12-21 | Engineering  | Added TR-7: SQL Query Patterns (CTEs, window functions, CASE, subqueries, self-joins, 3NF) |
| 1.4     | 2025-12-18 | Security Eng | Added DSA/SQL requirements for rule DAGs and normalized, immutable rule storage            |
| 1.3     | 2025-12-18 | Security Eng | Added secure-by-design evaluation (DAG, default-deny, signed policy bundles)               |
| 1.2     | 2025-12-16 | Engineering  | Add concurrent evidence-gathering requirements and acceptance criteria                     |
| 1.1     | 2025-12-12 | Engineering  | Add TR-5 CQRS & Read-Optimized Projections                                                 |
| 1.0     | 2025-12-03 | Product Team | Initial PRD                                                                                |
