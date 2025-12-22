# PRD-037: Multi-Party Authorization (Maker-Checker)

**Status:** Not Started
**Priority:** P1 (High - Banking/Fintech)
**Owner:** Engineering Team
**Dependencies:** PRD-036 (Legal Entity Identity), PRD-021 (MFA), PRD-027 (Adaptive Auth), PRD-006 (Audit)
**Phase:** 8 (Banking Identity Pack)
**Last Updated:** 2025-12-22

---

## 1. Overview

### Problem Statement

High-value or sensitive actions in banking require more than single-user approval. Regulations and corporate governance demand:
- **Maker-Checker**: One person initiates, another approves
- **Multi-Signature**: N of M approvers required (e.g., 2 of 3 directors)
- **Hierarchical Approval**: Escalation based on amount or risk
- **Time-Bound Approval**: Requests expire if not acted upon

Current Credo supports single-user authentication and consent. For banking identity gateway use cases, we need **authorization requests** as a first-class primitive.

### Goals

- Model **authorization requests** with configurable approval rules
- Support **maker-checker** (1 initiator + 1 approver)
- Support **M-of-N approval** (2 of 3 directors)
- Enforce **approval rules** based on entity/role (PRD-036)
- Integrate with **SCA** (PRD-039) for approver authentication
- Provide **non-repudiation** via signed approval records
- Enable **policy-driven rules** (via PRD-015/PRD-027)

### Non-Goals

- Workflow orchestration beyond approval (no multi-step business processes)
- Approval routing/assignment (who should approve is determined by rules, not UI)
- Real-time collaboration/chat during approval
- Approval delegation (covered in PRD-038)

---

## 2. User Stories

**As a company CFO**
**I want to** require two directors to approve transfers over €50,000
**So that** we have proper financial controls

**As a compliance officer**
**I want to** see who approved each high-value transaction
**So that** we have a clear audit trail for regulators

**As a finance team member**
**I want to** initiate a payment and have it queued for approval
**So that** I can prepare payments in advance

**As a director**
**I want to** see pending approvals and approve from my mobile
**So that** I don't block business operations

**As an auditor**
**I want to** verify the cryptographic proof of each approval
**So that** I can confirm approvals weren't forged

---

## 3. Functional Requirements

### FR-1: Authorization Request Model

**Request Types:**

| Type | Description | Default Rule |
|------|-------------|--------------|
| `transfer` | Payment/transfer approval | Amount-based thresholds |
| `beneficiary_add` | New payment recipient | Maker-checker |
| `card_create` | Issue new card | Maker-checker |
| `card_limit_change` | Modify card limits | Amount-based |
| `user_invite` | Add team member | Manager approval |
| `settings_change` | Sensitive settings | Director approval |
| `contract_sign` | Legal agreement | M-of-N directors |

**Request Status:**

```go
type RequestStatus string

const (
    RequestStatusPending   RequestStatus = "pending"    // Awaiting approvals
    RequestStatusApproved  RequestStatus = "approved"   // All approvals received
    RequestStatusDenied    RequestStatus = "denied"     // Explicitly rejected
    RequestStatusExpired   RequestStatus = "expired"    // Timeout without approval
    RequestStatusCancelled RequestStatus = "cancelled"  // Initiator cancelled
    RequestStatusExecuted  RequestStatus = "executed"   // Action completed
)
```

### FR-2: Approval Rules

**Rule Types:**

```go
type ApprovalRule struct {
    ID          id.RuleID
    EntityID    *id.EntityID       // Entity-specific or global
    TenantID    id.TenantID
    RequestType RequestType
    Name        string
    Conditions  []RuleCondition    // When rule applies
    Requirement ApprovalRequirement
    Priority    int                // Higher = evaluated first
    Enabled     bool
}

type RuleCondition struct {
    Field    string      // amount, currency, beneficiary_new, etc.
    Operator string      // gt, gte, lt, lte, eq, in
    Value    interface{} // 50000, "EUR", true, ["DE", "FR"]
}

type ApprovalRequirement struct {
    Type       RequirementType  // any_of, all_of, m_of_n
    Count      int              // For m_of_n: how many needed
    Approvers  ApproverSpec     // Who can approve
    TimeoutMin int              // Request expiry (minutes)
}

type ApproverSpec struct {
    Roles       []RepresentationRole // director, signatory
    Powers      []Power              // approve_transfers
    UserIDs     []id.UserID          // Specific users (optional)
    ExcludeInitiator bool            // Maker can't be checker
}
```

**Example Rules:**

```json
[
  {
    "name": "Standard Transfer Approval",
    "request_type": "transfer",
    "conditions": [
      {"field": "amount", "operator": "gte", "value": 10000},
      {"field": "amount", "operator": "lt", "value": 50000}
    ],
    "requirement": {
      "type": "any_of",
      "count": 1,
      "approvers": {
        "powers": ["approve_transfers"],
        "exclude_initiator": true
      },
      "timeout_min": 1440
    }
  },
  {
    "name": "High-Value Transfer Approval",
    "request_type": "transfer",
    "conditions": [
      {"field": "amount", "operator": "gte", "value": 50000}
    ],
    "requirement": {
      "type": "m_of_n",
      "count": 2,
      "approvers": {
        "roles": ["director"],
        "exclude_initiator": true
      },
      "timeout_min": 2880
    }
  },
  {
    "name": "New Beneficiary Approval",
    "request_type": "beneficiary_add",
    "conditions": [],
    "requirement": {
      "type": "any_of",
      "count": 1,
      "approvers": {
        "powers": ["manage_beneficiaries"],
        "exclude_initiator": true
      },
      "timeout_min": 4320
    }
  }
]
```

### FR-3: Create Authorization Request

**Endpoint:** `POST /authz/requests`

**Description:** Initiate an action that requires approval.

**Input:**

```json
{
  "entity_id": "ent_abc123",
  "request_type": "transfer",
  "action_data": {
    "amount": 75000,
    "currency": "EUR",
    "beneficiary_id": "ben_xyz789",
    "beneficiary_name": "Supplier GmbH",
    "reference": "INV-2025-001"
  },
  "urgency": "normal",
  "notes": "Q4 invoice payment"
}
```

**Output (Success - 201):**

```json
{
  "request_id": "req_def456",
  "entity_id": "ent_abc123",
  "request_type": "transfer",
  "status": "pending",
  "initiated_by": "user_alice123",
  "initiated_at": "2025-12-22T10:00:00Z",
  "expires_at": "2025-12-24T10:00:00Z",
  "approval_rule": {
    "name": "High-Value Transfer Approval",
    "type": "m_of_n",
    "required_count": 2,
    "approver_roles": ["director"]
  },
  "approvals": [],
  "approvals_needed": 2
}
```

**Business Logic:**

1. Validate initiator has representation for entity
2. Validate initiator has power to initiate this request type
3. Find matching approval rule (highest priority match)
4. If no rule matches, check if type requires approval (fail-safe)
5. Create request with `pending` status
6. Calculate expiry based on rule timeout
7. Notify eligible approvers (via PRD-018)
8. Emit audit event `authz.request_created`

### FR-4: List Pending Requests

**Endpoint:** `GET /authz/requests`

**Query Parameters:**
- `entity_id` - Filter by entity
- `status` - pending, approved, denied, expired
- `request_type` - transfer, beneficiary_add, etc.
- `awaiting_my_approval` - Only requests user can approve

**Output:**

```json
{
  "requests": [
    {
      "request_id": "req_def456",
      "request_type": "transfer",
      "status": "pending",
      "initiated_by": "Alice Smith",
      "initiated_at": "2025-12-22T10:00:00Z",
      "expires_at": "2025-12-24T10:00:00Z",
      "summary": "Transfer €75,000 to Supplier GmbH",
      "approvals_received": 1,
      "approvals_needed": 2,
      "can_approve": true
    }
  ],
  "total": 1
}
```

### FR-5: Submit Approval

**Endpoint:** `POST /authz/requests/{request_id}/approve`

**Description:** Approve a pending request. Requires SCA.

**Input:**

```json
{
  "decision": "approve",
  "notes": "Verified against PO-2025-042",
  "sca_token": "stepup_xyz789"
}
```

**Output (Success - 200):**

```json
{
  "request_id": "req_def456",
  "status": "approved",
  "approval": {
    "approver_id": "user_bob456",
    "approver_name": "Bob Jones",
    "role": "director",
    "decision": "approve",
    "timestamp": "2025-12-22T11:30:00Z",
    "signature": "eyJhbGciOiJFUzI1NiIs..."
  },
  "approvals_received": 2,
  "approvals_needed": 2,
  "final_status": "approved",
  "ready_for_execution": true
}
```

**Business Logic:**

1. Validate request exists and is pending
2. Validate request hasn't expired
3. Validate approver has representation for entity
4. Validate approver meets rule requirements (role/power)
5. Validate approver isn't initiator (if exclude_initiator)
6. Validate approver hasn't already approved
7. Validate SCA token (PRD-039)
8. Generate cryptographic signature for approval
9. Store approval record
10. Check if approval threshold met
11. If met, update status to `approved`
12. Emit audit event `authz.approval_submitted`
13. Notify initiator of status change

### FR-6: Deny Request

**Endpoint:** `POST /authz/requests/{request_id}/deny`

**Input:**

```json
{
  "reason": "Beneficiary not in approved vendor list",
  "sca_token": "stepup_xyz789"
}
```

**Business Logic:**

1. Validate denier has approval authority
2. Set status to `denied`
3. Record reason and denier
4. Emit audit event `authz.request_denied`
5. Notify initiator

**Note:** Single denial by any eligible approver denies the entire request.

### FR-7: Cancel Request

**Endpoint:** `POST /authz/requests/{request_id}/cancel`

**Description:** Initiator cancels their own request.

**Input:**

```json
{
  "reason": "No longer needed - duplicate payment"
}
```

### FR-8: Execute Approved Request

**Endpoint:** `POST /authz/requests/{request_id}/execute`

**Description:** Mark request as executed after downstream action completes.

**Input:**

```json
{
  "execution_reference": "txn_abc123",
  "executed_at": "2025-12-22T12:00:00Z"
}
```

**Note:** This is called by the system after the actual action (e.g., payment) is performed. The authorization request tracks approval; execution is recorded for audit completeness.

### FR-9: Non-Repudiation Signatures

Each approval is cryptographically signed:

```go
type ApprovalSignature struct {
    RequestID    id.RequestID
    ApproverID   id.UserID
    Decision     string        // approve, deny
    Timestamp    time.Time
    ActionDigest string        // SHA-256 of action_data
    Signature    string        // ECDSA signature
    PublicKeyRef string        // Key identifier for verification
}
```

**Signature Payload:**

```json
{
  "request_id": "req_def456",
  "approver_id": "user_bob456",
  "decision": "approve",
  "timestamp": "2025-12-22T11:30:00Z",
  "action_digest": "sha256:abc123..."
}
```

---

## 4. Technical Requirements

### TR-1: Data Models

```go
// internal/authz/models.go

type AuthorizationRequest struct {
    ID            id.RequestID
    EntityID      id.EntityID
    TenantID      id.TenantID
    RequestType   RequestType
    Status        RequestStatus
    InitiatedBy   id.UserID
    InitiatedAt   time.Time
    ExpiresAt     time.Time
    ActionData    map[string]interface{}  // Type-specific payload
    ActionDigest  string                  // SHA-256 for signature verification
    ApprovalRule  *ApprovalRule           // Snapshot of rule at creation
    Urgency       Urgency
    Notes         *string
    Approvals     []Approval
    DeniedBy      *id.UserID
    DeniedAt      *time.Time
    DeniedReason  *string
    CancelledBy   *id.UserID
    CancelledAt   *time.Time
    CancelledReason *string
    ExecutedAt    *time.Time
    ExecutionRef  *string
    CreatedAt     time.Time
    UpdatedAt     time.Time
}

type Approval struct {
    ID           id.ApprovalID
    RequestID    id.RequestID
    ApproverID   id.UserID
    Role         RepresentationRole
    Decision     ApprovalDecision  // approve, deny
    Notes        *string
    Timestamp    time.Time
    SCAMethod    string            // totp, passkey, paired_device
    Signature    string            // ECDSA signature
    PublicKeyRef string
}

func (r *AuthorizationRequest) ApprovalsNeeded() int {
    if r.ApprovalRule == nil {
        return 1
    }
    return r.ApprovalRule.Requirement.Count
}

func (r *AuthorizationRequest) ApprovalsReceived() int {
    count := 0
    for _, a := range r.Approvals {
        if a.Decision == ApprovalDecisionApprove {
            count++
        }
    }
    return count
}

func (r *AuthorizationRequest) IsFullyApproved() bool {
    return r.ApprovalsReceived() >= r.ApprovalsNeeded()
}

func (r *AuthorizationRequest) IsExpired() bool {
    return time.Now().After(r.ExpiresAt)
}
```

### TR-2: Store Interfaces

```go
type AuthorizationRequestStore interface {
    Save(ctx context.Context, req *AuthorizationRequest) error
    FindByID(ctx context.Context, id id.RequestID) (*AuthorizationRequest, error)
    FindByEntity(ctx context.Context, entityID id.EntityID, filter RequestFilter) ([]AuthorizationRequest, error)
    FindPendingForApprover(ctx context.Context, userID id.UserID, entityID *id.EntityID) ([]AuthorizationRequest, error)
    Update(ctx context.Context, req *AuthorizationRequest) error
    AddApproval(ctx context.Context, approval *Approval) error
    ExpirePending(ctx context.Context) (int, error)  // Background job
}

type ApprovalRuleStore interface {
    Save(ctx context.Context, rule *ApprovalRule) error
    FindByID(ctx context.Context, id id.RuleID) (*ApprovalRule, error)
    FindByEntityAndType(ctx context.Context, entityID id.EntityID, reqType RequestType) ([]ApprovalRule, error)
    FindGlobalByType(ctx context.Context, tenantID id.TenantID, reqType RequestType) ([]ApprovalRule, error)
    Update(ctx context.Context, rule *ApprovalRule) error
    Delete(ctx context.Context, id id.RuleID) error
}
```

### TR-3: Service Layer

```go
type AuthorizationService struct {
    requests       AuthorizationRequestStore
    rules          ApprovalRuleStore
    representations RepresentationStore  // PRD-036
    sca            SCAService            // PRD-039
    notifications  NotificationService   // PRD-018
    signer         ApprovalSigner
    auditor        audit.Publisher
}

func (s *AuthorizationService) CreateRequest(ctx context.Context, req CreateRequestInput) (*AuthorizationRequest, error)
func (s *AuthorizationService) ListRequests(ctx context.Context, filter RequestFilter) ([]AuthorizationRequest, error)
func (s *AuthorizationService) GetRequest(ctx context.Context, id id.RequestID) (*AuthorizationRequest, error)
func (s *AuthorizationService) SubmitApproval(ctx context.Context, req SubmitApprovalInput) (*AuthorizationRequest, error)
func (s *AuthorizationService) DenyRequest(ctx context.Context, req DenyRequestInput) (*AuthorizationRequest, error)
func (s *AuthorizationService) CancelRequest(ctx context.Context, id id.RequestID, reason string) error
func (s *AuthorizationService) MarkExecuted(ctx context.Context, id id.RequestID, ref string) error

// Rule management
func (s *AuthorizationService) CreateRule(ctx context.Context, rule *ApprovalRule) error
func (s *AuthorizationService) UpdateRule(ctx context.Context, rule *ApprovalRule) error
func (s *AuthorizationService) DeleteRule(ctx context.Context, id id.RuleID) error
func (s *AuthorizationService) EvaluateRules(ctx context.Context, entityID id.EntityID, reqType RequestType, actionData map[string]interface{}) (*ApprovalRule, error)
```

### TR-4: Background Jobs

```go
// Expire pending requests
func (s *AuthorizationService) ExpirePendingRequests(ctx context.Context) error {
    count, err := s.requests.ExpirePending(ctx)
    if err != nil {
        return err
    }
    if count > 0 {
        s.auditor.Emit(ctx, audit.Event{
            Action: "authz.requests_expired",
            Metadata: map[string]interface{}{"count": count},
        })
    }
    return nil
}

// Send reminders for pending requests approaching expiry
func (s *AuthorizationService) SendExpiryReminders(ctx context.Context) error
```

### TR-5: Approval Signing

```go
type ApprovalSigner interface {
    Sign(ctx context.Context, payload ApprovalPayload) (signature string, keyRef string, error)
    Verify(ctx context.Context, payload ApprovalPayload, signature string, keyRef string) (bool, error)
}

type ApprovalPayload struct {
    RequestID    id.RequestID
    ApproverID   id.UserID
    Decision     string
    Timestamp    time.Time
    ActionDigest string
}

// Implementation using ECDSA P-256
type ECDSASigner struct {
    keyStore KeyStore
}
```

---

## 5. API Specifications

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/authz/requests` | POST | Bearer | Create authorization request |
| `/authz/requests` | GET | Bearer | List requests (with filters) |
| `/authz/requests/{id}` | GET | Bearer | Get request details |
| `/authz/requests/{id}/approve` | POST | Bearer+SCA | Submit approval |
| `/authz/requests/{id}/deny` | POST | Bearer+SCA | Deny request |
| `/authz/requests/{id}/cancel` | POST | Bearer | Cancel own request |
| `/authz/requests/{id}/execute` | POST | Service | Mark as executed |
| `/authz/rules` | GET | Admin | List approval rules |
| `/authz/rules` | POST | Admin | Create rule |
| `/authz/rules/{id}` | PUT | Admin | Update rule |
| `/authz/rules/{id}` | DELETE | Admin | Delete rule |

---

## 6. Security Requirements

### SR-1: Authorization Checks
- Initiator must have representation + initiation power
- Approvers must have representation + approval power
- Initiator cannot approve own request (configurable)
- All approvals require valid SCA

### SR-2: Non-Repudiation
- All approvals cryptographically signed
- Signatures verifiable offline
- Action data hashed and included in signature

### SR-3: Request Integrity
- Action data immutable after creation
- Rule snapshot stored with request (rule changes don't affect pending)
- Status transitions validated (no skipping states)

### SR-4: Time Sensitivity
- Requests expire per rule configuration
- Expired requests cannot be approved
- Clock skew tolerance: 30 seconds

---

## 7. Observability

### Metrics

```
# Counter: Requests created by type
authz_requests_created_total{entity_id, request_type}

# Counter: Request outcomes
authz_requests_completed_total{request_type, outcome="approved|denied|expired|cancelled"}

# Histogram: Time to approval
authz_approval_duration_seconds{request_type}

# Gauge: Pending requests
authz_requests_pending{entity_id, request_type}

# Counter: Approvals submitted
authz_approvals_submitted_total{decision="approve|deny"}
```

### Audit Events

- `authz.request_created` - New request initiated
- `authz.approval_submitted` - Approval/denial recorded
- `authz.request_approved` - Request fully approved
- `authz.request_denied` - Request denied
- `authz.request_expired` - Request auto-expired
- `authz.request_cancelled` - Request cancelled by initiator
- `authz.request_executed` - Downstream action completed
- `authz.rule_created` - New approval rule
- `authz.rule_updated` - Rule modified
- `authz.rule_deleted` - Rule removed

---

## 8. Acceptance Criteria

- [ ] Authorization requests can be created for defined types
- [ ] Approval rules evaluated based on conditions (amount, type)
- [ ] M-of-N approval logic works correctly
- [ ] Initiator exclusion enforced when configured
- [ ] SCA required for all approval actions
- [ ] Cryptographic signatures generated and verifiable
- [ ] Requests expire after timeout
- [ ] Notifications sent to eligible approvers
- [ ] Audit trail complete for all state changes
- [ ] Admin can configure approval rules per entity

---

## 9. Implementation Steps

### Phase 1: Foundation (6-8 hours)
1. Domain models for requests, approvals, rules
2. Store implementations
3. Basic create/get/list endpoints
4. Unit tests

### Phase 2: Approval Logic (4-6 hours)
1. Rule evaluation engine
2. Approval submission with validation
3. M-of-N threshold logic
4. Status transitions

### Phase 3: Security Layer (4-6 hours)
1. SCA integration (PRD-039)
2. Approval signing
3. Signature verification endpoint
4. Initiator exclusion logic

### Phase 4: Notifications & Jobs (3-4 hours)
1. Approver notification on request creation
2. Status change notifications
3. Expiry background job
4. Reminder job

### Phase 5: Admin & Rules (3-4 hours)
1. Rule CRUD endpoints
2. Rule condition evaluation
3. Per-entity rule configuration
4. E2E tests

---

## 10. Future Enhancements

- Approval escalation (auto-escalate if no response)
- Conditional approval (approve with modifications)
- Approval templates (pre-configured rule sets)
- Batch approval (approve multiple requests)
- Approval analytics dashboard
- Mobile push notifications for approvals
- Integration with external approval systems

---

## 11. References

- [PSD2 Strong Customer Authentication](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018R0389)
- [ISO 20022 Payment Standards](https://www.iso20022.org/)
- PRD-036: Legal Entity Identity
- PRD-039: SCA Orchestration
- PRD-021: Multi-Factor Authentication

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-22 | Engineering | Initial PRD |
