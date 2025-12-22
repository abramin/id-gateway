# PRD-038: Delegated Authority (Power of Attorney)

**Status:** Not Started
**Priority:** P1 (High - Banking/Fintech)
**Owner:** Engineering Team
**Dependencies:** PRD-036 (Legal Entity Identity), PRD-037 (Multi-Party Auth), PRD-021 (MFA), PRD-006 (Audit)
**Phase:** 8 (Banking Identity Pack)
**Last Updated:** 2025-12-22

---

## 1. Overview

### Problem Statement

Real-world banking involves people acting on behalf of others:
- **Vacation coverage**: "While I'm away, my colleague can approve up to €5,000"
- **Accountant access**: "My accountant can view transactions but not transfer"
- **Spouse/family**: "My partner can manage our joint account expenses"
- **Legal guardianship**: "I manage finances for my elderly parent"
- **Corporate proxy**: "I'm authorized to act for the CEO during Q4"

PRD-036 covers **entity → user representation** (who can act for a company). This PRD covers **user → user delegation** (one person granting authority to another person).

### Goals

- Model **delegations** as user-to-user authority grants
- Support **scoped powers** (what the delegate can do)
- Support **constraints** (amount limits, time bounds, specific resources)
- Require **grantor consent** for delegation creation
- Enable **revocation** at any time by grantor
- Integrate with authorization checks (PRD-037)
- Provide **audit trail** for all delegated actions

### Non-Goals

- Cascading delegation (delegate cannot re-delegate)
- Legal power of attorney document generation
- Court-appointed guardianship verification
- Delegation marketplaces or discovery

---

## 2. User Stories

**As a business owner**
**I want to** grant my accountant authority to view transactions and initiate small payments
**So that** they can manage day-to-day finances while I focus on the business

**As a senior employee**
**I want to** delegate my approval authority to a colleague while on vacation
**So that** business operations aren't blocked by my absence

**As a delegate**
**I want to** see clearly what actions I can take on someone's behalf
**So that** I don't accidentally exceed my authority

**As a grantor**
**I want to** revoke delegation immediately if needed
**So that** I maintain control over my authority

**As a compliance officer**
**I want to** see when actions were taken under delegation
**So that** I can distinguish delegated from direct actions in audits

---

## 3. Functional Requirements

### FR-1: Delegation Model

**Delegation** grants a grantee (delegate) authority to act on behalf of a grantor within defined scope.

```go
type Delegation struct {
    ID            id.DelegationID
    TenantID      id.TenantID
    GrantorID     id.UserID         // Who grants authority
    GranteeID     id.UserID         // Who receives authority
    EntityID      *id.EntityID      // Optional: scope to specific entity
    Scope         DelegationScope
    Constraints   *DelegationConstraints
    Status        DelegationStatus  // active, suspended, revoked, expired
    RequiresSCA   bool              // Delegate must SCA for actions
    ValidFrom     time.Time
    ValidUntil    *time.Time
    CreatedAt     time.Time
    RevokedAt     *time.Time
    RevokedBy     *id.UserID
    RevokedReason *string
}

type DelegationScope struct {
    Powers        []Power           // What can they do
    ResourceTypes []string          // Optional: specific resource types
    ResourceIDs   []string          // Optional: specific resource IDs
}

type DelegationConstraints struct {
    AmountLimit   *AmountLimit      // Max per transaction/day/month
    TimeWindow    *TimeWindow       // e.g., business hours only
    RequiresNote  bool              // Must provide reason for each action
    MaxActions    *int              // Total action limit
}
```

### FR-2: Create Delegation

**Endpoint:** `POST /delegations`

**Description:** Grant authority to another user.

**Input:**

```json
{
  "grantee_id": "user_bob456",
  "entity_id": "ent_abc123",
  "scope": {
    "powers": ["view_transactions", "initiate_transfers"],
    "resource_types": ["bank_account"]
  },
  "constraints": {
    "amount_limit": {
      "max_single": 5000,
      "max_daily": 10000,
      "currency": "EUR"
    },
    "time_window": {
      "days": ["monday", "tuesday", "wednesday", "thursday", "friday"],
      "start_hour": 9,
      "end_hour": 18,
      "timezone": "Europe/Berlin"
    }
  },
  "requires_sca": true,
  "valid_from": "2025-12-23T00:00:00Z",
  "valid_until": "2026-01-07T00:00:00Z",
  "notes": "Vacation coverage - Bob can handle small payments"
}
```

**Output (Success - 201):**

```json
{
  "delegation_id": "del_xyz789",
  "grantor_id": "user_alice123",
  "grantee_id": "user_bob456",
  "entity_id": "ent_abc123",
  "status": "active",
  "scope": {
    "powers": ["view_transactions", "initiate_transfers"]
  },
  "constraints": {
    "amount_limit": {
      "max_single": 5000,
      "max_daily": 10000,
      "currency": "EUR"
    }
  },
  "valid_from": "2025-12-23T00:00:00Z",
  "valid_until": "2026-01-07T00:00:00Z",
  "created_at": "2025-12-22T10:00:00Z"
}
```

**Business Logic:**

1. Validate grantor is authenticated user
2. Validate grantee exists and is active
3. Validate grantor has the powers they're delegating
4. Validate grantor can delegate (has `can_delegate` flag or power)
5. If entity_id provided, validate grantor has representation
6. Check for conflicting delegations
7. Create delegation with `active` status
8. Emit audit event `delegation.created`
9. Notify grantee of new delegation

### FR-3: List Delegations

**Endpoint:** `GET /delegations`

**Query Parameters:**
- `as` - "grantor" or "grantee" (required)
- `status` - active, expired, revoked
- `entity_id` - Filter by entity

**Output (as grantor):**

```json
{
  "delegations": [
    {
      "delegation_id": "del_xyz789",
      "grantee_id": "user_bob456",
      "grantee_name": "Bob Jones",
      "entity_id": "ent_abc123",
      "entity_name": "Acme GmbH",
      "status": "active",
      "powers": ["view_transactions", "initiate_transfers"],
      "valid_until": "2026-01-07T00:00:00Z",
      "can_revoke": true
    }
  ],
  "total": 1
}
```

**Output (as grantee):**

```json
{
  "delegations": [
    {
      "delegation_id": "del_xyz789",
      "grantor_id": "user_alice123",
      "grantor_name": "Alice Smith",
      "entity_id": "ent_abc123",
      "entity_name": "Acme GmbH",
      "status": "active",
      "powers": ["view_transactions", "initiate_transfers"],
      "constraints": {
        "amount_limit": {"max_single": 5000, "currency": "EUR"}
      },
      "valid_until": "2026-01-07T00:00:00Z"
    }
  ],
  "total": 1
}
```

### FR-4: Check Delegation Authority

**Endpoint:** `POST /delegations/check`

**Description:** Check if a user can act on behalf of another user.

**Input:**

```json
{
  "grantee_id": "user_bob456",
  "grantor_id": "user_alice123",
  "entity_id": "ent_abc123",
  "power": "initiate_transfers",
  "context": {
    "amount": 3000,
    "currency": "EUR",
    "action_time": "2025-12-26T14:30:00Z"
  }
}
```

**Output (Allowed):**

```json
{
  "allowed": true,
  "delegation_id": "del_xyz789",
  "acting_as": {
    "grantor_id": "user_alice123",
    "grantor_name": "Alice Smith"
  },
  "constraints_evaluated": {
    "amount_within_limit": true,
    "time_within_window": true
  }
}
```

**Output (Denied):**

```json
{
  "allowed": false,
  "reason": "amount_exceeds_limit",
  "delegation_id": "del_xyz789",
  "constraint_violated": {
    "type": "amount_limit",
    "limit": 5000,
    "requested": 7500,
    "currency": "EUR"
  }
}
```

### FR-5: Revoke Delegation

**Endpoint:** `POST /delegations/{id}/revoke`

**Description:** Grantor revokes delegation immediately.

**Input:**

```json
{
  "reason": "No longer needed - returned from vacation"
}
```

**Output (Success - 200):**

```json
{
  "delegation_id": "del_xyz789",
  "status": "revoked",
  "revoked_at": "2025-12-22T16:00:00Z",
  "revoked_by": "user_alice123"
}
```

**Business Logic:**

1. Validate requester is grantor (or admin)
2. Validate delegation is active
3. Set status to `revoked`
4. Record revocation timestamp and reason
5. Emit audit event `delegation.revoked`
6. Notify grantee

### FR-6: Acting Under Delegation

When a user acts under delegation, the system must:

1. **Identify the delegation** - User specifies or system infers
2. **Validate the delegation** - Check status, expiry, constraints
3. **Require SCA if configured** - Step-up auth for delegate
4. **Execute action** - With grantor's authority
5. **Record the delegation** - Audit trail shows delegated action

**Request Header:**

```
X-Acting-As: user_alice123
X-Delegation-ID: del_xyz789
```

**Audit Event:**

```json
{
  "event": "transfer.initiated",
  "actor_id": "user_bob456",
  "acting_as": "user_alice123",
  "delegation_id": "del_xyz789",
  "entity_id": "ent_abc123",
  "action_data": {
    "amount": 3000,
    "currency": "EUR"
  },
  "timestamp": "2025-12-26T14:30:00Z"
}
```

### FR-7: Delegation Notifications

| Event | Notify |
|-------|--------|
| Delegation created | Grantee |
| Delegation revoked | Grantee |
| Delegation expiring (24h) | Grantor, Grantee |
| Delegation expired | Grantor, Grantee |
| Action under delegation | Grantor (configurable) |

---

## 4. Technical Requirements

### TR-1: Data Models

```go
// internal/delegation/models.go

type Delegation struct {
    ID            id.DelegationID
    TenantID      id.TenantID
    GrantorID     id.UserID
    GranteeID     id.UserID
    EntityID      *id.EntityID
    Scope         DelegationScope
    Constraints   *DelegationConstraints
    Status        DelegationStatus
    RequiresSCA   bool
    NotifyGrantor bool              // Notify on each delegated action
    ValidFrom     time.Time
    ValidUntil    *time.Time
    ActionsCount  int               // Track usage
    CreatedAt     time.Time
    RevokedAt     *time.Time
    RevokedBy     *id.UserID
    RevokedReason *string
}

type DelegationStatus string

const (
    DelegationStatusPending   DelegationStatus = "pending"   // Awaiting grantee acceptance
    DelegationStatusActive    DelegationStatus = "active"
    DelegationStatusSuspended DelegationStatus = "suspended"
    DelegationStatusRevoked   DelegationStatus = "revoked"
    DelegationStatusExpired   DelegationStatus = "expired"
)

type DelegationScope struct {
    Powers        []Power
    ResourceTypes []string
    ResourceIDs   []string
}

type DelegationConstraints struct {
    AmountLimit   *AmountLimit
    TimeWindow    *TimeWindow
    RequiresNote  bool
    MaxActions    *int
}

type AmountLimit struct {
    MaxSingle   int64
    MaxDaily    int64
    MaxMonthly  int64
    Currency    string
    UsedToday   int64   // Tracked for daily limit
    UsedMonth   int64   // Tracked for monthly limit
}

type TimeWindow struct {
    Days      []string  // monday, tuesday, etc.
    StartHour int       // 0-23
    EndHour   int       // 0-23
    Timezone  string    // IANA timezone
}

func (d *Delegation) IsValid(now time.Time) bool {
    if d.Status != DelegationStatusActive {
        return false
    }
    if now.Before(d.ValidFrom) {
        return false
    }
    if d.ValidUntil != nil && now.After(*d.ValidUntil) {
        return false
    }
    return true
}

func (d *Delegation) CheckConstraints(ctx CheckContext) error {
    if d.Constraints == nil {
        return nil
    }

    if d.Constraints.AmountLimit != nil {
        if ctx.Amount > d.Constraints.AmountLimit.MaxSingle {
            return ErrAmountExceedsLimit
        }
        // Check daily/monthly limits...
    }

    if d.Constraints.TimeWindow != nil {
        if !d.Constraints.TimeWindow.Contains(ctx.ActionTime) {
            return ErrOutsideTimeWindow
        }
    }

    if d.Constraints.MaxActions != nil {
        if d.ActionsCount >= *d.Constraints.MaxActions {
            return ErrMaxActionsReached
        }
    }

    return nil
}
```

### TR-2: Store Interface

```go
type DelegationStore interface {
    Save(ctx context.Context, delegation *Delegation) error
    FindByID(ctx context.Context, id id.DelegationID) (*Delegation, error)
    FindByGrantor(ctx context.Context, grantorID id.UserID, filter DelegationFilter) ([]Delegation, error)
    FindByGrantee(ctx context.Context, granteeID id.UserID, filter DelegationFilter) ([]Delegation, error)
    FindActiveByGrantorAndGrantee(ctx context.Context, grantorID, granteeID id.UserID, entityID *id.EntityID) (*Delegation, error)
    Update(ctx context.Context, delegation *Delegation) error
    IncrementActionCount(ctx context.Context, id id.DelegationID) error
    ExpireAll(ctx context.Context) (int, error)  // Background job
}
```

### TR-3: Service Layer

```go
type DelegationService struct {
    delegations     DelegationStore
    users           UserStore
    representations RepresentationStore  // PRD-036
    notifications   NotificationService  // PRD-018
    auditor         audit.Publisher
}

func (s *DelegationService) CreateDelegation(ctx context.Context, req CreateDelegationRequest) (*Delegation, error)
func (s *DelegationService) ListDelegations(ctx context.Context, userID id.UserID, role string, filter DelegationFilter) ([]Delegation, error)
func (s *DelegationService) GetDelegation(ctx context.Context, id id.DelegationID) (*Delegation, error)
func (s *DelegationService) CheckAuthority(ctx context.Context, req CheckAuthorityRequest) (*CheckResult, error)
func (s *DelegationService) RevokeDelegation(ctx context.Context, id id.DelegationID, revokerID id.UserID, reason string) error
func (s *DelegationService) RecordAction(ctx context.Context, delegationID id.DelegationID, action ActionRecord) error
```

### TR-4: Middleware for Delegated Actions

```go
func DelegationMiddleware(delegationSvc *DelegationService) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            actingAs := r.Header.Get("X-Acting-As")
            delegationID := r.Header.Get("X-Delegation-ID")

            if actingAs == "" {
                // Normal request, no delegation
                next.ServeHTTP(w, r)
                return
            }

            // Validate delegation
            result, err := delegationSvc.CheckAuthority(r.Context(), CheckAuthorityRequest{
                GranteeID:    getCurrentUserID(r.Context()),
                GrantorID:    actingAs,
                DelegationID: delegationID,
                Power:        getRequiredPower(r),
            })
            if err != nil || !result.Allowed {
                http.Error(w, "Delegation not valid", http.StatusForbidden)
                return
            }

            // Add delegation context
            ctx := context.WithValue(r.Context(), delegationKey, result.Delegation)
            ctx = context.WithValue(ctx, actingAsKey, actingAs)

            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

---

## 5. API Specifications

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/delegations` | POST | Bearer | Create delegation |
| `/delegations` | GET | Bearer | List delegations |
| `/delegations/{id}` | GET | Bearer | Get delegation details |
| `/delegations/{id}/revoke` | POST | Bearer | Revoke delegation |
| `/delegations/check` | POST | Service | Check delegation authority |
| `/delegations/{id}/actions` | GET | Bearer | List actions under delegation |

---

## 6. Security Requirements

### SR-1: Authority Verification
- Grantor must possess the powers being delegated
- Delegation cannot exceed grantor's own authority
- Entity-scoped delegations require grantor representation

### SR-2: Delegation Limits
- Maximum delegation depth: 1 (no sub-delegation)
- Maximum active delegations per grantor: configurable (default 10)
- Maximum delegation duration: configurable (default 90 days)

### SR-3: Revocation
- Grantor can revoke any time
- Revocation is immediate
- In-flight actions may complete, but new actions blocked

### SR-4: Audit
- All delegated actions clearly marked in audit
- Grantor can see all actions taken under their delegation
- Delegation lifecycle fully audited

---

## 7. Observability

### Metrics

```
# Gauge: Active delegations
delegations_active{tenant_id}

# Counter: Delegations created/revoked
delegations_lifecycle_total{action="created|revoked|expired"}

# Counter: Actions under delegation
delegated_actions_total{power, result="allowed|denied"}

# Histogram: Delegation duration
delegation_duration_days
```

### Audit Events

- `delegation.created` - New delegation granted
- `delegation.accepted` - Grantee accepted (if acceptance required)
- `delegation.revoked` - Delegation revoked
- `delegation.expired` - Delegation auto-expired
- `delegation.action_performed` - Action taken under delegation
- `delegation.action_denied` - Delegated action denied (constraint violation)

---

## 8. Acceptance Criteria

- [ ] Users can create delegations with scoped powers
- [ ] Delegations enforce time validity (from/until)
- [ ] Amount constraints enforced per transaction/day/month
- [ ] Time window constraints enforced
- [ ] Grantor can revoke delegation immediately
- [ ] Delegated actions recorded with delegation context
- [ ] Grantee notified of new/revoked delegations
- [ ] Audit trail distinguishes delegated from direct actions
- [ ] API check endpoint validates delegation authority
- [ ] Middleware enforces delegation for X-Acting-As requests

---

## 9. Implementation Steps

### Phase 1: Foundation (4-6 hours)
1. Delegation domain models
2. Store implementation
3. Create/Get/List endpoints
4. Unit tests

### Phase 2: Authority Checks (3-4 hours)
1. Check endpoint implementation
2. Constraint evaluation logic
3. Grantor authority validation

### Phase 3: Middleware & Integration (3-4 hours)
1. X-Acting-As header handling
2. Delegation middleware
3. Audit context propagation

### Phase 4: Lifecycle (2-3 hours)
1. Revocation flow
2. Expiry background job
3. Notifications

### Phase 5: Observability (2 hours)
1. Metrics
2. Audit events
3. E2E tests

---

## 10. Future Enhancements

- Delegation acceptance workflow (grantee must accept)
- Delegation templates (pre-defined scope/constraint sets)
- Delegation requests (grantee can request authority)
- Emergency delegation (bypass normal flows in crisis)
- Delegation analytics (usage patterns, underutilized delegations)
- Multi-level delegation with explicit approval

---

## 11. References

- [Power of Attorney - Legal Framework](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:62016CJ0218)
- PRD-036: Legal Entity Identity
- PRD-037: Multi-Party Authorization

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-22 | Engineering | Initial PRD |
