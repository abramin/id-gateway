# PRD-036: Legal Entity Identity & Representation

**Status:** Not Started
**Priority:** P1 (High - Banking/Fintech)
**Owner:** Engineering Team
**Dependencies:** PRD-026A (Tenant & Client Management), PRD-035 (Identity Assurance), PRD-006 (Audit)
**Phase:** 8 (Banking Identity Pack)
**Last Updated:** 2025-12-22

---

## 1. Overview

### Problem Statement

Banks serve businesses, not just individuals. A business banking platform like Qonto needs to answer:
- **Is this a legitimate legal entity?** (company registry verification)
- **Who can act on behalf of this entity?** (directors, signatories, proxies)
- **What powers do they have?** (full authority, limited to €X, specific actions only)
- **Is their authority currently valid?** (not expired, not revoked)

Current Credo has:
- Users (individuals with email)
- Tenants (isolated identity boundaries)

Missing:
- Legal entities (companies, organizations)
- Representation relationships (user → entity with specific powers)
- Signatory management (who can sign what)

### Goals

- Model **legal entities** as first-class identity subjects
- Track entity verification status from company registries
- Define **representation** relationships (user can act for entity)
- Support **role-based powers** (director, signatory, proxy, accountant)
- Enable policy decisions based on representation validity
- Integrate with beneficial ownership for AML compliance

### Non-Goals

- Implementing company registry integrations (Credo consumes external providers)
- Full UBO (Ultimate Beneficial Owner) graph resolution
- Entity-to-entity relationships (subsidiaries, parent companies)
- Legal entity account management (that's the banking system's job)

---

## 2. User Stories

**As a bank compliance officer**
**I want to** verify that a person is an authorized director of a company
**So that** they can open accounts and sign contracts on behalf of the entity

**As a business account holder**
**I want to** delegate limited signing authority to my accountant
**So that** they can approve small payments without my involvement

**As a fintech platform**
**I want to** check entity verification status before allowing transactions
**So that** we only transact with verified, non-sanctioned businesses

**As an auditor**
**I want to** see the full history of who was authorized to act for an entity
**So that** I can trace authorization for past transactions

---

## 3. Functional Requirements

### FR-1: Legal Entity Model

**Entity Types (EU-focused, extensible):**

| Type | Description | Examples |
|------|-------------|----------|
| `gmbh` | German limited liability | GmbH, UG |
| `ag` | German public company | AG |
| `sas` | French simplified joint-stock | SAS |
| `sarl` | French limited liability | SARL |
| `ltd` | UK limited company | Ltd, PLC |
| `bv` | Dutch private limited | B.V. |
| `sole_trader` | Individual business | Einzelunternehmen |
| `partnership` | General partnership | OHG, GbR |
| `other` | Other entity types | Associations, foundations |

**Entity Status:**

```go
type EntityStatus string

const (
    EntityStatusPending    EntityStatus = "pending"     // Awaiting verification
    EntityStatusActive     EntityStatus = "active"      // Verified and operational
    EntityStatusSuspended  EntityStatus = "suspended"   // Temporarily restricted
    EntityStatusDissolved  EntityStatus = "dissolved"   // No longer exists
    EntityStatusSanctioned EntityStatus = "sanctioned"  // On sanctions list
)
```

### FR-2: Register Legal Entity

**Endpoint:** `POST /entities`

**Description:** Register a legal entity for verification.

**Input:**

```json
{
  "name": "Acme GmbH",
  "entity_type": "gmbh",
  "registration_number": "HRB 123456",
  "registration_authority": "Amtsgericht München",
  "jurisdiction": "DE",
  "registered_address": {
    "street": "Maximilianstraße 1",
    "city": "München",
    "postal_code": "80539",
    "country": "DE"
  },
  "incorporation_date": "2020-01-15",
  "tax_id": "DE123456789"
}
```

**Output (Success - 201):**

```json
{
  "entity_id": "ent_abc123",
  "name": "Acme GmbH",
  "entity_type": "gmbh",
  "status": "pending",
  "verification_required": true,
  "created_at": "2025-12-22T10:00:00Z"
}
```

**Business Logic:**

1. Validate required fields (name, type, jurisdiction)
2. Check for duplicate registration number in jurisdiction
3. Create entity with `pending` status
4. Queue for verification (external registry lookup)
5. Emit audit event `entity.registered`

### FR-3: Verify Entity

**Endpoint:** `POST /entities/{id}/verify` (internal/admin)

**Description:** Record verification result from company registry.

**Input:**

```json
{
  "provider": "company_house_de",
  "provider_reference": "ref_xyz789",
  "verification_result": "verified",
  "verified_data": {
    "name": "Acme GmbH",
    "status": "active",
    "incorporation_date": "2020-01-15",
    "registered_directors": ["Alice Smith", "Bob Jones"],
    "share_capital": "25000 EUR"
  },
  "sanctions_check": {
    "checked_at": "2025-12-22T10:30:00Z",
    "result": "clear",
    "lists_checked": ["EU", "UN", "OFAC"]
  }
}
```

**Output (Success - 200):**

```json
{
  "entity_id": "ent_abc123",
  "status": "active",
  "verified_at": "2025-12-22T10:30:00Z",
  "verification_expires_at": "2026-12-22T00:00:00Z"
}
```

### FR-4: Representation Model

**Representation** links a user to an entity with specific powers.

**Roles:**

| Role | Description | Typical Powers |
|------|-------------|----------------|
| `director` | Legal representative | Full authority, sign contracts |
| `signatory` | Authorized signer | Sign within limits |
| `proxy` | Delegated authority | Specific powers, time-limited |
| `accountant` | Financial access | View transactions, limited approvals |
| `employee` | Basic access | View only, initiate requests |

**Powers:**

```go
type Power string

const (
    PowerFullAuthority      Power = "full_authority"       // Can do anything
    PowerSignContracts      Power = "sign_contracts"       // Legal agreements
    PowerInitiateTransfers  Power = "initiate_transfers"   // Start payments
    PowerApproveTransfers   Power = "approve_transfers"    // Approve payments
    PowerViewTransactions   Power = "view_transactions"    // Read-only access
    PowerManageCards        Power = "manage_cards"         // Card operations
    PowerManageUsers        Power = "manage_users"         // Add/remove team
    PowerManageBeneficiaries Power = "manage_beneficiaries" // Payment targets
)
```

### FR-5: Create Representation

**Endpoint:** `POST /entities/{entity_id}/representations`

**Description:** Grant a user representation rights for an entity.

**Input:**

```json
{
  "user_id": "user_alice123",
  "role": "signatory",
  "powers": ["initiate_transfers", "approve_transfers"],
  "constraints": {
    "amount_limit": {
      "max_single": 10000,
      "max_daily": 50000,
      "currency": "EUR"
    },
    "valid_from": "2025-12-22T00:00:00Z",
    "valid_until": "2026-12-22T00:00:00Z",
    "requires_sca": true
  },
  "granted_by": "user_bob456",
  "evidence": {
    "type": "board_resolution",
    "reference": "doc_res123",
    "date": "2025-12-20"
  }
}
```

**Output (Success - 201):**

```json
{
  "representation_id": "rep_def456",
  "entity_id": "ent_abc123",
  "user_id": "user_alice123",
  "role": "signatory",
  "status": "active",
  "powers": ["initiate_transfers", "approve_transfers"],
  "valid_until": "2026-12-22T00:00:00Z",
  "created_at": "2025-12-22T10:00:00Z"
}
```

**Business Logic:**

1. Validate entity exists and is active
2. Validate user exists
3. Validate grantor has authority to grant (is director or has `manage_users`)
4. Check for conflicting representations
5. Store representation with constraints
6. Emit audit event `representation.granted`

### FR-6: Check Representation

**Endpoint:** `POST /entities/{entity_id}/representations/check`

**Description:** Check if a user can perform an action for an entity.

**Input:**

```json
{
  "user_id": "user_alice123",
  "power": "approve_transfers",
  "context": {
    "amount": 5000,
    "currency": "EUR",
    "action": "transfer_approval"
  }
}
```

**Output (Success - 200):**

```json
{
  "allowed": true,
  "representation_id": "rep_def456",
  "role": "signatory",
  "constraints_checked": {
    "amount_within_limit": true,
    "valid_time_range": true,
    "sca_required": true
  }
}
```

**Output (Denied - 403):**

```json
{
  "allowed": false,
  "reason": "amount_exceeds_limit",
  "representation_id": "rep_def456",
  "constraint_violated": {
    "type": "amount_limit",
    "limit": 10000,
    "requested": 15000,
    "currency": "EUR"
  }
}
```

### FR-7: List Entity Representations

**Endpoint:** `GET /entities/{entity_id}/representations`

**Output:**

```json
{
  "entity_id": "ent_abc123",
  "representations": [
    {
      "representation_id": "rep_001",
      "user_id": "user_alice",
      "user_name": "Alice Smith",
      "role": "director",
      "status": "active",
      "powers": ["full_authority"],
      "valid_until": null
    },
    {
      "representation_id": "rep_002",
      "user_id": "user_bob",
      "user_name": "Bob Jones",
      "role": "signatory",
      "status": "active",
      "powers": ["initiate_transfers", "approve_transfers"],
      "valid_until": "2026-12-22T00:00:00Z"
    }
  ]
}
```

### FR-8: Revoke Representation

**Endpoint:** `POST /entities/{entity_id}/representations/{rep_id}/revoke`

**Input:**

```json
{
  "reason": "employment_terminated",
  "effective_immediately": true,
  "revoked_by": "user_alice123"
}
```

**Business Logic:**

1. Validate revoker has authority
2. Set representation status to `revoked`
3. Set `revoked_at` timestamp
4. Emit audit event `representation.revoked`
5. Invalidate any active step-up tokens for this representation

---

## 4. Technical Requirements

### TR-1: Data Models

```go
// internal/entity/models.go

type LegalEntity struct {
    ID                   id.EntityID
    TenantID             id.TenantID
    Name                 string
    EntityType           EntityType
    RegistrationNumber   string
    RegistrationAuthority string
    Jurisdiction         string        // ISO 3166-1 alpha-2
    RegisteredAddress    Address
    IncorporationDate    *time.Time
    TaxID                *string
    Status               EntityStatus
    VerifiedAt           *time.Time
    VerificationExpiresAt *time.Time
    SanctionsStatus      SanctionsStatus
    SanctionsCheckedAt   *time.Time
    CreatedAt            time.Time
    UpdatedAt            time.Time
}

type Representation struct {
    ID           id.RepresentationID
    EntityID     id.EntityID
    UserID       id.UserID
    TenantID     id.TenantID
    Role         RepresentationRole
    Powers       []Power
    Constraints  *RepresentationConstraints
    Status       RepresentationStatus  // active, suspended, revoked, expired
    GrantedBy    id.UserID
    Evidence     *RepresentationEvidence
    ValidFrom    time.Time
    ValidUntil   *time.Time
    RevokedAt    *time.Time
    RevokedBy    *id.UserID
    RevokedReason *string
    CreatedAt    time.Time
    UpdatedAt    time.Time
}

type RepresentationConstraints struct {
    AmountLimit    *AmountLimit
    RequiresSCA    bool
    AllowedActions []string  // Specific action types
    TimeWindow     *TimeWindow  // e.g., business hours only
}

type AmountLimit struct {
    MaxSingle  int64
    MaxDaily   int64
    MaxMonthly int64
    Currency   string
}

type RepresentationEvidence struct {
    Type       string    // board_resolution, power_of_attorney, employment_contract
    Reference  string    // Document ID
    Date       time.Time
    VerifiedBy *id.UserID
}
```

### TR-2: Store Interfaces

```go
type EntityStore interface {
    Save(ctx context.Context, entity *LegalEntity) error
    FindByID(ctx context.Context, id id.EntityID) (*LegalEntity, error)
    FindByRegistration(ctx context.Context, regNum, jurisdiction string) (*LegalEntity, error)
    FindByTenant(ctx context.Context, tenantID id.TenantID) ([]LegalEntity, error)
    Update(ctx context.Context, entity *LegalEntity) error
    Delete(ctx context.Context, id id.EntityID) error
}

type RepresentationStore interface {
    Save(ctx context.Context, rep *Representation) error
    FindByID(ctx context.Context, id id.RepresentationID) (*Representation, error)
    FindByEntity(ctx context.Context, entityID id.EntityID) ([]Representation, error)
    FindByUser(ctx context.Context, userID id.UserID) ([]Representation, error)
    FindActiveByUserAndEntity(ctx context.Context, userID id.UserID, entityID id.EntityID) (*Representation, error)
    Update(ctx context.Context, rep *Representation) error
    Revoke(ctx context.Context, id id.RepresentationID, revokedBy id.UserID, reason string) error
}
```

### TR-3: Service Layer

```go
type EntityService struct {
    entities        EntityStore
    representations RepresentationStore
    sanctions       SanctionsChecker  // PRD-003
    auditor         audit.Publisher
}

func (s *EntityService) RegisterEntity(ctx context.Context, req RegisterEntityRequest) (*LegalEntity, error)
func (s *EntityService) VerifyEntity(ctx context.Context, req VerifyEntityRequest) (*LegalEntity, error)
func (s *EntityService) GetEntity(ctx context.Context, entityID id.EntityID) (*LegalEntity, error)

func (s *EntityService) GrantRepresentation(ctx context.Context, req GrantRepresentationRequest) (*Representation, error)
func (s *EntityService) CheckRepresentation(ctx context.Context, req CheckRepresentationRequest) (*CheckResult, error)
func (s *EntityService) RevokeRepresentation(ctx context.Context, req RevokeRepresentationRequest) error
func (s *EntityService) ListRepresentations(ctx context.Context, entityID id.EntityID) ([]Representation, error)
```

### TR-4: Integration with Decision Engine

Expose entity/representation as evidence for policy decisions:

```go
type EntityEvidence struct {
    EntityID     id.EntityID
    Status       EntityStatus
    Verified     bool
    Sanctioned   bool
    DaysSinceVerification int
}

type RepresentationEvidence struct {
    HasRepresentation bool
    Role              RepresentationRole
    Powers            []Power
    WithinAmountLimit bool
    ValidTimeRange    bool
    RequiresSCA       bool
}
```

---

## 5. API Specifications

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/entities` | POST | Bearer | Register new entity |
| `/entities/{id}` | GET | Bearer | Get entity details |
| `/entities/{id}/verify` | POST | Admin | Record verification |
| `/entities/{id}/representations` | GET | Bearer | List representations |
| `/entities/{id}/representations` | POST | Bearer | Grant representation |
| `/entities/{id}/representations/check` | POST | Service | Check authorization |
| `/entities/{id}/representations/{rep_id}` | GET | Bearer | Get representation |
| `/entities/{id}/representations/{rep_id}/revoke` | POST | Bearer | Revoke representation |
| `/users/{id}/representations` | GET | Bearer | User's representations |

---

## 6. Security Requirements

### SR-1: Authorization Hierarchy
- Only directors can grant director roles
- Signatories cannot grant powers they don't have
- Representation changes require valid representation
- Self-revocation always allowed

### SR-2: Audit Trail
- All representation changes logged with evidence
- Entity verification history preserved
- Grantor/revoker identity recorded

### SR-3: Sanctions Compliance
- Sanctioned entities cannot have active representations
- Periodic re-screening required (configurable interval)
- Sanctions hit triggers immediate suspension

---

## 7. Observability

### Metrics

```
# Gauge: Entities by status
entity_count_by_status{tenant_id, status}

# Counter: Entity verifications
entity_verifications_total{result="verified|failed|pending"}

# Counter: Representation operations
representation_operations_total{operation="grant|revoke|check", result}

# Counter: Authorization checks
representation_checks_total{power, result="allowed|denied"}
```

### Audit Events

- `entity.registered` - New entity created
- `entity.verified` - Verification completed
- `entity.suspended` - Entity suspended
- `entity.sanctioned` - Sanctions hit detected
- `representation.granted` - New representation
- `representation.revoked` - Representation revoked
- `representation.checked` - Authorization check performed
- `representation.expired` - Auto-expired representation

---

## 8. Acceptance Criteria

- [ ] Legal entities can be registered with type and jurisdiction
- [ ] Entity verification status tracked from external providers
- [ ] Representations link users to entities with roles and powers
- [ ] Representation constraints enforced (amount limits, time validity)
- [ ] Directors can grant/revoke representations
- [ ] Check endpoint evaluates constraints in context
- [ ] Sanctions status blocks operations for flagged entities
- [ ] Audit trail captures all representation changes
- [ ] GDPR deletion removes entity data (with retention for AML)

---

## 9. Implementation Steps

### Phase 1: Entity Foundation (4-6 hours)
1. Entity domain models and store
2. Register/Get entity endpoints
3. Basic validation
4. Unit tests

### Phase 2: Verification Integration (3-4 hours)
1. Verification recording endpoint
2. Sanctions status tracking
3. Verification expiry logic

### Phase 3: Representation Model (6-8 hours)
1. Representation domain models and store
2. Grant/Revoke/List endpoints
3. Authorization hierarchy enforcement
4. Constraint evaluation

### Phase 4: Authorization Check (3-4 hours)
1. Check endpoint with full context
2. Integration with decision engine
3. E2E tests

---

## 10. Future Enhancements

- Company registry API integrations (Companies House, Handelsregister)
- Beneficial ownership (UBO) tracking
- Multi-level entity hierarchies (parent/subsidiary)
- Representation approval workflows (pending → approved)
- Document storage for evidence (board resolutions)
- Cross-border entity recognition

---

## 11. References

- [EU Company Law Directive](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32017L1132)
- [5th Anti-Money Laundering Directive (5AMLD)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843)
- PRD-003: Registry Integration
- PRD-035: Identity Assurance Levels

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-22 | Engineering | Initial PRD |
