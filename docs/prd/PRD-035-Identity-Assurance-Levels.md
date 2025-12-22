# PRD-035: Identity Assurance Levels

**Status:** Not Started
**Priority:** P1 (High - Banking/Fintech)
**Owner:** Engineering Team
**Dependencies:** PRD-004 (Verifiable Credentials), PRD-003 (Registry Integration), PRD-006 (Audit)
**Phase:** 8 (Banking Identity Pack)
**Last Updated:** 2025-12-22

---

## 1. Overview

### Problem Statement

Banks and regulated financial services don't just need "is this user authenticated?" — they need "how confident are we in this identity?" Current Credo VCs prove specific facts (e.g., "is over 18") but don't track the **strength of identity proofing** used to establish those facts.

Identity Assurance Levels (IALs) answer:
- **How was this identity verified?** (document scan, video call, in-branch, eID)
- **How recently?** (some proofing methods decay in trust over time)
- **What can this assurance level unlock?** (higher IAL = higher transaction limits)

Without IALs, a bank cannot implement tiered access: "LoA1 users can view balances; LoA3 users can transfer €50k."

### Goals

- Define Identity Assurance Levels aligned with eIDAS/NIST 800-63-3
- Track proofing method, verification timestamp, and expiry per user
- Store verified claims with their assurance context
- Expose IAL in tokens and API responses for downstream policy decisions
- Enable policy rules based on IAL (via PRD-015/PRD-027)

### Non-Goals

- Implementing actual identity proofing (document scanning, video ident) — Credo consumes external IDV providers
- Biometric storage (see PRD-013)
- Credential wallet / holder-side storage
- Cross-tenant IAL portability (each tenant maintains own assurance records)

---

## 2. User Stories

**As a bank compliance officer**
**I want to** require IAL2+ for account opening and IAL3 for high-value transfers
**So that** we meet regulatory KYC requirements

**As a fintech product manager**
**I want to** offer tiered onboarding (IAL1 for browsing, IAL2 for transactions)
**So that** users can start quickly and upgrade when needed

**As a security engineer**
**I want to** see the proofing method and timestamp in audit logs
**So that** I can investigate identity-related incidents

**As a user**
**I want to** know what verification is required to unlock higher limits
**So that** I can complete verification proactively

---

## 3. Functional Requirements

### FR-1: Assurance Level Model

**Levels (eIDAS-aligned):**

| Level | Name | Description | Example Methods |
|-------|------|-------------|-----------------|
| IAL0 | No Proofing | Self-asserted identity | Email signup only |
| IAL1 | Low | Basic identity verification | Email + phone verified |
| IAL2 | Substantial | Identity document verification | Document scan + selfie match |
| IAL3 | High | In-person or supervised remote | Video ident, in-branch, eID |

**Proofing Methods:**

```go
type ProofingMethod string

const (
    ProofingNone          ProofingMethod = "none"           // Self-asserted
    ProofingEmailVerified ProofingMethod = "email_verified" // Email OTP confirmed
    ProofingPhoneVerified ProofingMethod = "phone_verified" // SMS OTP confirmed
    ProofingDocumentScan  ProofingMethod = "document_scan"  // ID document OCR + verification
    ProofingSelfieMatch   ProofingMethod = "selfie_match"   // Liveness + face match to document
    ProofingVideoIdent    ProofingMethod = "video_ident"    // Live video call with agent
    ProofingInBranch      ProofingMethod = "in_branch"      // Physical presence verification
    ProofingEID           ProofingMethod = "eid"            // Government eID (e.g., German Ausweis)
    ProofingBankVerified  ProofingMethod = "bank_verified"  // Verified via bank account ownership
)
```

### FR-2: Identity Assurance Record

**Endpoint:** `POST /identity/assurance` (internal/admin)

**Description:** Record identity proofing result from external IDV provider.

**Input:**

```json
{
  "user_id": "user_abc123",
  "level": "IAL2",
  "proofing_method": "document_scan",
  "provider": "onfido",
  "provider_reference": "check_xyz789",
  "verified_claims": [
    {"claim": "full_name", "value": "Alice Smith", "confidence": 0.95},
    {"claim": "date_of_birth", "value": "1990-05-15", "confidence": 0.98},
    {"claim": "nationality", "value": "DE", "confidence": 0.92},
    {"claim": "document_number", "value": "L01X...", "confidence": 0.99}
  ],
  "document_type": "passport",
  "document_country": "DE",
  "expires_at": "2026-12-22T00:00:00Z"
}
```

**Output (Success - 201):**

```json
{
  "assurance_id": "ial_def456",
  "user_id": "user_abc123",
  "level": "IAL2",
  "proofing_method": "document_scan",
  "verified_at": "2025-12-22T10:30:00Z",
  "expires_at": "2026-12-22T00:00:00Z",
  "claims_count": 4
}
```

**Business Logic:**

1. Validate user exists and belongs to tenant
2. Validate level is recognized (IAL0-IAL3)
3. Validate proofing method is appropriate for level
4. Store assurance record with verified claims
5. Update user's current IAL if this is higher
6. Emit audit event `identity.assurance_recorded`
7. If regulated mode, store only derived flags (not raw PII)

### FR-3: Query User Assurance

**Endpoint:** `GET /identity/assurance/{user_id}`

**Description:** Get current identity assurance level and history.

**Output:**

```json
{
  "user_id": "user_abc123",
  "current_level": "IAL2",
  "current_method": "document_scan",
  "verified_at": "2025-12-22T10:30:00Z",
  "expires_at": "2026-12-22T00:00:00Z",
  "is_expired": false,
  "history": [
    {
      "assurance_id": "ial_def456",
      "level": "IAL2",
      "method": "document_scan",
      "verified_at": "2025-12-22T10:30:00Z"
    },
    {
      "assurance_id": "ial_abc123",
      "level": "IAL1",
      "method": "email_verified",
      "verified_at": "2025-12-01T08:00:00Z"
    }
  ]
}
```

### FR-4: Require Assurance Level

**Endpoint:** `POST /identity/assurance/require` (service-to-service)

**Description:** Check if user meets minimum assurance level for an operation.

**Input:**

```json
{
  "user_id": "user_abc123",
  "required_level": "IAL2",
  "operation": "transfer_initiate",
  "amount": 5000,
  "currency": "EUR"
}
```

**Output (Success - 200):**

```json
{
  "allowed": true,
  "current_level": "IAL2",
  "required_level": "IAL2",
  "verified_at": "2025-12-22T10:30:00Z"
}
```

**Output (Insufficient - 403):**

```json
{
  "allowed": false,
  "current_level": "IAL1",
  "required_level": "IAL2",
  "upgrade_url": "/identity/upgrade?target=IAL2",
  "reason": "identity_assurance_insufficient"
}
```

### FR-5: Token Claims

Access tokens include assurance level when requested via scope:

**Scope:** `identity_assurance`

**Claims:**

```json
{
  "ial": "IAL2",
  "ial_method": "document_scan",
  "ial_verified_at": "2025-12-22T10:30:00Z",
  "ial_expires_at": "2026-12-22T00:00:00Z"
}
```

### FR-6: Assurance Expiry & Decay

- Document-based proofing (IAL2) valid for 12 months by default
- Video ident (IAL3) valid for 24 months
- eID (IAL3) valid until document expiry
- Expired assurance demotes user to previous valid level
- Configurable per tenant via policy

---

## 4. Technical Requirements

### TR-1: Data Models

```go
// internal/identity/assurance/models.go

type AssuranceLevel string

const (
    IAL0 AssuranceLevel = "IAL0" // No proofing
    IAL1 AssuranceLevel = "IAL1" // Low
    IAL2 AssuranceLevel = "IAL2" // Substantial
    IAL3 AssuranceLevel = "IAL3" // High
)

func (l AssuranceLevel) Rank() int {
    switch l {
    case IAL0: return 0
    case IAL1: return 1
    case IAL2: return 2
    case IAL3: return 3
    default: return -1
    }
}

func (l AssuranceLevel) MeetsOrExceeds(required AssuranceLevel) bool {
    return l.Rank() >= required.Rank()
}

type AssuranceRecord struct {
    ID              id.AssuranceID
    UserID          id.UserID
    TenantID        id.TenantID
    Level           AssuranceLevel
    ProofingMethod  ProofingMethod
    Provider        string            // External IDV provider
    ProviderRef     string            // External reference ID
    VerifiedClaims  []VerifiedClaim   // What was proven
    DocumentType    *string           // passport, id_card, drivers_license
    DocumentCountry *string           // ISO 3166-1 alpha-2
    VerifiedAt      time.Time
    ExpiresAt       *time.Time
    RevokedAt       *time.Time
    RevokedReason   *string
    CreatedAt       time.Time
}

type VerifiedClaim struct {
    Claim      string  // full_name, date_of_birth, nationality, etc.
    Value      string  // Encrypted or hashed in regulated mode
    Confidence float64 // 0.0 - 1.0
}

type UserAssuranceState struct {
    UserID          id.UserID
    CurrentLevel    AssuranceLevel
    CurrentMethod   ProofingMethod
    VerifiedAt      time.Time
    ExpiresAt       *time.Time
    IsExpired       bool
    History         []AssuranceRecord
}
```

### TR-2: Store Interface

```go
type AssuranceStore interface {
    Save(ctx context.Context, record *AssuranceRecord) error
    FindByID(ctx context.Context, id id.AssuranceID) (*AssuranceRecord, error)
    FindByUser(ctx context.Context, userID id.UserID) ([]AssuranceRecord, error)
    FindCurrentByUser(ctx context.Context, userID id.UserID) (*AssuranceRecord, error)
    Revoke(ctx context.Context, id id.AssuranceID, reason string) error
    DeleteByUser(ctx context.Context, userID id.UserID) error // GDPR
}
```

### TR-3: Service Layer

```go
type AssuranceService struct {
    store   AssuranceStore
    auditor audit.Publisher
    config  AssuranceConfig
}

func (s *AssuranceService) RecordAssurance(ctx context.Context, req RecordAssuranceRequest) (*AssuranceRecord, error)
func (s *AssuranceService) GetUserAssurance(ctx context.Context, userID id.UserID) (*UserAssuranceState, error)
func (s *AssuranceService) RequireLevel(ctx context.Context, userID id.UserID, required AssuranceLevel) error
func (s *AssuranceService) RevokeAssurance(ctx context.Context, assuranceID id.AssuranceID, reason string) error
```

### TR-4: Integration with Decision Engine (PRD-005)

The decision engine can query assurance level as evidence:

```go
// Evidence signal for decision engine
type AssuranceEvidence struct {
    Level        AssuranceLevel
    Method       ProofingMethod
    VerifiedAt   time.Time
    IsExpired    bool
    DaysSinceVerification int
}
```

### TR-5: Regulated Mode Handling

In `REGULATED_MODE=true`:
- `VerifiedClaim.Value` is hashed, not stored in cleartext
- API responses return only derived flags (`has_verified_name: true`)
- Full claim values never exposed via API

---

## 5. API Specifications

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/identity/assurance` | POST | Admin/Service | Record new assurance |
| `/identity/assurance/{user_id}` | GET | Bearer | Get user assurance state |
| `/identity/assurance/require` | POST | Service | Check assurance requirement |
| `/identity/assurance/{id}/revoke` | POST | Admin | Revoke assurance record |
| `/admin/assurance/policies` | GET/PUT | Admin | Configure tenant assurance policies |

---

## 6. Security Requirements

### SR-1: Data Protection
- Verified claims encrypted at rest
- PII never logged (only assurance IDs and levels)
- Provider references stored for audit trail only

### SR-2: Access Control
- Recording assurance requires admin or service-to-service auth
- Users can view their own assurance state
- Cross-tenant access prohibited

### SR-3: Audit Trail
- All assurance changes logged with actor, timestamp, reason
- Revocation requires documented reason
- History preserved for compliance (7 years default)

---

## 7. Observability

### Metrics

```
# Gauge: Users at each assurance level per tenant
identity_assurance_users_by_level{tenant_id, level}

# Counter: Assurance verifications recorded
identity_assurance_recorded_total{level, method, provider}

# Counter: Assurance checks (require) by outcome
identity_assurance_checks_total{required_level, outcome="allowed|denied"}

# Counter: Expired assurances
identity_assurance_expired_total{level}
```

### Audit Events

- `identity.assurance_recorded` - New assurance added
- `identity.assurance_required_passed` - Check passed
- `identity.assurance_required_failed` - Check failed
- `identity.assurance_revoked` - Manually revoked
- `identity.assurance_expired` - Auto-expired

---

## 8. Acceptance Criteria

- [ ] IAL0-IAL3 levels defined and stored per user
- [ ] Proofing method recorded with each assurance
- [ ] Assurance expiry enforced (demotes to previous level)
- [ ] Token claims include IAL when `identity_assurance` scope requested
- [ ] Require endpoint returns upgrade URL on insufficient assurance
- [ ] Regulated mode hashes claim values
- [ ] Audit trail for all assurance operations
- [ ] Integration with decision engine (PRD-005) for policy evaluation
- [ ] GDPR deletion removes assurance records

---

## 9. Implementation Steps

### Phase 1: Foundation (4-6 hours)
1. Define domain models and value objects
2. Implement AssuranceStore (in-memory, then PostgreSQL)
3. Implement AssuranceService core methods
4. Unit tests

### Phase 2: API Layer (2-3 hours)
1. HTTP handlers for record/query/require
2. Request validation
3. Integration tests

### Phase 3: Token Integration (2 hours)
1. Add `identity_assurance` scope
2. Include IAL claims in access tokens
3. Update token validation

### Phase 4: Decision Engine Integration (2 hours)
1. Expose assurance as evidence signal
2. Policy examples for IAL-based decisions
3. E2E tests

---

## 10. Future Enhancements

- IDV provider integrations (Onfido, Jumio, IDnow)
- Progressive verification flows (step-up from IAL1 to IAL2)
- Assurance level inheritance (IAL3 implies IAL2 claims)
- Cross-border assurance recognition (eIDAS interoperability)
- Assurance score (continuous, not just levels)

---

## 11. References

- [eIDAS Regulation](https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation)
- [NIST SP 800-63-3: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [ISO/IEC 29115:2013 Entity Authentication Assurance](https://www.iso.org/standard/45138.html)
- PRD-004: Verifiable Credentials
- PRD-005: Decision Engine

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-22 | Engineering | Initial PRD |
