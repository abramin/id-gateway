# PRD-039: SCA Orchestration (PSD2 Strong Customer Authentication)

**Status:** Not Started
**Priority:** P0 (Critical - Banking/Fintech Compliance)
**Owner:** Engineering Team
**Dependencies:** PRD-001 (Authentication), PRD-021 (MFA), PRD-027 (Adaptive Auth), PRD-018 (Notifications)
**Phase:** 8 (Banking Identity Pack)
**Last Updated:** 2025-12-22

---

## 1. Overview

### Problem Statement

PSD2 (Payment Services Directive 2) requires **Strong Customer Authentication (SCA)** for:
- Payment initiation
- Account access (with exemptions)
- Sensitive data changes

SCA requires 2 of 3 authentication factors:
- **Knowledge**: Something the user knows (password, PIN)
- **Possession**: Something the user has (phone, hardware token)
- **Inherence**: Something the user is (biometric)

Current Credo has MFA (PRD-021) but lacks:
- Action-specific SCA challenges
- Session tokens bound to specific operations
- SCA exemption management
- PSD2-compliant challenge flows

This is the **exact flow Qonto's API uses** — a 428 response triggers SCA, the user approves on their device, and the request is retried with an `sca_session_token`.

### Goals

- Implement **action-bound SCA challenges** (not reusable across actions)
- Support **multiple SCA methods** (paired device, passkey, SMS OTP fallback)
- Manage **SCA exemptions** (low value, trusted beneficiary, recurring)
- Provide **session tokens** for approved SCA challenges
- Enable **policy-driven SCA triggers** (amount, action type, risk)
- Ensure **PSD2/RTS compliance** for payment service providers

### Non-Goals

- Implementing the payment execution itself
- Biometric hardware integration (use device capabilities)
- SCA for card-present transactions (3DS is separate)
- Cross-border SCA interoperability

---

## 2. User Stories

**As a fintech API consumer**
**I want to** receive a 428 response when SCA is required
**So that** I can prompt the user for authentication and retry

**As a mobile app user**
**I want to** approve transactions via push notification on my paired device
**So that** I don't need to leave the banking app

**As a frequent user**
**I want to** skip SCA for small payments to trusted beneficiaries
**So that** everyday transactions are frictionless

**As a compliance officer**
**I want to** configure SCA thresholds per transaction type
**So that** we meet PSD2 requirements while optimizing UX

**As a security engineer**
**I want to** ensure SCA tokens are bound to specific actions
**So that** a token can't be reused for different transactions

---

## 3. Functional Requirements

### FR-1: SCA Challenge Flow

**Standard Flow (Qonto-style):**

```
1. Client → API: POST /transfers (initiate payment)
2. API → Client: 428 Precondition Required
   {
     "error": "sca_required",
     "sca_session_token": "sca_abc123",
     "challenge_type": "paired_device",
     "expires_in": 900
   }
3. API → User Device: Push notification "Approve €500 to Supplier GmbH"
4. User → Device: Approve (biometric/PIN)
5. Device → API: POST /sca/confirm (device confirms approval)
6. Client polls: GET /sca/status/{token} → "approved"
7. Client → API: POST /transfers (retry with X-Qonto-Sca-Session-Token)
8. API → Client: 200 OK (transfer executed)
```

### FR-2: SCA Methods

| Method | Factor Types | Priority | Description |
|--------|--------------|----------|-------------|
| `paired_device` | Possession + Inherence | 1 | Push to enrolled mobile app |
| `passkey` | Possession + Inherence | 2 | WebAuthn/FIDO2 |
| `totp` | Possession | 3 | Time-based OTP (authenticator app) |
| `sms_otp` | Possession | 4 | SMS code (fallback only) |
| `email_otp` | Possession | 5 | Email code (lowest security) |

**Method Selection:**

```go
func (s *SCAService) SelectMethod(ctx context.Context, userID id.UserID, preference string) (SCAMethod, error) {
    enrolled := s.getEnrolledMethods(ctx, userID)

    // Honor preference if enrolled
    if preference != "" && enrolled.Has(preference) {
        return preference, nil
    }

    // Return highest-priority enrolled method
    for _, method := range methodPriority {
        if enrolled.Has(method) {
            return method, nil
        }
    }

    return "", ErrNoSCAMethodEnrolled
}
```

### FR-3: Initiate SCA Challenge

**Endpoint:** `POST /sca/challenge`

**Description:** Initiate an SCA challenge for a sensitive action.

**Input:**

```json
{
  "action_type": "transfer",
  "action_id": "txn_xyz789",
  "action_data": {
    "amount": 500,
    "currency": "EUR",
    "beneficiary_name": "Supplier GmbH",
    "beneficiary_iban": "DE89..."
  },
  "method_preference": "paired_device"
}
```

**Output (Success - 201):**

```json
{
  "sca_session_token": "sca_abc123def456",
  "challenge_type": "paired_device",
  "status": "pending",
  "expires_at": "2025-12-22T10:15:00Z",
  "expires_in": 900,
  "device_hint": "iPhone 14 Pro",
  "action_summary": "Approve €500 transfer to Supplier GmbH"
}
```

**Business Logic:**

1. Validate user is authenticated
2. Check if SCA is actually required (exemptions)
3. Select SCA method based on preference/availability
4. Generate unique `sca_session_token`
5. Create challenge bound to action
6. Store challenge with expiry (15 minutes)
7. Trigger method-specific flow (push notification, etc.)
8. Return challenge details

### FR-4: SCA Challenge Status

**Endpoint:** `GET /sca/status/{sca_session_token}`

**Description:** Poll for SCA challenge status.

**Output (Pending):**

```json
{
  "sca_session_token": "sca_abc123def456",
  "status": "pending",
  "expires_at": "2025-12-22T10:15:00Z",
  "method": "paired_device"
}
```

**Output (Approved):**

```json
{
  "sca_session_token": "sca_abc123def456",
  "status": "approved",
  "approved_at": "2025-12-22T10:05:30Z",
  "method": "paired_device",
  "valid_until": "2025-12-22T10:20:30Z"
}
```

**Output (Denied/Expired):**

```json
{
  "sca_session_token": "sca_abc123def456",
  "status": "denied",
  "reason": "user_rejected"
}
```

### FR-5: Confirm SCA (Device Callback)

**Endpoint:** `POST /sca/confirm`

**Description:** Device confirms user approved the challenge.

**Input:**

```json
{
  "sca_session_token": "sca_abc123def456",
  "device_id": "dev_xyz789",
  "approval_signature": "eyJhbGciOiJFUzI1NiIs...",
  "biometric_verified": true
}
```

**Output (Success - 200):**

```json
{
  "confirmed": true,
  "valid_until": "2025-12-22T10:20:30Z"
}
```

**Business Logic:**

1. Validate device is paired to user
2. Validate sca_session_token exists and is pending
3. Validate approval signature (device private key)
4. Mark challenge as approved
5. Set validity window (5-15 minutes based on action type)
6. Emit audit event `sca.challenge_approved`

### FR-6: Validate SCA Token

**Endpoint:** Internal service call

**Description:** Validate SCA token for action execution.

```go
func (s *SCAService) ValidateSCAToken(ctx context.Context, token string, actionType string, actionID string) error {
    challenge, err := s.store.FindByToken(ctx, token)
    if err != nil {
        return ErrInvalidSCAToken
    }

    if challenge.Status != ChallengeStatusApproved {
        return ErrSCANotApproved
    }

    if time.Now().After(challenge.ValidUntil) {
        return ErrSCATokenExpired
    }

    // Action binding: token must match the action it was issued for
    if challenge.ActionType != actionType || challenge.ActionID != actionID {
        return ErrSCATokenActionMismatch
    }

    // Single use: mark as used
    challenge.UsedAt = time.Now()
    s.store.Update(ctx, challenge)

    return nil
}
```

### FR-7: SCA Exemptions (PSD2 RTS)

**Exemption Types:**

| Exemption | Criteria | Max Amount |
|-----------|----------|------------|
| Low Value | Transaction amount | €30 (cumulative €100 or 5 txns) |
| Trusted Beneficiary | Whitelisted recipient | Unlimited |
| Recurring | Same amount/beneficiary | Per agreement |
| Corporate | B2B dedicated processes | Per agreement |
| TRA | Transaction Risk Analysis | Based on fraud rate |

**Endpoint:** `POST /sca/exemptions/check`

**Input:**

```json
{
  "user_id": "user_abc123",
  "action_type": "transfer",
  "amount": 25,
  "currency": "EUR",
  "beneficiary_id": "ben_xyz789"
}
```

**Output (Exempt):**

```json
{
  "sca_required": false,
  "exemption_type": "low_value",
  "exemption_reason": "Transaction under €30 threshold",
  "cumulative_remaining": 75
}
```

**Output (Required):**

```json
{
  "sca_required": true,
  "reason": "amount_exceeds_threshold",
  "required_method": "paired_device"
}
```

### FR-8: Trusted Beneficiary Management

**Endpoint:** `POST /sca/trusted-beneficiaries`

**Description:** Add beneficiary to trusted list (requires SCA).

**Input:**

```json
{
  "beneficiary_id": "ben_xyz789",
  "sca_session_token": "sca_abc123"
}
```

**Output:**

```json
{
  "trusted": true,
  "beneficiary_id": "ben_xyz789",
  "trusted_at": "2025-12-22T10:00:00Z"
}
```

---

## 4. Technical Requirements

### TR-1: Data Models

```go
// internal/sca/models.go

type SCAChallenge struct {
    ID              id.ChallengeID
    Token           string            // sca_session_token
    UserID          id.UserID
    TenantID        id.TenantID
    Method          SCAMethod
    Status          ChallengeStatus   // pending, approved, denied, expired
    ActionType      string            // transfer, beneficiary_add, etc.
    ActionID        string            // Transaction/action identifier
    ActionDigest    string            // SHA-256 of action data
    ActionSummary   string            // Human-readable summary
    DeviceID        *string           // Paired device used for approval
    CreatedAt       time.Time
    ExpiresAt       time.Time
    ApprovedAt      *time.Time
    ValidUntil      *time.Time        // Token validity after approval
    UsedAt          *time.Time        // When token was consumed
    DeniedAt        *time.Time
    DeniedReason    *string
}

type ChallengeStatus string

const (
    ChallengeStatusPending  ChallengeStatus = "pending"
    ChallengeStatusApproved ChallengeStatus = "approved"
    ChallengeStatusDenied   ChallengeStatus = "denied"
    ChallengeStatusExpired  ChallengeStatus = "expired"
    ChallengeStatusUsed     ChallengeStatus = "used"
)

type SCAMethod string

const (
    SCAMethodPairedDevice SCAMethod = "paired_device"
    SCAMethodPasskey      SCAMethod = "passkey"
    SCAMethodTOTP         SCAMethod = "totp"
    SCAMethodSMSOTP       SCAMethod = "sms_otp"
    SCAMethodEmailOTP     SCAMethod = "email_otp"
    SCAMethodMock         SCAMethod = "mock"  // Sandbox only
)

type SCAExemption struct {
    ID            id.ExemptionID
    UserID        id.UserID
    TenantID      id.TenantID
    Type          ExemptionType
    BeneficiaryID *id.BeneficiaryID  // For trusted beneficiary
    MaxAmount     *int64
    Currency      *string
    ValidUntil    *time.Time         // For recurring agreements
    CreatedAt     time.Time
}

type ExemptionType string

const (
    ExemptionLowValue          ExemptionType = "low_value"
    ExemptionTrustedBeneficiary ExemptionType = "trusted_beneficiary"
    ExemptionRecurring         ExemptionType = "recurring"
    ExemptionCorporate         ExemptionType = "corporate"
    ExemptionTRA               ExemptionType = "tra"
)

type LowValueTracker struct {
    UserID       id.UserID
    TenantID     id.TenantID
    Date         string      // YYYY-MM-DD
    TotalAmount  int64       // Cumulative amount
    TxnCount     int         // Transaction count
}
```

### TR-2: Store Interfaces

```go
type SCAStore interface {
    // Challenges
    SaveChallenge(ctx context.Context, challenge *SCAChallenge) error
    FindChallengeByToken(ctx context.Context, token string) (*SCAChallenge, error)
    FindChallengeByID(ctx context.Context, id id.ChallengeID) (*SCAChallenge, error)
    UpdateChallenge(ctx context.Context, challenge *SCAChallenge) error
    ExpirePending(ctx context.Context) (int, error)

    // Exemptions
    SaveExemption(ctx context.Context, exemption *SCAExemption) error
    FindExemptionsByUser(ctx context.Context, userID id.UserID) ([]SCAExemption, error)
    FindTrustedBeneficiary(ctx context.Context, userID id.UserID, beneficiaryID id.BeneficiaryID) (*SCAExemption, error)
    DeleteExemption(ctx context.Context, id id.ExemptionID) error

    // Low value tracking
    GetLowValueTracker(ctx context.Context, userID id.UserID, date string) (*LowValueTracker, error)
    IncrementLowValue(ctx context.Context, userID id.UserID, amount int64) error
}
```

### TR-3: Service Layer

```go
type SCAService struct {
    store         SCAStore
    devices       DeviceStore         // PRD-001 device binding
    notifications NotificationService // PRD-018
    auditor       audit.Publisher
    config        SCAConfig
}

// Challenge lifecycle
func (s *SCAService) InitiateChallenge(ctx context.Context, req InitiateChallengeRequest) (*SCAChallenge, error)
func (s *SCAService) GetChallengeStatus(ctx context.Context, token string) (*SCAChallenge, error)
func (s *SCAService) ConfirmChallenge(ctx context.Context, req ConfirmChallengeRequest) error
func (s *SCAService) DenyChallenge(ctx context.Context, token string, reason string) error
func (s *SCAService) ValidateToken(ctx context.Context, token string, actionType string, actionID string) error

// Exemptions
func (s *SCAService) CheckExemption(ctx context.Context, req CheckExemptionRequest) (*ExemptionResult, error)
func (s *SCAService) AddTrustedBeneficiary(ctx context.Context, userID id.UserID, beneficiaryID id.BeneficiaryID) error
func (s *SCAService) RemoveTrustedBeneficiary(ctx context.Context, userID id.UserID, beneficiaryID id.BeneficiaryID) error

// Method management
func (s *SCAService) GetEnrolledMethods(ctx context.Context, userID id.UserID) ([]SCAMethod, error)
func (s *SCAService) SelectMethod(ctx context.Context, userID id.UserID, preference string) (SCAMethod, error)
```

### TR-4: HTTP Middleware for SCA-Protected Endpoints

```go
func RequireSCA(scaService *SCAService, actionType string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            userID := getUserID(r.Context())

            // Check for SCA token in header
            scaToken := r.Header.Get("X-Sca-Session-Token")

            if scaToken == "" {
                // Check exemptions first
                actionData := extractActionData(r)
                exempt, err := scaService.CheckExemption(r.Context(), CheckExemptionRequest{
                    UserID:     userID,
                    ActionType: actionType,
                    ActionData: actionData,
                })

                if err == nil && !exempt.SCARequired {
                    // Exempt, continue without SCA
                    next.ServeHTTP(w, r)
                    return
                }

                // SCA required, initiate challenge
                challenge, _ := scaService.InitiateChallenge(r.Context(), InitiateChallengeRequest{
                    UserID:     userID,
                    ActionType: actionType,
                    ActionData: actionData,
                })

                // Return 428 Precondition Required
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusPreconditionRequired)
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "error":             "sca_required",
                    "sca_session_token": challenge.Token,
                    "challenge_type":    challenge.Method,
                    "expires_in":        int(time.Until(challenge.ExpiresAt).Seconds()),
                })
                return
            }

            // Validate SCA token
            actionID := extractActionID(r)
            if err := scaService.ValidateToken(r.Context(), scaToken, actionType, actionID); err != nil {
                http.Error(w, "Invalid or expired SCA token", http.StatusUnauthorized)
                return
            }

            // SCA validated, proceed
            next.ServeHTTP(w, r)
        })
    }
}
```

### TR-5: Push Notification Integration

```go
type PairedDeviceNotifier struct {
    pushService PushService
}

func (n *PairedDeviceNotifier) SendChallenge(ctx context.Context, challenge *SCAChallenge, device *Device) error {
    return n.pushService.Send(ctx, PushNotification{
        DeviceToken: device.PushToken,
        Title:       "Approval Required",
        Body:        challenge.ActionSummary,
        Data: map[string]string{
            "type":              "sca_challenge",
            "sca_session_token": challenge.Token,
            "action_type":       challenge.ActionType,
            "action_digest":     challenge.ActionDigest,
            "expires_at":        challenge.ExpiresAt.Format(time.RFC3339),
        },
        Priority: "high",
        TTL:      int(time.Until(challenge.ExpiresAt).Seconds()),
    })
}
```

---

## 5. API Specifications

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/sca/challenge` | POST | Bearer | Initiate SCA challenge |
| `/sca/status/{token}` | GET | Bearer | Get challenge status |
| `/sca/confirm` | POST | Device | Device confirms approval |
| `/sca/deny` | POST | Bearer/Device | User denies challenge |
| `/sca/exemptions/check` | POST | Service | Check if SCA exempt |
| `/sca/trusted-beneficiaries` | GET | Bearer | List trusted beneficiaries |
| `/sca/trusted-beneficiaries` | POST | Bearer+SCA | Add trusted beneficiary |
| `/sca/trusted-beneficiaries/{id}` | DELETE | Bearer+SCA | Remove trusted beneficiary |
| `/sca/methods` | GET | Bearer | Get enrolled SCA methods |

---

## 6. Security Requirements

### SR-1: Token Security
- SCA tokens cryptographically random (256 bits)
- Tokens single-use (consumed on validation)
- Tokens action-bound (cannot be reused for different action)
- Short expiry (15 minutes for challenge, 5 minutes after approval)

### SR-2: Challenge Binding
- Challenge includes action digest (SHA-256)
- Device approval must sign the action digest
- Mismatched digest = rejection

### SR-3: Method Security
- SMS OTP only as fallback (lower priority)
- Paired device requires biometric/PIN on device
- Rate limit challenge initiations (max 5 per hour)

### SR-4: Exemption Security
- Low value cumulative tracking (reset daily)
- Trusted beneficiary addition requires SCA
- Exemption abuse triggers risk review

---

## 7. Observability

### Metrics

```
# Counter: SCA challenges by method and outcome
sca_challenges_total{method, outcome="approved|denied|expired"}

# Histogram: Time to approve
sca_approval_duration_seconds{method}

# Counter: SCA exemptions applied
sca_exemptions_applied_total{type}

# Counter: SCA tokens validated
sca_tokens_validated_total{result="valid|invalid|expired|mismatch"}

# Gauge: Pending challenges
sca_challenges_pending
```

### Audit Events

- `sca.challenge_initiated` - Challenge created
- `sca.challenge_approved` - User approved
- `sca.challenge_denied` - User denied
- `sca.challenge_expired` - Challenge timed out
- `sca.token_validated` - Token used for action
- `sca.token_rejected` - Token validation failed
- `sca.exemption_applied` - Action exempt from SCA
- `sca.trusted_beneficiary_added` - New trusted beneficiary
- `sca.trusted_beneficiary_removed` - Removed trusted beneficiary

---

## 8. Acceptance Criteria

- [ ] 428 response returned when SCA required
- [ ] Challenge token returned with expiry
- [ ] Push notification sent to paired device
- [ ] Device can approve/deny challenge
- [ ] Polling endpoint shows challenge status
- [ ] Action retry with valid token succeeds
- [ ] Token rejected if action doesn't match
- [ ] Token rejected after expiry
- [ ] Token single-use (second use rejected)
- [ ] Low value exemption works with cumulative tracking
- [ ] Trusted beneficiary exemption works
- [ ] Adding trusted beneficiary requires SCA
- [ ] Audit trail complete for all SCA operations

---

## 9. Implementation Steps

### Phase 1: Challenge Flow (6-8 hours)
1. Challenge domain models
2. Store implementation
3. Initiate/Status/Confirm endpoints
4. Token generation and validation
5. Unit tests

### Phase 2: Device Integration (4-6 hours)
1. Push notification for paired device
2. Device confirmation endpoint
3. Approval signature verification
4. Integration with PRD-001 device binding

### Phase 3: Exemptions (3-4 hours)
1. Exemption models and store
2. Low value tracking
3. Trusted beneficiary management
4. Exemption check endpoint

### Phase 4: Middleware & Integration (3-4 hours)
1. RequireSCA middleware
2. 428 response handling
3. Action binding validation
4. Integration tests

### Phase 5: Sandbox Support (2 hours)
1. Mock SCA method for sandbox
2. Auto-approve option
3. Testing documentation

---

## 10. Future Enhancements

- WebAuthn/Passkey integration
- Hardware token support (YubiKey)
- SCA analytics dashboard
- Adaptive SCA (risk-based method selection)
- SCA delegation (approve on behalf of)
- Batch approval (multiple actions, one SCA)
- Offline approval (time-based approval codes)

---

## 11. References

- [PSD2 RTS on Strong Customer Authentication](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018R0389)
- [EBA Opinion on SCA Elements](https://www.eba.europa.eu/regulation-and-policy/payment-services-and-electronic-money)
- [Qonto SCA Documentation](https://docs.qonto.com/api-reference/business-api/authentication/sca/sca-flows)
- PRD-021: Multi-Factor Authentication
- PRD-027: Risk-Based Adaptive Authentication

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-22 | Engineering | Initial PRD |
