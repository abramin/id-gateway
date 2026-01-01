# PRD-022: Account Recovery & Credential Management

**Status:** Not Started
**Priority:** P1 (High)
**Owner:** Engineering Team
**Dependencies:** PRD-001 (Authentication), PRD-018 (Notifications), PRD-016 (Token Lifecycle - partial completion)
**Last Updated:** 2025-12-24

## 1. Overview

### Problem Statement
Users cannot recover locked/lost accounts, leading to poor retention and support overhead.

### Goals
- Password reset flow (email-based)
- Account unlock (after brute force lockout)
- Email verification & change flow
- Security questions as recovery option
- Credential strength requirements
- Password history (prevent reuse)

---

## 2. Functional Requirements

### FR-1: Password Reset
**Endpoint:** `POST /auth/password/reset-request`
**Input:** `{"email": "user@example.com"}`
**Output:** `{"sent": true, "message": "Check your email"}`

### FR-2: Account Unlock
**Automatic unlock after 30 minutes of last failed attempt**

### FR-3: Email Verification

**Principle:** Validation should be minimal; treat email as opaque and verify by sending.

#### FR-3.1: Send Verification Email

**Endpoint:** `POST /auth/email/send-verification`

**Trigger:** Automatically on registration, or manually via endpoint

**Business Logic:**
1. Generate cryptographically secure token (32 bytes, URL-safe base64)
2. Store token with 24-hour expiry
3. Send verification email via PRD-018 Notification Service
4. Rate limit: max 3 verification emails per hour per address

**Error Cases:**
- 429 Too Many Requests: Rate limit exceeded
- 400 Bad Request: Email already verified

#### FR-3.2: Verify Email

**Endpoint:** `POST /auth/email/verify`

**Input:**
```json
{
  "token": "<verification_token>"
}
```

**Output (Success - 200):**
```json
{
  "verified": true,
  "email": "user@example.com"
}
```

**Business Logic:**
1. Validate token exists and is not expired
2. Mark `Email.verified = true`, record `verifiedAt` timestamp
3. Invalidate token (single-use)
4. Publish audit event: `email.verified`

**Error Cases:**
- 400 Bad Request: Invalid or expired token
- 410 Gone: Token already used

#### FR-3.3: Resend Verification

**Endpoint:** `POST /auth/email/resend-verification`

**Input:** `{"email": "user@example.com"}`

**Output:** `{"sent": true}`

**Business Logic:**
1. Invalidate any existing verification tokens for this email
2. Generate new token and send verification email
3. Subject to same rate limits as FR-3.1

#### FR-3.4: Email Verification Gating

**Gated Operations:** The following operations require a verified email:
- Consent grant (PRD-002)
- Evidence retrieval (PRD-003)
- Credential changes (password reset/change)
- Authorization code issuance and token exchange (OAuth login)

**Unverified Account Behavior:**
- Allow login and basic profile access
- Display verification reminder in UI
- Send reminder email after 24 hours if still unverified

#### FR-3.5: Name Derivation Guidance

**Principle:** Use derived names for UI display hints only, not stored identity.

- `DeriveNameFromEmail()` produces **ephemeral display values**
- User `FirstName`/`LastName` fields should be nullable until explicitly provided by user
- Alternative: derive display name lazily at render time, never persist to database
- Registration flow should prompt for name separately (optional field)

---

## 3. Technical Requirements

### TR-1: Email Domain Primitive

Create `Email` value object encapsulating verification state:

```go
// internal/auth/models/email.go

type Email struct {
    address    string
    verified   bool
    verifiedAt time.Time
}

// NewUnverifiedEmail creates an email with minimal validation.
// Validation is intentionally minimal: non-empty, contains @, length <= 254.
// The ultimate proof of validity is successful delivery.
func NewUnverifiedEmail(address string) (Email, error) {
    if err := validateEmailMinimal(address); err != nil {
        return Email{}, err
    }
    return Email{address: address, verified: false}, nil
}

// Verify transitions the email to verified state.
func (e *Email) Verify() {
    e.verified = true
    e.verifiedAt = time.Now().UTC()
}

// IsVerified returns true if email has been verified via token.
func (e Email) IsVerified() bool {
    return e.verified
}

// Address returns the email address string.
func (e Email) Address() string {
    return e.address
}

// VerifiedAt returns when the email was verified (zero if unverified).
func (e Email) VerifiedAt() time.Time {
    return e.verifiedAt
}
```

**Minimal Validation Function:**

```go
func validateEmailMinimal(email string) error {
    if len(email) == 0 {
        return errors.New("email cannot be empty")
    }
    if len(email) > 254 {
        return errors.New("email exceeds maximum length")
    }
    at := strings.LastIndexByte(email, '@')
    if at <= 0 || at >= len(email)-1 {
        return errors.New("email must contain @ with content on both sides")
    }
    return nil
}
```

**Rationale:** Over-validation rejects valid addresses (e.g., `user@localhost`, `user@[192.168.1.1]`). The current implementation checking for `.` in domain is too restrictive.

### TR-2: Verification Token Store

```go
type VerificationTokenStore interface {
    Create(ctx context.Context, token VerificationToken) error
    FindByToken(ctx context.Context, token string) (*VerificationToken, error)
    Invalidate(ctx context.Context, token string) error
    InvalidateByEmail(ctx context.Context, email string) error
    DeleteExpired(ctx context.Context) (int64, error)
}

type VerificationToken struct {
    Token     string
    Email     string
    ExpiresAt time.Time
    UsedAt    *time.Time
    CreatedAt time.Time
}
```

### TR-3: Migration Path

When implementing, migrate existing `internal/auth/email/email.go`:
1. Replace `IsValidEmail()` with `validateEmailMinimal()`
2. Deprecate `DeriveNameFromEmail()` or mark as UI-only utility
3. Update `models.User` to use `Email` value object
4. Add `verified` and `verified_at` columns to users table

---

## 4. Security Requirements

### SR-1: Minimal Email Validation

> **Principle:** Validation should be minimal; treat email as opaque and verify by sending.

- **DO:** Check non-empty, contains `@` with content on both sides, length <= 254
- **DON'T:** Validate TLD, require `.` in domain, regex pattern matching
- **Rationale:** Over-validation rejects valid addresses; delivery is the ultimate proof

### SR-2: Token Security

- Tokens must be cryptographically random (32 bytes minimum)
- Tokens must be single-use (invalidate after verification)
- Tokens must expire (24 hours default, configurable)
- Token lookup must be constant-time to prevent timing attacks

### SR-3: Rate Limiting

- Max 3 verification emails per email address per hour
- Max 10 verification attempts per IP per hour
- Failed verification attempts logged for abuse detection

### SR-4: Audit Events

| Event | Trigger | Fields |
|-------|---------|--------|
| `email.verification_sent` | Verification email sent | `email`, `token_id` |
| `email.verified` | Successful verification | `email`, `user_id` |
| `email.verification_failed` | Invalid/expired token | `email`, `reason` |

---

## 5. Acceptance Criteria

- [ ] Password reset emails delivered
- [ ] Reset links expire after 24 hours
- [ ] Account auto-unlocks after cooldown
- [ ] Email verification required before sensitive ops
- [ ] Password change triggers global session revocation (completes PRD-016 FR-6)
- [ ] Email domain primitive with verification state implemented
- [ ] Minimal validation replaces over-validation in `IsValidEmail()`
- [ ] Verification tokens are cryptographically secure and single-use
- [ ] Name derivation documented as UI-only, not persisted identity

---

## 6. Related PRDs

**PRD-016 Completion:** When implementing password change/reset, also implement:
- Global session revocation on password change (PRD-016 acceptance criterion)

**PRD-018 Dependency:** Email delivery infrastructure required for:
- Verification emails
- Password reset emails
- Security alert notifications

See [PRD-016](./PRD-016-Token-Lifecycle-Revocation.md) Section 6 Acceptance Criteria.

---

## Revision History

| Version | Date       | Author       | Changes                                                  |
| ------- | ---------- | ------------ | -------------------------------------------------------- |
| 1.0     | 2025-12-12 | Product Team | Initial PRD                                              |
| 1.1     | 2025-12-24 | Engineering  | Expanded FR-3 with verification flow, Email domain primitive, minimal validation philosophy, security requirements |
