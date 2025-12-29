package models

import (
	"time"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// Audit event actions
const (
	AuditActionConsentGranted     = "consent_granted"
	AuditActionConsentRevoked     = "consent_revoked"
	AuditActionConsentDeleted     = "consent_deleted"
	AuditActionConsentCheckPassed = "consent_check_passed"
	AuditActionConsentCheckFailed = "consent_check_failed"
)

// Audit event decisions
const (
	AuditDecisionGranted = "granted"
	AuditDecisionRevoked = "revoked"
	AuditDecisionDeleted = "deleted"
	AuditDecisionDenied  = "denied"
)

// Audit event reasons
const (
	AuditReasonUserInitiated = "user_initiated"
)

// Record captures a user's decision for a specific purpose.
//
// # Scoping Invariant
//
// A ConsentID is ALWAYS scoped by (UserID, Purpose). The combination is unique:
// each user can have at most one consent record per purpose.
//
// Security Implications:
//   - ConsentID alone is NOT sufficient to authorize access to a record
//   - All queries MUST include UserID to prevent cross-user access
//   - The store layer enforces this invariant by requiring UserID in all queries
//   - Never expose ConsentID in URLs/APIs without also validating UserID ownership
//
// This design prevents:
//   - Enumeration attacks (guessing ConsentIDs to access other users' data)
//   - IDOR vulnerabilities (accessing records by ConsentID without ownership check)
//   - Data leakage via consent record manipulation
type Record struct {
	ID        id.ConsentID
	UserID    id.UserID
	Purpose   Purpose
	GrantedAt time.Time
	ExpiresAt *time.Time
	RevokedAt *time.Time
}

// NewRecord creates a Record with domain invariant checks.
func NewRecord(consentID id.ConsentID, userID id.UserID, purpose Purpose, grantedAt time.Time, expiresAt *time.Time) (*Record, error) {
	if consentID.IsNil() {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "consent ID required")
	}
	if userID.IsNil() {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "user ID required")
	}
	if !purpose.IsValid() {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "invalid consent purpose")
	}
	if grantedAt.IsZero() {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "grant time required")
	}
	if expiresAt != nil && expiresAt.Before(grantedAt) {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "expiry must be after grant time")
	}
	return &Record{
		ID:        consentID,
		UserID:    userID,
		Purpose:   purpose,
		GrantedAt: grantedAt,
		ExpiresAt: expiresAt,
	}, nil
}

// IsActive returns true when consent is currently valid.
func (c Record) IsActive(now time.Time) bool {
	if c.RevokedAt != nil {
		return false
	}
	if c.ExpiresAt != nil && c.ExpiresAt.Before(now) {
		return false
	}
	return true
}

// CanRevoke returns true if the consent can be revoked (not already revoked or expired).
func (c Record) CanRevoke(now time.Time) bool {
	if c.RevokedAt != nil {
		return false
	}
	if c.ExpiresAt != nil && c.ExpiresAt.Before(now) {
		return false
	}
	return true
}

// DefaultReGrantCooldown is the default minimum time after revocation before re-grant is allowed.
// This prevents abuse patterns where users rapidly toggle consent to circumvent audit trails.
const DefaultReGrantCooldown = 5 * time.Minute

// CanReGrant returns true if enough time has passed since revocation to allow re-granting.
// This prevents rapid revoke→grant cycles that could be used to:
// - Circumvent audit trail analysis
// - Exploit race conditions in consent-dependent workflows
// - Generate artificial consent churn for gaming metrics
//
// If the consent was never revoked, or the cooldown period has elapsed, returns true.
func (c Record) CanReGrant(now time.Time, cooldown time.Duration) bool {
	if c.RevokedAt == nil {
		// Not revoked, can always grant (including first-time grants)
		return true
	}
	// Check if cooldown period has elapsed since revocation
	return now.Sub(*c.RevokedAt) >= cooldown
}

// ComputeStatus reports the consent lifecycle state at the provided time.
func (c Record) ComputeStatus(now time.Time) Status {
	if c.RevokedAt != nil {
		return StatusRevoked
	}
	if c.ExpiresAt != nil && c.ExpiresAt.Before(now) {
		return StatusExpired
	}
	return StatusActive
}

// RecordFilter allows filtering consent records by purpose and status.
type RecordFilter struct {
	Purpose *Purpose
	Status  *Status
}

// Ensure enforces that consent exists and is active for the given purpose.
func Ensure(consents []*Record, purpose Purpose, now time.Time) error {
	for _, c := range consents {
		if c.Purpose == purpose && c.IsActive(now) {
			return nil
		}
	}
	return dErrors.New(dErrors.CodeMissingConsent, "consent not granted for required purpose")
}
