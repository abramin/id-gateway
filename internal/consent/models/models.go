package models

import (
	"fmt"
	"time"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
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

// GrantEvaluation captures the result of evaluating a grant request against an existing record.
type GrantEvaluation struct {
	// Updated contains the renewed record if Changed is true.
	Updated Record
	// Changed indicates whether the record was modified.
	Changed bool
	// WasActive indicates whether the record was active before evaluation.
	// Used by callers to track metrics (e.g., new active consent vs renewal).
	WasActive bool
}

// EvaluateGrant applies idempotency and re-grant cooldown rules to determine if a grant should proceed.
// Returns a GrantEvaluation describing the outcome:
//   - If active and within idempotencyWindow: no change (idempotent)
//   - If recently revoked (within cooldown): returns error
//   - Otherwise: returns renewed record with Changed=true
func (c Record) EvaluateGrant(now time.Time, idempotencyWindow, reGrantCooldown, ttl time.Duration) (GrantEvaluation, error) {
	eval := GrantEvaluation{WasActive: c.IsActive(now)}

	// Idempotency: if active and recently granted, skip update
	if eval.WasActive && now.Sub(c.GrantedAt) < idempotencyWindow {
		return eval, nil
	}

	// Re-grant cooldown: prevent rapid revoke→grant cycles
	if !c.CanReGrant(now, reGrantCooldown) {
		return GrantEvaluation{}, dErrors.New(dErrors.CodeBadRequest,
			fmt.Sprintf("consent was recently revoked; please wait before re-granting (cooldown: %v)", reGrantCooldown))
	}

	// Renew the consent
	updated, err := c.RenewAt(now, ttl)
	if err != nil {
		return GrantEvaluation{}, err
	}

	eval.Updated = updated
	eval.Changed = true
	return eval, nil
}

// RenewAt returns an updated record with a new grant window applied.
// It clears RevokedAt and sets ExpiresAt based on the provided TTL.
func (c Record) RenewAt(now time.Time, ttl time.Duration) (Record, error) {
	if now.IsZero() {
		return Record{}, dErrors.New(dErrors.CodeInvariantViolation, "grant time required")
	}
	if ttl <= 0 {
		return Record{}, dErrors.New(dErrors.CodeInvariantViolation, "consent TTL must be positive")
	}
	expiry := now.Add(ttl)
	updated := c
	updated.GrantedAt = now
	updated.ExpiresAt = &expiry
	updated.RevokedAt = nil
	return updated, nil
}

// RevokeAt returns an updated record with RevokedAt set to the provided time.
func (c Record) RevokeAt(now time.Time) (Record, error) {
	if now.IsZero() {
		return Record{}, dErrors.New(dErrors.CodeInvariantViolation, "revocation time required")
	}
	updated := c
	updated.RevokedAt = &now
	return updated, nil
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

// Ensure enforces that consent exists and is active for the given purpose.
func Ensure(consents []*Record, purpose Purpose, now time.Time) error {
	for _, c := range consents {
		if c.Purpose == purpose && c.IsActive(now) {
			return nil
		}
	}
	return dErrors.New(dErrors.CodeMissingConsent, "consent not granted for required purpose")
}
