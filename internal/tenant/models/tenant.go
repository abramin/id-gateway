package models

import (
	"time"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// Tenant is the aggregate root for a tenant organization.
//
// Invariants:
//   - Name is non-empty and at most 128 characters
//   - Status is either active or inactive
//   - Status transitions: active ↔ inactive only (no other states)
//   - CreatedAt is immutable after construction
type Tenant struct {
	ID        id.TenantID  `json:"id"`
	Name      string       `json:"name"`
	Status    TenantStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

func (t *Tenant) IsActive() bool {
	return t.Status == TenantStatusActive
}

// Deactivate transitions the tenant to inactive status.
// Updates the timestamp to track when the transition occurred.
// Returns an error if the transition is not allowed.
func (t *Tenant) Deactivate(now time.Time) error {
	if !t.Status.CanTransitionTo(TenantStatusInactive) {
		return dErrors.New(dErrors.CodeInvariantViolation, "tenant is already inactive")
	}
	t.Status = TenantStatusInactive
	t.UpdatedAt = now
	return nil
}

// Reactivate transitions the tenant to active status.
// Updates the timestamp to track when the transition occurred.
// Returns an error if the transition is not allowed.
func (t *Tenant) Reactivate(now time.Time) error {
	if !t.Status.CanTransitionTo(TenantStatusActive) {
		return dErrors.New(dErrors.CodeInvariantViolation, "tenant is already active")
	}
	t.Status = TenantStatusActive
	t.UpdatedAt = now
	return nil
}

func NewTenant(tenantID id.TenantID, name string, now time.Time) (*Tenant, error) {
	if name == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "tenant name cannot be empty")
	}
	if len(name) > 128 {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "tenant name must be 128 characters or less")
	}
	return &Tenant{
		ID:        tenantID,
		Name:      name,
		Status:    TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

