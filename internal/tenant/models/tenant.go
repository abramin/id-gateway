package models

import (
	"time"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

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
// Returns an error if the tenant is already inactive.
func (t *Tenant) Deactivate(now time.Time) error {
	if !t.IsActive() {
		return dErrors.New(dErrors.CodeInvariantViolation, "tenant is already inactive")
	}
	t.Status = TenantStatusInactive
	t.UpdatedAt = now
	return nil
}

// Reactivate transitions the tenant to active status.
// Updates the timestamp to track when the transition occurred.
// Returns an error if the tenant is already active.
func (t *Tenant) Reactivate(now time.Time) error {
	if t.IsActive() {
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

// TenantDetails aggregates tenant metadata with counts for admin dashboards.
// Internal type - converted to TenantDetailsResponse for HTTP serialization.
type TenantDetails struct {
	ID          id.TenantID
	Name        string
	Status      TenantStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
	UserCount   int
	ClientCount int
}
