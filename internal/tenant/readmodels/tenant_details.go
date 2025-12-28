// Package readmodels contains query-optimized data structures for read operations.
// These are separate from domain models to allow independent evolution
// and optimization for display/reporting use cases.
package readmodels

import (
	"time"

	"credo/internal/tenant/models"
	id "credo/pkg/domain"
)

// TenantDetails aggregates tenant metadata with counts for admin dashboards.
// This is a read model optimized for display - not a domain aggregate.
type TenantDetails struct {
	ID          id.TenantID
	Name        string
	Status      models.TenantStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
	UserCount   int
	ClientCount int
}
