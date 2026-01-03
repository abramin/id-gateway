package adapters

import (
	"context"

	"credo/internal/evidence/registry/ports"
	id "credo/pkg/domain"
)

// consentRequirer defines the interface for consent enforcement.
// Defined locally to avoid coupling to consent service package.
type consentRequirer interface {
	Require(ctx context.Context, userID id.UserID, purpose id.ConsentPurpose) error
}

// ConsentAdapter is an in-process adapter that implements ports.ConsentPort
// by directly calling the consent service. This maintains the hexagonal
// architecture boundaries while keeping everything in a single process.
type ConsentAdapter struct {
	consentService consentRequirer
}

// NewConsentAdapter creates a new in-process consent adapter.
func NewConsentAdapter(consentService consentRequirer) ports.ConsentPort {
	return &ConsentAdapter{
		consentService: consentService,
	}
}

// RequireConsent enforces consent requirement - returns error if not granted.
func (a *ConsentAdapter) RequireConsent(ctx context.Context, userID id.UserID, purpose id.ConsentPurpose) error {
	return a.consentService.Require(ctx, userID, purpose)
}
