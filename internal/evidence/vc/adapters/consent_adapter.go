package adapters

import (
	"context"

	"credo/internal/evidence/vc/ports"
	id "credo/pkg/domain"
)

// consentRequirer defines the interface for consent enforcement.
// Defined locally to avoid coupling to consent service package.
type consentRequirer interface {
	Require(ctx context.Context, userID id.UserID, purpose id.ConsentPurpose) error
}

// ConsentAdapter bridges the consent service into the VC consent port.
type ConsentAdapter struct {
	consentService consentRequirer
}

// NewConsentAdapter creates a new in-process consent adapter.
func NewConsentAdapter(consentService consentRequirer) ports.ConsentPort {
	return &ConsentAdapter{consentService: consentService}
}

// RequireConsent enforces consent for the specified purpose.
func (a *ConsentAdapter) RequireConsent(ctx context.Context, userID id.UserID, purpose id.ConsentPurpose) error {
	return a.consentService.Require(ctx, userID, purpose)
}
