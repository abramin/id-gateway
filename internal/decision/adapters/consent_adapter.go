package adapters

import (
	"context"

	consentcontracts "credo/contracts/consent"
	"credo/internal/decision/ports"
	id "credo/pkg/domain"
)

// ConsentAdapter implements ports.ConsentPort by calling the consent service.
// This maintains hexagonal architecture boundaries while keeping
// everything in a single process.
type ConsentAdapter struct {
	consent consentcontracts.Requirer
}

// NewConsentAdapter creates a new consent adapter.
func NewConsentAdapter(consent consentcontracts.Requirer) ports.ConsentPort {
	return &ConsentAdapter{consent: consent}
}

// RequireConsent enforces consent requirement.
// Side effects: calls the consent service and returns its error.
func (a *ConsentAdapter) RequireConsent(ctx context.Context, userID id.UserID, purpose id.ConsentPurpose) error {
	return a.consent.Require(ctx, userID, purpose)
}
