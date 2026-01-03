package adapters

import (
	"context"

	"credo/internal/decision/ports"
	id "credo/pkg/domain"
)

// consentRequirer defines the interface for consent enforcement.
// Defined locally to avoid coupling to consent service package.
type consentRequirer interface {
	Require(ctx context.Context, userID id.UserID, purpose id.ConsentPurpose) error
}

// ConsentAdapter implements ports.ConsentPort by calling the consent service.
// This maintains hexagonal architecture boundaries while keeping
// everything in a single process.
type ConsentAdapter struct {
	consent consentRequirer
}

// NewConsentAdapter creates a new consent adapter.
func NewConsentAdapter(consent consentRequirer) ports.ConsentPort {
	return &ConsentAdapter{consent: consent}
}

// RequireConsent enforces consent requirement.
// Side effects: calls the consent service and returns its error.
func (a *ConsentAdapter) RequireConsent(ctx context.Context, userID id.UserID, purpose id.ConsentPurpose) error {
	return a.consent.Require(ctx, userID, purpose)
}
