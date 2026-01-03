package adapters

import (
	"context"

	consentcontracts "credo/contracts/consent"
	"credo/internal/evidence/registry/ports"
	id "credo/pkg/domain"
)

// ConsentAdapter is an in-process adapter that implements ports.ConsentPort
// by directly calling the consent service. This maintains the hexagonal
// architecture boundaries while keeping everything in a single process.
type ConsentAdapter struct {
	consentService consentcontracts.Requirer
}

// NewConsentAdapter creates a new in-process consent adapter.
func NewConsentAdapter(consentService consentcontracts.Requirer) ports.ConsentPort {
	return &ConsentAdapter{
		consentService: consentService,
	}
}

// RequireConsent enforces consent requirement - returns error if not granted.
func (a *ConsentAdapter) RequireConsent(ctx context.Context, userID id.UserID, purpose id.ConsentPurpose) error {
	return a.consentService.Require(ctx, userID, purpose)
}
