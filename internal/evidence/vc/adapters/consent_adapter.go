package adapters

import (
	"context"

	consentcontracts "credo/contracts/consent"
	"credo/internal/evidence/vc/ports"
	id "credo/pkg/domain"
)

// ConsentAdapter bridges the consent service into the VC consent port.
type ConsentAdapter struct {
	consentService consentcontracts.Requirer
}

// NewConsentAdapter creates a new in-process consent adapter.
func NewConsentAdapter(consentService consentcontracts.Requirer) ports.ConsentPort {
	return &ConsentAdapter{consentService: consentService}
}

// RequireConsent enforces consent for the specified purpose.
func (a *ConsentAdapter) RequireConsent(ctx context.Context, userID id.UserID, purpose id.ConsentPurpose) error {
	return a.consentService.Require(ctx, userID, purpose)
}
