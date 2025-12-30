package adapters

import (
	"context"

	"credo/internal/consent/models"
	"credo/internal/consent/service"
	"credo/internal/evidence/vc/ports"
	id "credo/pkg/domain"
)

// ConsentAdapter bridges the consent service into the VC consent port.
type ConsentAdapter struct {
	consentService *service.Service
}

// NewConsentAdapter creates a new in-process consent adapter.
func NewConsentAdapter(consentService *service.Service) ports.ConsentPort {
	return &ConsentAdapter{consentService: consentService}
}

// RequireVCIssuance enforces vc_issuance consent for the user.
func (a *ConsentAdapter) RequireVCIssuance(ctx context.Context, userID id.UserID) error {
	return a.consentService.Require(ctx, userID, models.PurposeVCIssuance)
}
