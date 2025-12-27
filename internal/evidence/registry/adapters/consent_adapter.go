package adapters

import (
	"context"

	"credo/internal/consent/models"
	"credo/internal/consent/service"
	"credo/internal/evidence/registry/ports"
	id "credo/pkg/domain"
)

// ConsentAdapter is an in-process adapter that implements ports.ConsentPort
// by directly calling the consent service. This maintains the hexagonal
// architecture boundaries while keeping everything in a single process.
type ConsentAdapter struct {
	consentService *service.Service
}

// NewConsentAdapter creates a new in-process consent adapter.
func NewConsentAdapter(consentService *service.Service) ports.ConsentPort {
	return &ConsentAdapter{
		consentService: consentService,
	}
}

// RequireConsent enforces consent requirement - returns error if not granted.
func (a *ConsentAdapter) RequireConsent(ctx context.Context, userID string, purpose string) error {
	parsedUserID, err := id.ParseUserID(userID)
	if err != nil {
		return err
	}
	parsedPurpose, err := models.ParsePurpose(purpose)
	if err != nil {
		return err
	}
	return a.consentService.Require(ctx, parsedUserID, parsedPurpose)
}
