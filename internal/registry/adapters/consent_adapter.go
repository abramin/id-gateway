package adapters

import (
	"context"

	"credo/internal/consent/models"
	"credo/internal/consent/service"
	"credo/internal/registry/ports"
)

// ConsentAdapter is an in-process adapter that implements ports.ConsentPort
// by directly calling the consent service. This maintains the hexagonal
// architecture boundaries while keeping everything in a single process.
// When splitting into microservices, this can be replaced with a gRPC adapter
// without changing the registry domain layer.
type ConsentAdapter struct {
	consentService *service.Service
}

// NewConsentAdapter creates a new in-process consent adapter
func NewConsentAdapter(consentService *service.Service) ports.ConsentPort {
	return &ConsentAdapter{
		consentService: consentService,
	}
}

// HasConsent checks if user has valid consent for a purpose
func (a *ConsentAdapter) HasConsent(ctx context.Context, userID string, purpose string) (bool, error) {
	consents, err := a.consentService.List(ctx, userID, nil)
	if err != nil {
		return false, err
	}

	// Find consent for this purpose and check if active
	for _, c := range consents.Consents {
		if string(c.Purpose) == purpose && c.Status == models.StatusActive {
			return true, nil
		}
	}

	return false, nil
}

// RequireConsent enforces consent requirement - returns error if not granted
func (a *ConsentAdapter) RequireConsent(ctx context.Context, userID string, purpose string) error {
	return a.consentService.Require(ctx, userID, models.Purpose(purpose))
}
