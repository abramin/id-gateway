package adapters

import (
	"context"

	vccontracts "credo/contracts/vc"
	"credo/internal/decision/ports"
	id "credo/pkg/domain"
)

// VCService defines the interface for VC service operations used by the decision module.
// This allows the adapter to depend on an interface rather than a concrete service type.
type VCService interface {
	FindCredentialPresence(ctx context.Context, userID id.UserID, credType vccontracts.CredentialType) (*vccontracts.CredentialPresence, error)
}

// VCAdapter implements ports.VCPort by calling the VC service.
// Routes through the service layer rather than directly to the store,
// maintaining proper module boundaries.
type VCAdapter struct {
	service VCService
}

// NewVCAdapter creates a new VC adapter that routes through the VC service.
func NewVCAdapter(service VCService) ports.VCPort {
	return &VCAdapter{service: service}
}

// FindCredentialPresence checks if a valid credential exists for a user and type.
// Delegates to the VC service which handles not-found cases internally.
func (a *VCAdapter) FindCredentialPresence(ctx context.Context, userID id.UserID, credType vccontracts.CredentialType) (*vccontracts.CredentialPresence, error) {
	return a.service.FindCredentialPresence(ctx, userID, credType)
}
