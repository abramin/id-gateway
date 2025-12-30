package ports

import (
	"context"

	id "credo/pkg/domain"
)

// ConsentPort defines the interface for consent checks.
// This is a hexagonal architecture port - the service layer depends on this interface,
// and adapters (in-process, gRPC client, mock) implement it.
type ConsentPort interface {
	// RequireVCIssuance enforces consent requirement for VC issuance.
	// Returns nil if consent is active, error otherwise.
	// Error types should match pkg/domain-errors conventions.
	RequireVCIssuance(ctx context.Context, userID id.UserID) error
}
