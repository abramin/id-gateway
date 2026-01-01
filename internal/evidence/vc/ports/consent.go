package ports

import (
	"context"

	id "credo/pkg/domain"
)

// ConsentPort defines the interface for consent checks.
// This is a hexagonal architecture port - the service layer depends on this interface,
// and adapters (in-process, gRPC client, mock) implement it.
type ConsentPort interface {
	// RequireConsent enforces consent requirement for a purpose.
	// Returns nil if consent is active, error otherwise.
	// Error types should match pkg/domain-errors conventions.
	RequireConsent(ctx context.Context, userID id.UserID, purpose string) error
}
