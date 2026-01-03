package ports

import (
	"context"

	vccontracts "credo/contracts/vc"
	id "credo/pkg/domain"
)

// VCPort defines the interface for VC lookups in the decision engine.
// This port allows finding existing credentials by subject/type without
// depending on the VC store or internal models directly.
type VCPort interface {
	// FindCredentialPresence checks if a valid credential exists for a user and type.
	// Returns a minimal contract type (Exists, Claims) rather than the full record.
	// Returns nil, error only for infrastructure failures.
	FindCredentialPresence(ctx context.Context, userID id.UserID, credType vccontracts.CredentialType) (*vccontracts.CredentialPresence, error)
}
