// Package consent defines stable contract types for cross-module consent boundaries.
package consent

import (
	"context"

	id "credo/pkg/domain"
)

// Requirer defines the interface for consent enforcement across module boundaries.
// Adapters in decision, evidence/registry, and evidence/vc use this interface
// to depend on consent behavior without importing the consent service package.
type Requirer interface {
	Require(ctx context.Context, userID id.UserID, purpose id.ConsentPurpose) error
}
