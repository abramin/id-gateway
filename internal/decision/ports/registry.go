package ports

import (
	"context"
	"time"

	id "credo/pkg/domain"
)

// RegistryPort defines the interface for registry lookups
// This port allows the decision engine to fetch identity evidence
// without depending on gRPC, HTTP, or specific registry implementations.
type RegistryPort interface {
	// CheckCitizen retrieves citizen record by national ID
	// Returns minimized data in regulated mode
	// userID is required for consent verification
	CheckCitizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*CitizenRecord, error)

	// CheckSanctions retrieves sanctions record by national ID
	// Always returns minimal data (no PII)
	// userID is required for consent verification
	CheckSanctions(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*SanctionsRecord, error)

	// Check performs combined citizen + sanctions lookup
	// Optimized for parallel execution
	// userID is required for consent verification
	Check(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*CitizenRecord, *SanctionsRecord, error)
}

// CitizenRecord represents citizen identity data (port model)
// This is a domain model, not a protobuf or database model
type CitizenRecord struct {
	NationalID  string
	FullName    string // Empty in regulated mode
	DateOfBirth string // Empty in regulated mode (YYYY-MM-DD)
	Valid       bool
	CheckedAt   time.Time
}

// SanctionsRecord represents sanctions/PEP status (port model)
// No PII - safe for any mode
type SanctionsRecord struct {
	NationalID string
	Listed     bool
	Source     string
	CheckedAt  time.Time
}
