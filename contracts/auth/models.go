package auth

import "time"

// Package auth hosts the stable, minimal DTOs shared across services for
// auth user/session data. Keep these versioned independently from internal
// auth schemas or persistence models.

// ContractVersion identifies the contract schema version for compatibility checks.
// Bump on breaking changes to the shapes below; consumers can pin or roll forward.
const ContractVersion = "v0.1.0"

// AdminUserView is the minimal user info needed by admin operations.
// Contains only fields relevant for administrative display/management.
type AdminUserView struct {
	ID        string
	TenantID  string
	Email     string
	FirstName string
	LastName  string
	Verified  bool
	Active    bool
}

// AdminSessionView is the minimal session info needed by admin operations.
type AdminSessionView struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	Active    bool
}
