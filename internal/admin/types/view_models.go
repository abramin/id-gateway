package types

import (
	"time"

	id "credo/pkg/domain"
)

// AdminUser contains user fields needed for admin display.
// This is an admin-local DTO to avoid coupling to auth models.
type AdminUser struct {
	ID        id.UserID
	TenantID  id.TenantID
	Email     string
	FirstName string
	LastName  string
	Verified  bool
	Active    bool
}

// AdminSession contains session fields needed for admin display.
// This is an admin-local DTO to avoid coupling to auth models.
type AdminSession struct {
	ID        id.SessionID
	UserID    id.UserID
	CreatedAt time.Time
	ExpiresAt time.Time
	Active    bool
}
