package dto

import "time"

// GrantResponse is returned after granting consent.
type GrantResponse struct {
	Granted []*Grant `json:"granted"`
	Message string   `json:"message,omitempty"`
}

// Grant represents a granted consent in HTTP responses.
type Grant struct {
	Purpose   string     `json:"purpose"`
	GrantedAt time.Time  `json:"granted_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Status    string     `json:"status"`
}

// RevokeResponse is returned after revoking consent.
type RevokeResponse struct {
	Revoked []*Revoked `json:"revoked"`
	Message string     `json:"message,omitempty"`
}

// Revoked represents a revoked consent in HTTP responses.
type Revoked struct {
	Purpose   string    `json:"purpose"`
	RevokedAt time.Time `json:"revoked_at"`
	Status    string    `json:"status"`
}

// ListResponse is returned when listing consents.
type ListResponse struct {
	Consents []*ConsentWithStatus `json:"consents"`
}

// Consent represents a consent record in HTTP responses (without status).
type Consent struct {
	ID        string     `json:"id"`
	Purpose   string     `json:"purpose"`
	GrantedAt time.Time  `json:"granted_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// ConsentWithStatus extends Consent with computed status.
type ConsentWithStatus struct {
	Consent
	Status string `json:"status"`
}
