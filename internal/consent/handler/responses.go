package handler

import (
	"fmt"
	"time"

	"credo/internal/consent/models"
)

// GrantResponse is returned after granting consent.
type GrantResponse struct {
	Granted []*Grant `json:"granted"`
	Message string   `json:"message,omitempty"`
}

// Grant represents a granted consent in HTTP responses.
type Grant struct {
	Purpose   models.Purpose `json:"purpose"`
	GrantedAt time.Time      `json:"granted_at"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	Status    models.Status  `json:"status"`
}

// RevokeResponse is returned after revoking consent.
type RevokeResponse struct {
	Revoked []*Revoked `json:"revoked"`
	Message string     `json:"message,omitempty"`
}

// Revoked represents a revoked consent in HTTP responses.
type Revoked struct {
	Purpose   models.Purpose `json:"purpose"`
	RevokedAt time.Time      `json:"revoked_at"`
	Status    models.Status  `json:"status"`
}

// ListResponse is returned when listing consents.
type ListResponse struct {
	Consents []*ConsentWithStatus `json:"consents"`
}

// Consent represents a consent record in HTTP responses (without status).
type Consent struct {
	ID        string         `json:"id"`
	Purpose   models.Purpose `json:"purpose"`
	GrantedAt time.Time      `json:"granted_at"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	RevokedAt *time.Time     `json:"revoked_at,omitempty"`
}

// ConsentWithStatus extends Consent with computed status.
type ConsentWithStatus struct {
	Consent
	Status models.Status `json:"status"`
}

func toGrantResponse(records []*models.Record, now time.Time) *GrantResponse {
	granted := make([]*Grant, 0, len(records))
	for _, record := range records {
		granted = append(granted, &Grant{
			Purpose:   record.Purpose,
			GrantedAt: record.GrantedAt,
			ExpiresAt: record.ExpiresAt,
			Status:    record.ComputeStatus(now),
		})
	}
	return &GrantResponse{
		Granted: granted,
		Message: formatActionMessage("Consent granted for %d purpose", len(records)),
	}
}

func toRevokeResponse(records []*models.Record, now time.Time) *RevokeResponse {
	revoked := make([]*Revoked, 0, len(records))
	for _, record := range records {
		if record.RevokedAt != nil {
			revoked = append(revoked, &Revoked{
				Purpose:   record.Purpose,
				RevokedAt: *record.RevokedAt,
				Status:    record.ComputeStatus(now),
			})
		}
	}
	return &RevokeResponse{
		Revoked: revoked,
		Message: formatActionMessage("Consent revoked for %d purpose", len(revoked)),
	}
}

func toListResponse(records []*models.Record, now time.Time) *ListResponse {
	consents := make([]*ConsentWithStatus, 0, len(records))
	for _, record := range records {
		consents = append(consents, &ConsentWithStatus{
			Consent: Consent{
				ID:        record.ID.String(),
				Purpose:   record.Purpose,
				GrantedAt: record.GrantedAt,
				ExpiresAt: record.ExpiresAt,
				RevokedAt: record.RevokedAt,
			},
			Status: record.ComputeStatus(now),
		})
	}
	return &ListResponse{Consents: consents}
}

func formatActionMessage(template string, count int) string {
	suffix := "s"
	if count == 1 {
		suffix = ""
	}
	return fmt.Sprintf(template+"%s", count, suffix)
}
