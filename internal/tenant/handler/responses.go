package handler

import (
	"time"

	"credo/internal/tenant/models"
	"credo/internal/tenant/readmodels"
)

type TenantResponse struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	Status    models.TenantStatus `json:"status"`
	CreatedAt time.Time           `json:"created_at"`
	UpdatedAt time.Time           `json:"updated_at"`
}

type TenantCreateResponse struct {
	TenantID string          `json:"tenant_id"`
	Tenant   *TenantResponse `json:"tenant"`
}

type TenantDetailsResponse struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Status      models.TenantStatus `json:"status"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
	UserCount   int                 `json:"user_count"`
	ClientCount int                 `json:"client_count"`
}

type ClientResponse struct {
	ID            string   `json:"id"`
	TenantID      string   `json:"tenant_id"`
	Name          string   `json:"name"`
	OAuthClientID string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret,omitempty"` // Only included on create/rotate
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedGrants []string `json:"allowed_grants"`
	AllowedScopes []string `json:"allowed_scopes"`
	Status        string   `json:"status"`
	PublicClient  bool     `json:"public_client"`
}

// Response mapping functions - convert domain objects to HTTP DTOs

func toTenantResponse(t *models.Tenant) *TenantResponse {
	return &TenantResponse{
		ID:        t.ID.String(),
		Name:      t.Name,
		Status:    t.Status,
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
	}
}

func toTenantDetailsResponse(td *readmodels.TenantDetails) *TenantDetailsResponse {
	return &TenantDetailsResponse{
		ID:          td.ID.String(),
		Name:        td.Name,
		Status:      td.Status,
		CreatedAt:   td.CreatedAt,
		UpdatedAt:   td.UpdatedAt,
		UserCount:   td.UserCount,
		ClientCount: td.ClientCount,
	}
}

func toClientResponse(client *models.Client, secret string) *ClientResponse {
	return &ClientResponse{
		ID:            client.ID.String(),
		TenantID:      client.TenantID.String(),
		Name:          client.Name,
		OAuthClientID: client.OAuthClientID,
		ClientSecret:  secret, // Empty string omitted due to omitempty tag
		RedirectURIs:  client.RedirectURIs,
		AllowedGrants: grantTypesToStrings(client.AllowedGrants),
		AllowedScopes: client.AllowedScopes,
		Status:        client.Status.String(),
		PublicClient:  !client.IsConfidential(),
	}
}

// grantTypesToStrings converts typed grant types to strings for DTO serialization.
func grantTypesToStrings(grants []models.GrantType) []string {
	result := make([]string, len(grants))
	for i, g := range grants {
		result[i] = g.String()
	}
	return result
}
