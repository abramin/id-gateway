package models

import "time"

type TenantResponse struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Status    TenantStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

type TenantCreateResponse struct {
	TenantID string          `json:"tenant_id"`
	Tenant   *TenantResponse `json:"tenant"`
}

type TenantDetailsResponse struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Status      TenantStatus `json:"status"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	UserCount   int          `json:"user_count"`
	ClientCount int          `json:"client_count"`
}

type ClientResponse struct {
	ID            string   `json:"id"`
	TenantID      string   `json:"tenant_id"`
	Name          string   `json:"name"`
	OAuthClientID string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedGrants []string `json:"allowed_grants"`
	AllowedScopes []string `json:"allowed_scopes"`
	Status        string   `json:"status"`
}
