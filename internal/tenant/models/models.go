package models

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
)

// Tenant represents an isolated identity boundary.
type Tenant struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Client represents an OAuth relying party registered under a tenant.
type Client struct {
	ID               uuid.UUID `json:"id"`
	TenantID         uuid.UUID `json:"tenant_id"`
	Name             string    `json:"name"`
	ClientID         string    `json:"client_id"`
	ClientSecretHash string    `json:"client_secret_hash,omitempty"`
	RedirectURIs     []string  `json:"redirect_uris"`
	AllowedGrants    []string  `json:"allowed_grants"`
	AllowedScopes    []string  `json:"allowed_scopes"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// ClientResponse is returned to callers and includes the cleartext secret when rotated.
type ClientResponse struct {
	ID            uuid.UUID `json:"id"`
	TenantID      uuid.UUID `json:"tenant_id"`
	Name          string    `json:"name"`
	ClientID      string    `json:"client_id"`
	ClientSecret  string    `json:"client_secret,omitempty"`
	RedirectURIs  []string  `json:"redirect_uris"`
	AllowedGrants []string  `json:"allowed_grants"`
	AllowedScopes []string  `json:"allowed_scopes"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TenantDetails aggregates tenant metadata with counts for admin dashboards.
type TenantDetails struct {
	Tenant      *Tenant `json:"tenant"`
	UserCount   int     `json:"user_count"`
	ClientCount int     `json:"client_count"`
}

// CreateClientRequest captures required client fields.
type CreateClientRequest struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	Name          string    `json:"name"`
	RedirectURIs  []string  `json:"redirect_uris"`
	AllowedGrants []string  `json:"allowed_grants"`
	AllowedScopes []string  `json:"allowed_scopes"`
	Public        bool      `json:"public_client"`
}

func (r *CreateClientRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	if r.TenantID == uuid.Nil {
		return dErrors.New(dErrors.CodeValidation, "tenant_id is required")
	}
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return dErrors.New(dErrors.CodeValidation, "name is required")
	}
	if len(r.Name) > 128 {
		return dErrors.New(dErrors.CodeValidation, "name must be 128 characters or less")
	}
	if len(r.RedirectURIs) == 0 {
		return dErrors.New(dErrors.CodeValidation, "redirect_uris are required")
	}
	for _, uri := range r.RedirectURIs {
		if err := validateRedirectURI(uri); err != nil {
			return err
		}
	}
	if len(r.AllowedGrants) == 0 {
		return dErrors.New(dErrors.CodeValidation, "allowed_grants are required")
	}
	if err := validateGrants(r.AllowedGrants); err != nil {
		return err
	}
	if r.Public {
		for _, grant := range r.AllowedGrants {
			if grant == "client_credentials" {
				return dErrors.New(dErrors.CodeValidation, "client_credentials grant requires a confidential client")
			}
		}
	}
	if len(r.AllowedScopes) == 0 {
		return dErrors.New(dErrors.CodeValidation, "allowed_scopes are required")
	}
	return nil
}

func validateRedirectURI(uri string) error {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme == "" {
		return dErrors.New(dErrors.CodeValidation, "invalid redirect_uri")
	}
	if parsed.Host == "" {
		return dErrors.New(dErrors.CodeValidation, "redirect_uri must include host")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && strings.HasPrefix(parsed.Host, "localhost")) {
		return dErrors.New(dErrors.CodeValidation, "redirect_uri must be https or localhost for development")
	}
	return nil
}

func validateGrants(grants []string) error {
	allowed := map[string]struct{}{
		"authorization_code": {},
		"refresh_token":      {},
		"client_credentials": {},
	}
	for _, grant := range grants {
		if _, ok := allowed[grant]; !ok {
			return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("unsupported grant: %s", grant))
		}
	}
	return nil
}

// UpdateClientRequest supports partial updates.
type UpdateClientRequest struct {
	Name          *string   `json:"name,omitempty"`
	RedirectURIs  *[]string `json:"redirect_uris,omitempty"`
	AllowedGrants *[]string `json:"allowed_grants,omitempty"`
	AllowedScopes *[]string `json:"allowed_scopes,omitempty"`
	RotateSecret  bool      `json:"rotate_secret"`
}

func (r *UpdateClientRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	if r.Name != nil {
		trimmed := strings.TrimSpace(*r.Name)
		if trimmed == "" {
			return dErrors.New(dErrors.CodeValidation, "name cannot be empty")
		}
		if len(trimmed) > 128 {
			return dErrors.New(dErrors.CodeValidation, "name must be 128 characters or less")
		}
	}
	if r.RedirectURIs != nil {
		if len(*r.RedirectURIs) == 0 {
			return dErrors.New(dErrors.CodeValidation, "redirect_uris cannot be empty")
		}
		for _, uri := range *r.RedirectURIs {
			if err := validateRedirectURI(uri); err != nil {
				return err
			}
		}
	}
	if r.AllowedGrants != nil {
		if len(*r.AllowedGrants) == 0 {
			return dErrors.New(dErrors.CodeValidation, "allowed_grants cannot be empty")
		}
		if err := validateGrants(*r.AllowedGrants); err != nil {
			return err
		}
	}
	if r.AllowedScopes != nil && len(*r.AllowedScopes) == 0 {
		return dErrors.New(dErrors.CodeValidation, "allowed_scopes cannot be empty")
	}
	return nil
}
