package handler

import (
	"strings"

	"credo/internal/tenant/models"
	"credo/internal/tenant/service"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	strutil "credo/pkg/platform/strings"
)

// HTTP Request DTOs - contain JSON tags for API serialization.
// These are converted to service commands before processing.

type CreateTenantRequest struct {
	Name string `json:"name"`
}

func (r *CreateTenantRequest) Normalize() {
	if r == nil {
		return
	}
	r.Name = strings.TrimSpace(r.Name)
}

func (r *CreateTenantRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	if r.Name == "" {
		return dErrors.New(dErrors.CodeValidation, "name is required")
	}
	return nil
}

type CreateClientRequest struct {
	TenantID      string   `json:"tenant_id"`
	Name          string   `json:"name"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedGrants []string `json:"allowed_grants"`
	AllowedScopes []string `json:"allowed_scopes"`
	Public        bool     `json:"public_client"`
}

// Normalize trims input and deduplicates collections for stable validation/storage.
func (r *CreateClientRequest) Normalize() {
	if r == nil {
		return
	}
	r.Name = strings.TrimSpace(r.Name)
	r.RedirectURIs = strutil.DedupeAndTrim(r.RedirectURIs)
	r.AllowedGrants = strutil.DedupeAndTrimLower(r.AllowedGrants)
	r.AllowedScopes = strutil.DedupeAndTrim(r.AllowedScopes)
}

// ToCommand converts the HTTP request to a service command.
// Returns an error if the tenant ID is invalid.
func (r *CreateClientRequest) ToCommand() (*service.CreateClientCommand, error) {
	tenantID, err := id.ParseTenantID(r.TenantID)
	if err != nil {
		return nil, err
	}

	grants := make([]models.GrantType, len(r.AllowedGrants))
	for i, g := range r.AllowedGrants {
		grants[i] = models.GrantType(g)
	}

	return &service.CreateClientCommand{
		TenantID:      tenantID,
		Name:          r.Name,
		RedirectURIs:  r.RedirectURIs,
		AllowedGrants: grants,
		AllowedScopes: r.AllowedScopes,
		Public:        r.Public,
	}, nil
}

type UpdateClientRequest struct {
	Name          *string   `json:"name,omitempty"`
	RedirectURIs  *[]string `json:"redirect_uris,omitempty"`
	AllowedGrants *[]string `json:"allowed_grants,omitempty"`
	AllowedScopes *[]string `json:"allowed_scopes,omitempty"`
	RotateSecret  bool      `json:"rotate_secret"`
}

func (r *UpdateClientRequest) Normalize() {
	if r == nil {
		return
	}
	r.Name = strutil.TrimSpacePtr(r.Name)
	r.RedirectURIs = strutil.DedupeAndTrimPtr(r.RedirectURIs)
	r.AllowedGrants = strutil.DedupeAndTrimLowerPtr(r.AllowedGrants)
	r.AllowedScopes = strutil.DedupeAndTrimPtr(r.AllowedScopes)
}

// ToCommand converts the HTTP request to a service command.
func (r *UpdateClientRequest) ToCommand() *service.UpdateClientCommand {
	cmd := &service.UpdateClientCommand{
		Name:         r.Name,
		RotateSecret: r.RotateSecret,
	}

	if r.RedirectURIs != nil {
		cmd.SetRedirectURIs(*r.RedirectURIs)
	}
	if r.AllowedGrants != nil {
		grants := make([]models.GrantType, len(*r.AllowedGrants))
		for i, g := range *r.AllowedGrants {
			grants[i] = models.GrantType(g)
		}
		cmd.SetAllowedGrants(grants)
	}
	if r.AllowedScopes != nil {
		cmd.SetAllowedScopes(*r.AllowedScopes)
	}

	return cmd
}
