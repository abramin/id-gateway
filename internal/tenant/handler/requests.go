package handler

import (
	"strings"

	"credo/internal/tenant/models"
	"credo/internal/tenant/service"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	strutil "credo/pkg/platform/strings"
	"credo/pkg/platform/validation"
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

// Validate validates the create client request following strict validation order.
func (r *CreateClientRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	// Phase 1: Size validation (fail fast on oversized input)
	if err := validation.CheckSliceCount("redirect URIs", len(r.RedirectURIs), validation.MaxRedirectURIs); err != nil {
		return err
	}
	if err := validation.CheckSliceCount("grant types", len(r.AllowedGrants), validation.MaxGrants); err != nil {
		return err
	}
	if err := validation.CheckSliceCount("scopes", len(r.AllowedScopes), validation.MaxScopes); err != nil {
		return err
	}
	if err := validation.CheckEachStringLength("redirect URI", r.RedirectURIs, validation.MaxRedirectURILength); err != nil {
		return err
	}
	if err := validation.CheckEachStringLength("scope", r.AllowedScopes, validation.MaxScopeLength); err != nil {
		return err
	}

	// Phase 2: Required fields
	if r.Name == "" {
		return dErrors.New(dErrors.CodeValidation, "name is required")
	}
	if len(r.RedirectURIs) == 0 {
		return dErrors.New(dErrors.CodeValidation, "at least one redirect_uri is required")
	}

	return nil
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

// Validate validates the update client request following strict validation order.
func (r *UpdateClientRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	// Phase 1: Size validation (fail fast on oversized input)
	if r.RedirectURIs != nil {
		if err := validation.CheckSliceCount("redirect URIs", len(*r.RedirectURIs), validation.MaxRedirectURIs); err != nil {
			return err
		}
		if err := validation.CheckEachStringLength("redirect URI", *r.RedirectURIs, validation.MaxRedirectURILength); err != nil {
			return err
		}
	}
	if r.AllowedGrants != nil {
		if err := validation.CheckSliceCount("grant types", len(*r.AllowedGrants), validation.MaxGrants); err != nil {
			return err
		}
	}
	if r.AllowedScopes != nil {
		if err := validation.CheckSliceCount("scopes", len(*r.AllowedScopes), validation.MaxScopes); err != nil {
			return err
		}
		if err := validation.CheckEachStringLength("scope", *r.AllowedScopes, validation.MaxScopeLength); err != nil {
			return err
		}
	}

	return nil
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
