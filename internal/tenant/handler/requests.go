package handler

import (
	"net/url"
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

const maxNameLength = 128

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
	if err := validation.CheckStringLength("name", r.Name, maxNameLength); err != nil {
		return err
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

	tenantID id.TenantID
}

// Normalize trims input and deduplicates collections for stable validation/storage.
func (r *CreateClientRequest) Normalize() {
	if r == nil {
		return
	}
	r.TenantID = strings.TrimSpace(r.TenantID)
	r.Name = strings.TrimSpace(r.Name)
	r.RedirectURIs = strutil.DedupeAndTrim(r.RedirectURIs)
	r.AllowedGrants = strutil.DedupeAndTrimLower(r.AllowedGrants)
	r.AllowedScopes = strutil.DedupeAndTrim(r.AllowedScopes)
}

// Validate validates the create client request following strict validation order.
// Follows 4-phase validation: size → required → syntax → semantic (semantic done in service).
func (r *CreateClientRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	if err := r.validateSizeLimits(); err != nil {
		return err
	}
	if err := r.validateRequired(); err != nil {
		return err
	}
	return r.validateSyntax()
}

func (r *CreateClientRequest) validateSizeLimits() error {
	checks := []error{
		validation.CheckStringLength("tenant_id", r.TenantID, validation.MaxTenantIDLength),
		validation.CheckStringLength("name", r.Name, maxNameLength),
		validation.CheckSliceCount("redirect URIs", len(r.RedirectURIs), validation.MaxRedirectURIs),
		validation.CheckSliceCount("grant types", len(r.AllowedGrants), validation.MaxGrants),
		validation.CheckSliceCount("scopes", len(r.AllowedScopes), validation.MaxScopes),
		validation.CheckEachStringLength("redirect URI", r.RedirectURIs, validation.MaxRedirectURILength),
		validation.CheckEachStringLength("scope", r.AllowedScopes, validation.MaxScopeLength),
	}
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *CreateClientRequest) validateRequired() error {
	if r.TenantID == "" {
		return dErrors.New(dErrors.CodeValidation, "tenant_id is required")
	}
	if r.Name == "" {
		return dErrors.New(dErrors.CodeValidation, "name is required")
	}
	if len(r.RedirectURIs) == 0 {
		return dErrors.New(dErrors.CodeValidation, "at least one redirect_uri is required")
	}
	return nil
}

func (r *CreateClientRequest) validateSyntax() error {
	tenantID, err := id.ParseTenantID(r.TenantID)
	if err != nil {
		return dErrors.New(dErrors.CodeValidation, "invalid tenant_id")
	}
	r.tenantID = tenantID

	for _, uri := range r.RedirectURIs {
		if _, err := url.Parse(uri); err != nil {
			return dErrors.New(dErrors.CodeValidation, "invalid redirect_uri format")
		}
	}
	return nil
}

// ToCommand converts the HTTP request to a service command.
// Returns an error if the tenant ID is invalid.
func (r *CreateClientRequest) ToCommand() (*service.CreateClientCommand, error) {
	tenantID := r.tenantID
	if tenantID.IsNil() {
		parsed, err := id.ParseTenantID(r.TenantID)
		if err != nil {
			return nil, err
		}
		tenantID = parsed
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
// Follows 4-phase validation: size → required → syntax → semantic (semantic done in service).
func (r *UpdateClientRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	if err := r.validateSizeLimits(); err != nil {
		return err
	}
	// Phase 2: Required fields - none for update (all fields optional)
	return r.validateSyntax()
}

func (r *UpdateClientRequest) validateSizeLimits() error {
	if r.Name != nil {
		if err := validation.CheckStringLength("name", *r.Name, maxNameLength); err != nil {
			return err
		}
	}
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

func (r *UpdateClientRequest) validateSyntax() error {
	if r.RedirectURIs == nil {
		return nil
	}
	for _, uri := range *r.RedirectURIs {
		if _, err := url.Parse(uri); err != nil {
			return dErrors.New(dErrors.CodeValidation, "invalid redirect_uri format")
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
