package models

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	dErrors "credo/pkg/domain-errors"
	strutil "credo/pkg/platform/strings"
)

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
	return validateRequiredName(r.Name)
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

func (r *CreateClientRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	// Note: We don't validate tenant_id != uuid.Nil here.
	// Instead, we let the service look up the tenant and return 404 if not found.
	// This gives consistent "tenant not found" behavior for both nil and non-existent UUIDs.
	if err := validateRequiredName(r.Name); err != nil {
		return err
	}
	if err := validateRequiredSlice(r.RedirectURIs, "redirect_uris", "redirect_uri", validateRedirectURI); err != nil {
		return err
	}
	if err := validateRequiredSlice(r.AllowedGrants, "allowed_grants", "allowed_grants", validateGrant); err != nil {
		return err
	}
	if r.Public {
		if slices.Contains(r.AllowedGrants, "client_credentials") {
			return dErrors.New(dErrors.CodeValidation, "client_credentials grant requires a confidential client")
		}
	}
	if err := validateRequiredSlice(r.AllowedScopes, "allowed_scopes", "allowed_scopes", validateScope); err != nil {
		return err
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
	if !isAllowedScheme(parsed.Scheme, parsed.Host) {
		return dErrors.New(dErrors.CodeValidation, "redirect_uri must be https or localhost for development")
	}
	return nil
}

// isAllowedScheme returns true if the URI scheme is acceptable:
// - https is always allowed
// - http is allowed only for localhost (development)
func isAllowedScheme(scheme, host string) bool {
	if scheme == "https" {
		return true
	}
	// Only allow exact localhost or localhost:port, not subdomains like localhost.attacker.com
	return scheme == "http" && isLocalhost(host)
}

// isLocalhost checks if the host is exactly "localhost" or "localhost:<port>".
// Prevents subdomain bypass attacks like "localhost.attacker.com".
func isLocalhost(host string) bool {
	return host == "localhost" || strings.HasPrefix(host, "localhost:")
}

// allowedGrants defines the valid OAuth grants clients can use.
var allowedGrants = map[string]struct{}{
	"authorization_code": {},
	"refresh_token":      {},
	"client_credentials": {},
}

func validateGrant(grant string) error {
	if _, ok := allowedGrants[grant]; !ok {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("unsupported grant: %s", grant))
	}
	return nil
}

// allowedScopes defines the valid OAuth scopes clients can request.
var allowedScopes = map[string]struct{}{
	"openid":  {},
	"profile": {},
	"email":   {},
	"offline": {}, // For refresh tokens
}

func validateScope(scope string) error {
	if _, ok := allowedScopes[scope]; !ok {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("unsupported scope: %s", scope))
	}
	return nil
}

func validateRequiredName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return dErrors.New(dErrors.CodeValidation, "name is required")
	}
	if len(trimmed) > maxNameLength {
		return dErrors.New(dErrors.CodeValidation, "name must be 128 characters or less")
	}
	return nil
}

// validateRequiredSlice validates a required slice field.
// Returns error if empty or any item fails validation.
func validateRequiredSlice(field []string, fieldName string, invalidName string, validateItem func(string) error) error {
	if len(field) == 0 {
		return dErrors.New(dErrors.CodeValidation, fieldName+" are required")
	}
	for _, item := range field {
		if err := validateItem(item); err != nil {
			return dErrors.Wrap(err, dErrors.CodeValidation, "invalid "+invalidName)
		}
	}
	return nil
}

// validateOptionalSlice validates an optional slice field.
// Returns nil if field is nil, error if empty or any item fails validation.
func validateOptionalSlice(field *[]string, fieldName string, validateItem func(string) error) error {
	if field == nil {
		return nil
	}
	if len(*field) == 0 {
		return dErrors.New(dErrors.CodeValidation, fieldName+" cannot be empty")
	}
	for _, item := range *field {
		if err := validateItem(item); err != nil {
			return dErrors.Wrap(err, dErrors.CodeValidation, "invalid "+fieldName)
		}
	}
	return nil
}

// validateOptionalName validates an optional name field.
// Returns nil if name is nil, error if empty or too long.
func validateOptionalName(name *string) error {
	if name == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*name)
	if trimmed == "" {
		return dErrors.New(dErrors.CodeValidation, "name cannot be empty")
	}
	if len(trimmed) > maxNameLength {
		return dErrors.New(dErrors.CodeValidation, "name must be 128 characters or less")
	}
	return nil
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
	if r.Name != nil {
		trimmed := strings.TrimSpace(*r.Name)
		r.Name = &trimmed
	}
	if r.RedirectURIs != nil {
		normalized := strutil.DedupeAndTrim(*r.RedirectURIs)
		r.RedirectURIs = &normalized
	}
	if r.AllowedGrants != nil {
		normalized := strutil.DedupeAndTrimLower(*r.AllowedGrants)
		r.AllowedGrants = &normalized
	}
	if r.AllowedScopes != nil {
		normalized := strutil.DedupeAndTrim(*r.AllowedScopes)
		r.AllowedScopes = &normalized
	}
}

// IsEmpty returns true if the request contains no updates.
func (r *UpdateClientRequest) IsEmpty() bool {
	if r == nil {
		return true
	}
	return r.Name == nil &&
		r.RedirectURIs == nil &&
		r.AllowedGrants == nil &&
		r.AllowedScopes == nil &&
		!r.RotateSecret
}

func (r *UpdateClientRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	if err := validateOptionalName(r.Name); err != nil {
		return err
	}
	if err := validateOptionalSlice(r.RedirectURIs, "redirect_uris", validateRedirectURI); err != nil {
		return err
	}
	if err := validateOptionalSlice(r.AllowedGrants, "allowed_grants", validateGrant); err != nil {
		return err
	}
	if err := validateOptionalSlice(r.AllowedScopes, "allowed_scopes", validateScope); err != nil {
		return err
	}
	return nil
}
