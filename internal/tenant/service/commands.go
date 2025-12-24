package service

import (
	"net/url"
	"slices"
	"strings"

	"credo/internal/tenant/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

const maxNameLength = 128

// CreateClientCommand contains validated input for client creation.
// Domain validation (OAuth rules) happens here, not in HTTP layer.
type CreateClientCommand struct {
	TenantID      id.TenantID
	Name          string
	RedirectURIs  []string
	AllowedGrants []models.GrantType
	AllowedScopes []string
	Public        bool
}

func (c *CreateClientCommand) Validate() error {
	if c.Name == "" {
		return dErrors.New(dErrors.CodeValidation, "name is required")
	}
	if len(c.Name) > maxNameLength {
		return dErrors.New(dErrors.CodeValidation, "name must be 128 characters or less")
	}
	if len(c.RedirectURIs) == 0 {
		return dErrors.New(dErrors.CodeValidation, "redirect_uris are required")
	}
	if err := validateEachURI(c.RedirectURIs); err != nil {
		return err
	}
	if len(c.AllowedGrants) == 0 {
		return dErrors.New(dErrors.CodeValidation, "allowed_grants are required")
	}
	if err := validateEachGrant(c.AllowedGrants); err != nil {
		return err
	}
	if c.Public && slices.Contains(c.AllowedGrants, models.GrantTypeClientCredentials) {
		return dErrors.New(dErrors.CodeValidation, "client_credentials grant requires a confidential client")
	}
	if len(c.AllowedScopes) == 0 {
		return dErrors.New(dErrors.CodeValidation, "allowed_scopes are required")
	}
	return validateEachScope(c.AllowedScopes)
}

// UpdateClientCommand contains validated input for client updates.
// All fields are optional; nil means "don't change".
type UpdateClientCommand struct {
	Name          *string
	RedirectURIs  []string // nil = don't change, empty slice after validation = invalid
	AllowedGrants []models.GrantType
	AllowedScopes []string
	RotateSecret  bool

	// Internal flags to distinguish "not provided" from "provided empty"
	hasRedirectURIs  bool
	hasAllowedGrants bool
	hasAllowedScopes bool
}

func (c *UpdateClientCommand) SetRedirectURIs(uris []string) {
	c.RedirectURIs = uris
	c.hasRedirectURIs = true
}

func (c *UpdateClientCommand) SetAllowedGrants(grants []models.GrantType) {
	c.AllowedGrants = grants
	c.hasAllowedGrants = true
}

func (c *UpdateClientCommand) SetAllowedScopes(scopes []string) {
	c.AllowedScopes = scopes
	c.hasAllowedScopes = true
}

func (c *UpdateClientCommand) HasRedirectURIs() bool  { return c.hasRedirectURIs }
func (c *UpdateClientCommand) HasAllowedGrants() bool { return c.hasAllowedGrants }
func (c *UpdateClientCommand) HasAllowedScopes() bool { return c.hasAllowedScopes }

func (c *UpdateClientCommand) Validate() error {
	if err := validateOptionalName(c.Name); err != nil {
		return err
	}
	if c.hasRedirectURIs {
		if len(c.RedirectURIs) == 0 {
			return dErrors.New(dErrors.CodeValidation, "redirect_uris cannot be empty")
		}
		if err := validateEachURI(c.RedirectURIs); err != nil {
			return err
		}
	}
	if c.hasAllowedGrants {
		if len(c.AllowedGrants) == 0 {
			return dErrors.New(dErrors.CodeValidation, "allowed_grants cannot be empty")
		}
		if err := validateEachGrant(c.AllowedGrants); err != nil {
			return err
		}
	}
	if c.hasAllowedScopes {
		if len(c.AllowedScopes) == 0 {
			return dErrors.New(dErrors.CodeValidation, "allowed_scopes cannot be empty")
		}
		if err := validateEachScope(c.AllowedScopes); err != nil {
			return err
		}
	}
	return nil
}

// IsEmpty returns true if the command contains no updates.
func (c *UpdateClientCommand) IsEmpty() bool {
	return c.Name == nil &&
		!c.hasRedirectURIs &&
		!c.hasAllowedGrants &&
		!c.hasAllowedScopes &&
		!c.RotateSecret
}

// Domain validation functions for OAuth rules.

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
	return scheme == "http" && isLocalhost(host)
}

// isLocalhost checks if the host is exactly "localhost" or "localhost:<port>".
// Prevents subdomain bypass attacks like "localhost.attacker.com".
func isLocalhost(host string) bool {
	return host == "localhost" || strings.HasPrefix(host, "localhost:")
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
		return dErrors.New(dErrors.CodeValidation, "unsupported scope")
	}
	return nil
}

// Batch validation helpers to reduce nesting in Validate methods.

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

func validateEachURI(uris []string) error {
	for _, uri := range uris {
		if err := validateRedirectURI(uri); err != nil {
			return err
		}
	}
	return nil
}

func validateEachGrant(grants []models.GrantType) error {
	for _, grant := range grants {
		if !grant.IsValid() {
			return dErrors.New(dErrors.CodeValidation, "unsupported grant type")
		}
	}
	return nil
}

func validateEachScope(scopes []string) error {
	for _, scope := range scopes {
		if err := validateScope(scope); err != nil {
			return err
		}
	}
	return nil
}
