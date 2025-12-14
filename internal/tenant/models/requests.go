package models

import (
	"fmt"
	"net/url"
	"strings"

	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
)

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
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return dErrors.New(dErrors.CodeValidation, "name is required")
	}
	if len(r.Name) > 128 {
		return dErrors.New(dErrors.CodeValidation, "name must be 128 characters or less")
	}
	return nil
}

type CreateClientRequest struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	Name          string    `json:"name"`
	RedirectURIs  []string  `json:"redirect_uris"`
	AllowedGrants []string  `json:"allowed_grants"`
	AllowedScopes []string  `json:"allowed_scopes"`
	Public        bool      `json:"public_client"`
}

// Normalize trims input and deduplicates collections for stable validation/storage.
func (r *CreateClientRequest) Normalize() {
	if r == nil {
		return
	}
	r.Name = strings.TrimSpace(r.Name)
	r.RedirectURIs = normalizeStrings(r.RedirectURIs)
	r.AllowedGrants = normalizeStrings(lowerStrings(r.AllowedGrants))
	r.AllowedScopes = normalizeStrings(r.AllowedScopes)
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
			return dErrors.Wrap(err, dErrors.CodeValidation, "invalid redirect_uri")
		}
	}
	if len(r.AllowedGrants) == 0 {
		return dErrors.New(dErrors.CodeValidation, "allowed_grants are required")
	}
	if err := validateGrants(r.AllowedGrants); err != nil {
		return dErrors.Wrap(err, dErrors.CodeValidation, "invalid allowed_grants")
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
	if parsed.Scheme != "https" && (parsed.Scheme != "http" || !strings.HasPrefix(parsed.Host, "localhost")) {
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
		normalized := normalizeStrings(*r.RedirectURIs)
		r.RedirectURIs = &normalized
	}
	if r.AllowedGrants != nil {
		normalized := normalizeStrings(lowerStrings(*r.AllowedGrants))
		r.AllowedGrants = &normalized
	}
	if r.AllowedScopes != nil {
		normalized := normalizeStrings(*r.AllowedScopes)
		r.AllowedScopes = &normalized
	}
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
				return dErrors.Wrap(err, dErrors.CodeValidation, "invalid redirect_uri")
			}
		}
	}
	if r.AllowedGrants != nil {
		if len(*r.AllowedGrants) == 0 {
			return dErrors.New(dErrors.CodeValidation, "allowed_grants cannot be empty")
		}
		if err := validateGrants(*r.AllowedGrants); err != nil {
			return dErrors.Wrap(err, dErrors.CodeValidation, "invalid allowed_grants")
		}
	}
	if r.AllowedScopes != nil && len(*r.AllowedScopes) == 0 {
		return dErrors.New(dErrors.CodeValidation, "allowed_scopes cannot be empty")
	}
	return nil
}

func normalizeStrings(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func lowerStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, strings.ToLower(v))
	}
	return out
}
