package models

import (
	"net/url"
	"slices"
	"strings"

	"credo/internal/auth/email"
	dErrors "credo/pkg/domain-errors"
)

type AuthorizationRequest struct {
	Email       string   `json:"email"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scopes"`
	RedirectURI string   `json:"redirect_uri"`
	State       string   `json:"state"`
}

func (r *AuthorizationRequest) Normalize() {
	if r == nil {
		return
	}
	r.Email = strings.TrimSpace(strings.ToLower(r.Email))
	r.ClientID = strings.TrimSpace(r.ClientID)
	r.RedirectURI = strings.TrimSpace(r.RedirectURI)
	r.State = strings.TrimSpace(r.State)

	// Default to "openid" scope if none provided
	if len(r.Scopes) == 0 {
		r.Scopes = []string{string(ScopeOpenID)}
	}
	r.Scopes = trimAndDedupScopes(r.Scopes)
}

func trimAndDedupScopes(scopes []string) []string {
	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(scopes))
	for _, s := range scopes {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; !ok {
			seen[trimmed] = struct{}{}
			normalized = append(normalized, trimmed)
		}
	}
	return normalized
}

// Validate validates the authorization request following strict validation order:
func (r *AuthorizationRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	// Phase 1: Size validation (fail fast on oversized input)
	if len(r.Email) > 255 {
		return dErrors.New(dErrors.CodeValidation, "email must be 255 characters or less")
	}
	if len(r.ClientID) > 100 {
		return dErrors.New(dErrors.CodeValidation, "client_id must be 100 characters or less")
	}
	if len(r.RedirectURI) > 2048 {
		return dErrors.New(dErrors.CodeValidation, "redirect_uri must be 2048 characters or less")
	}
	if len(r.State) > 500 {
		return dErrors.New(dErrors.CodeValidation, "state must be 500 characters or less")
	}

	// Phase 2: Required fields (presence checks)
	if r.Email == "" {
		return dErrors.New(dErrors.CodeValidation, "email is required")
	}
	if r.ClientID == "" {
		return dErrors.New(dErrors.CodeValidation, "client_id is required")
	}
	if len(r.ClientID) < 3 {
		return dErrors.New(dErrors.CodeValidation, "client_id must be at least 3 characters")
	}
	if r.RedirectURI == "" {
		return dErrors.New(dErrors.CodeValidation, "redirect_uri is required")
	}

	// Phase 3: Syntax validation (format checks)
	if !email.IsValidEmail(r.Email) {
		return dErrors.New(dErrors.CodeValidation, "email must be valid")
	}
	parsed, err := url.Parse(r.RedirectURI)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return dErrors.New(dErrors.CodeValidation, "redirect_uri must be a valid URL")
	}
	if len(r.Scopes) > 0 {
		if slices.Contains(r.Scopes, "") {
			return dErrors.New(dErrors.CodeValidation, "scopes cannot contain empty strings")
		}
	}

	// Phase 4: Semantic validation (business rules) - done in service layer
	return nil
}

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (r *TokenRequest) Normalize() {
	if r == nil {
		return
	}
	r.GrantType = strings.TrimSpace(r.GrantType)
	r.ClientID = strings.TrimSpace(r.ClientID)
	r.Code = strings.TrimSpace(r.Code)
	r.RedirectURI = strings.TrimSpace(r.RedirectURI)
	r.RefreshToken = strings.TrimSpace(r.RefreshToken)
}

// Validate validates the token request following strict validation order:
func (r *TokenRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	// Phase 2: Required fields (presence checks)
	if r.GrantType == "" {
		return dErrors.New(dErrors.CodeValidation, "grant_type is required")
	}
	if r.ClientID == "" {
		return dErrors.New(dErrors.CodeValidation, "client_id is required")
	}

	// Phase 3: Syntax validation (enum check)
	if r.GrantType != string(GrantAuthorizationCode) && r.GrantType != string(GrantRefreshToken) {
		return dErrors.New(dErrors.CodeBadRequest, "unsupported grant_type")
	}

	// Phase 4: Semantic validation (grant-type specific requirements)
	if r.GrantType == string(GrantAuthorizationCode) {
		if r.Code == "" {
			return dErrors.New(dErrors.CodeValidation, "code is required for authorization_code grant")
		}
		if r.RedirectURI == "" {
			return dErrors.New(dErrors.CodeValidation, "redirect_uri is required")
		}
	} else if r.GrantType == string(GrantRefreshToken) {
		if r.RefreshToken == "" {
			return dErrors.New(dErrors.CodeValidation, "refresh_token is required for refresh_token grant")
		}
	}
	return nil
}

type RevokeTokenRequest struct {
	Token         string `json:"token"`
	ClientID      string `json:"client_id"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`
}

// Validate validates the revoke token request following strict validation order:
func (r *RevokeTokenRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	// Phase 2: Required fields (presence checks)
	if r.Token == "" {
		return dErrors.New(dErrors.CodeValidation, "token is required")
	}
	// client_id is optional per RFC 7009 (only required for public clients)

	// Phase 3: Syntax validation (enum check for optional field)
	if r.TokenTypeHint != "" {
		allowed := map[string]struct{}{
			string(TokenTypeAccess):  {},
			string(TokenTypeRefresh): {},
		}
		if _, ok := allowed[r.TokenTypeHint]; !ok {
			return dErrors.New(dErrors.CodeValidation, "token_type_hint must be access_token or refresh_token if provided")
		}
	}
	return nil
}

func (r *RevokeTokenRequest) Normalize() {
	if r == nil {
		return
	}
	r.Token = strings.TrimSpace(r.Token)
	r.ClientID = strings.TrimSpace(r.ClientID)
	r.TokenTypeHint = strings.TrimSpace(r.TokenTypeHint)
}
