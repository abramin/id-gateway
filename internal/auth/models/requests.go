package models

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"credo/internal/auth/email"
	dErrors "credo/pkg/domain-errors"
	strutil "credo/pkg/platform/strings"
	"credo/pkg/platform/validation"
)

// This file contains transport-layer request models and validation logic.
// These types may include HTTP/JSON-specific fields or normalization rules.

// AuthorizationRequest represents the /auth/authorize payload.
type AuthorizationRequest struct {
	Email       string   `json:"email"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scopes"`
	RedirectURI string   `json:"redirect_uri"`
	State       string   `json:"state"`
}

// Normalize trims and deduplicates fields in the authorization request.
// It also sets a default scope when none is provided.
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
	r.Scopes = strutil.DedupeAndTrim(r.Scopes)
}

// Validate validates the authorization request following strict validation order:
// size -> required fields -> syntax -> semantics.
func (r *AuthorizationRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	// Phase 1: Size validation (fail fast on oversized input)
	if len(r.Email) > validation.MaxEmailLength {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("email must be %d characters or less", validation.MaxEmailLength))
	}
	if len(r.ClientID) > validation.MaxClientIDLength {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("client_id must be %d characters or less", validation.MaxClientIDLength))
	}
	if len(r.RedirectURI) > validation.MaxRedirectURILength {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("redirect_uri must be %d characters or less", validation.MaxRedirectURILength))
	}
	if len(r.State) > validation.MaxStateLength {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("state must be %d characters or less", validation.MaxStateLength))
	}
	if len(r.Scopes) > validation.MaxScopes {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("too many scopes: max %d allowed", validation.MaxScopes))
	}
	for _, scope := range r.Scopes {
		if len(scope) > validation.MaxScopeLength {
			return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("scope exceeds max length of %d", validation.MaxScopeLength))
		}
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

// TokenRequest represents the /auth/token payload for supported grant types.
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Normalize trims whitespace from token request fields.
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
// size -> required fields -> syntax -> semantics.
func (r *TokenRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	// Phase 1: Size validation (fail fast on oversized input)
	if len(r.ClientID) > validation.MaxClientIDLength {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("client_id must be %d characters or less", validation.MaxClientIDLength))
	}
	if len(r.Code) > validation.MaxCodeLength {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("code must be %d characters or less", validation.MaxCodeLength))
	}
	if len(r.RedirectURI) > validation.MaxRedirectURILength {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("redirect_uri must be %d characters or less", validation.MaxRedirectURILength))
	}
	if len(r.RefreshToken) > validation.MaxRefreshTokenLength {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("refresh_token must be %d characters or less", validation.MaxRefreshTokenLength))
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

// RevokeTokenRequest represents an RFC 7009 token revocation request.
type RevokeTokenRequest struct {
	Token         string `json:"token"`
	ClientID      string `json:"client_id"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`
}

// Validate validates the revoke token request with required fields and hints.
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

// Normalize trims whitespace from revoke token request fields.
func (r *RevokeTokenRequest) Normalize() {
	if r == nil {
		return
	}
	r.Token = strings.TrimSpace(r.Token)
	r.ClientID = strings.TrimSpace(r.ClientID)
	r.TokenTypeHint = strings.TrimSpace(r.TokenTypeHint)
}
