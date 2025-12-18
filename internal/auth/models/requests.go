package models

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"credo/internal/sentinel"
	"credo/pkg/email"
)

// AuthorizationRequest represents an OAuth authorization request from a client.
type AuthorizationRequest struct {
	Email       string   `json:"email"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scopes"`
	RedirectURI string   `json:"redirect_uri"`
	State       string   `json:"state"`
}

// Normalize applies business defaults (e.g., default scope to openid) and sanitizes inputs.
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
// 1. Size checks (cheapest, fail fast on oversized input)
// 2. Required fields (presence checks)
// 3. Syntax validation (format checks)
// 4. Semantic validation (business rules - done in service layer)
func (r *AuthorizationRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("request is required: %w", sentinel.ErrBadRequest)
	}

	// Phase 1: Size validation (fail fast on oversized input)
	if len(r.Email) > 255 {
		return fmt.Errorf("email must be 255 characters or less: %w", sentinel.ErrInvalidInput)
	}
	if len(r.ClientID) > 100 {
		return fmt.Errorf("client_id must be 100 characters or less: %w", sentinel.ErrInvalidInput)
	}
	if len(r.RedirectURI) > 2048 {
		return fmt.Errorf("redirect_uri must be 2048 characters or less: %w", sentinel.ErrInvalidInput)
	}
	if len(r.State) > 500 {
		return fmt.Errorf("state must be 500 characters or less: %w", sentinel.ErrInvalidInput)
	}

	// Phase 2: Required fields (presence checks)
	if r.Email == "" {
		return fmt.Errorf("email is required: %w", sentinel.ErrInvalidInput)
	}
	if r.ClientID == "" {
		return fmt.Errorf("client_id is required: %w", sentinel.ErrInvalidInput)
	}
	if len(r.ClientID) < 3 {
		return fmt.Errorf("client_id must be at least 3 characters: %w", sentinel.ErrInvalidInput)
	}
	if r.RedirectURI == "" {
		return fmt.Errorf("redirect_uri is required: %w", sentinel.ErrInvalidInput)
	}

	// Phase 3: Syntax validation (format checks)
	if !email.IsValidEmail(r.Email) {
		return fmt.Errorf("email must be valid: %w", sentinel.ErrInvalidInput)
	}
	parsed, err := url.Parse(r.RedirectURI)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("redirect_uri must be a valid URL: %w", sentinel.ErrInvalidInput)
	}
	if len(r.Scopes) > 0 {
		if slices.Contains(r.Scopes, "") {
			return fmt.Errorf("scopes cannot contain empty strings: %w", sentinel.ErrInvalidInput)
		}
	}

	// Phase 4: Semantic validation (business rules) - done in service layer
	return nil
}

// TokenRequest represents a request to exchange authorization code or refresh token for access tokens.
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
// 1. Size checks (implicit - no size limits on token request fields)
// 2. Required fields (presence checks)
// 3. Syntax validation (format/enum checks)
// 4. Semantic validation (grant-type specific requirements)
func (r *TokenRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("request is required: %w", sentinel.ErrBadRequest)
	}

	// Phase 2: Required fields (presence checks)
	if r.GrantType == "" {
		return fmt.Errorf("grant_type is required: %w", sentinel.ErrInvalidInput)
	}
	if r.ClientID == "" {
		return fmt.Errorf("client_id is required: %w", sentinel.ErrInvalidInput)
	}

	// Phase 3: Syntax validation (enum check)
	if r.GrantType != string(GrantAuthorizationCode) && r.GrantType != string(GrantRefreshToken) {
		return fmt.Errorf("unsupported grant_type: %w", sentinel.ErrBadRequest)
	}

	// Phase 4: Semantic validation (grant-type specific requirements)
	if r.GrantType == string(GrantAuthorizationCode) {
		if r.Code == "" {
			return fmt.Errorf("code is required for authorization_code grant: %w", sentinel.ErrInvalidInput)
		}
		if r.RedirectURI == "" {
			return fmt.Errorf("redirect_uri is required: %w", sentinel.ErrInvalidInput)
		}
	} else if r.GrantType == string(GrantRefreshToken) {
		if r.RefreshToken == "" {
			return fmt.Errorf("refresh_token is required for refresh_token grant: %w", sentinel.ErrInvalidInput)
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
// 1. Size checks (implicit - no size limits)
// 2. Required fields (presence checks)
// 3. Syntax validation (enum checks)
func (r *RevokeTokenRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("request is required: %w", sentinel.ErrBadRequest)
	}

	// Phase 2: Required fields (presence checks)
	if r.Token == "" {
		return fmt.Errorf("token is required: %w", sentinel.ErrInvalidInput)
	}
	// client_id is optional per RFC 7009 (only required for public clients)

	// Phase 3: Syntax validation (enum check for optional field)
	if r.TokenTypeHint != "" {
		allowed := map[string]struct{}{
			string(TokenTypeAccess):  {},
			string(TokenTypeRefresh): {},
		}
		if _, ok := allowed[r.TokenTypeHint]; !ok {
			return fmt.Errorf("token_type_hint must be access_token or refresh_token if provided: %w", sentinel.ErrInvalidInput)
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
