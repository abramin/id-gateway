package models

import (
	"strings"
	"testing"

	"credo/pkg/platform/validation"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizationRequest_Validate_SizeLimits(t *testing.T) {
	validRequest := func() *AuthorizationRequest {
		return &AuthorizationRequest{
			Email:       "test@example.com",
			ClientID:    "test-client-id",
			Scopes:      []string{"openid", "profile"},
			RedirectURI: "https://example.com/callback",
			State:       "state123",
		}
	}

	t.Run("valid request passes validation", func(t *testing.T) {
		req := validRequest()
		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("too many scopes rejected", func(t *testing.T) {
		req := validRequest()
		req.Scopes = make([]string, validation.MaxScopes+1)
		for i := range req.Scopes {
			req.Scopes[i] = "scope"
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many scopes")
	})

	t.Run("max scopes allowed", func(t *testing.T) {
		req := validRequest()
		req.Scopes = make([]string, validation.MaxScopes)
		for i := range req.Scopes {
			req.Scopes[i] = "scope"
		}

		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("scope exceeds max length rejected", func(t *testing.T) {
		req := validRequest()
		req.Scopes = []string{strings.Repeat("a", validation.MaxScopeLength+1)}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scope exceeds max length")
	})

	t.Run("scope at max length allowed", func(t *testing.T) {
		req := validRequest()
		req.Scopes = []string{strings.Repeat("a", validation.MaxScopeLength)}

		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("email exceeds max length rejected", func(t *testing.T) {
		req := validRequest()
		req.Email = strings.Repeat("a", validation.MaxEmailLength+1) + "@example.com"

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email must be")
	})

	t.Run("client_id exceeds max length rejected", func(t *testing.T) {
		req := validRequest()
		req.ClientID = strings.Repeat("a", validation.MaxClientIDLength+1)

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_id must be")
	})

	t.Run("redirect_uri exceeds max length rejected", func(t *testing.T) {
		req := validRequest()
		req.RedirectURI = "https://example.com/" + strings.Repeat("a", validation.MaxRedirectURILength)

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redirect_uri must be")
	})

	t.Run("state exceeds max length rejected", func(t *testing.T) {
		req := validRequest()
		req.State = strings.Repeat("a", validation.MaxStateLength+1)

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "state must be")
	})
}

func TestAuthorizationRequest_Validate_RequiredFields(t *testing.T) {
	t.Run("missing email rejected", func(t *testing.T) {
		req := &AuthorizationRequest{
			ClientID:    "test-client",
			Scopes:      []string{"openid"},
			RedirectURI: "https://example.com/callback",
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email is required")
	})

	t.Run("missing client_id rejected", func(t *testing.T) {
		req := &AuthorizationRequest{
			Email:       "test@example.com",
			Scopes:      []string{"openid"},
			RedirectURI: "https://example.com/callback",
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_id is required")
	})

	t.Run("missing redirect_uri rejected", func(t *testing.T) {
		req := &AuthorizationRequest{
			Email:    "test@example.com",
			ClientID: "test-client",
			Scopes:   []string{"openid"},
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redirect_uri is required")
	})

	t.Run("nil request rejected", func(t *testing.T) {
		var req *AuthorizationRequest
		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "request is required")
	})
}

func TestAuthorizationRequest_Validate_SyntaxChecks(t *testing.T) {
	t.Run("invalid email format rejected", func(t *testing.T) {
		req := &AuthorizationRequest{
			Email:       "not-an-email",
			ClientID:    "test-client",
			Scopes:      []string{"openid"},
			RedirectURI: "https://example.com/callback",
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email must be valid")
	})

	t.Run("invalid redirect_uri format rejected", func(t *testing.T) {
		req := &AuthorizationRequest{
			Email:       "test@example.com",
			ClientID:    "test-client",
			Scopes:      []string{"openid"},
			RedirectURI: "not-a-url",
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redirect_uri must be a valid URL")
	})

	t.Run("empty scope in array rejected", func(t *testing.T) {
		req := &AuthorizationRequest{
			Email:       "test@example.com",
			ClientID:    "test-client",
			Scopes:      []string{"openid", ""},
			RedirectURI: "https://example.com/callback",
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scopes cannot contain empty strings")
	})
}

func TestAuthorizationRequest_Normalize(t *testing.T) {
	t.Run("trims whitespace and lowercases email", func(t *testing.T) {
		req := &AuthorizationRequest{
			Email:       "  TEST@Example.com  ",
			ClientID:    "  client-123  ",
			Scopes:      []string{"  openid  ", "profile"},
			RedirectURI: "  https://example.com/callback  ",
			State:       "  state123  ",
		}

		req.Normalize()

		assert.Equal(t, "test@example.com", req.Email)
		assert.Equal(t, "client-123", req.ClientID)
		assert.Equal(t, []string{"openid", "profile"}, req.Scopes)
		assert.Equal(t, "https://example.com/callback", req.RedirectURI)
		assert.Equal(t, "state123", req.State)
	})

	t.Run("sets default scope when empty", func(t *testing.T) {
		req := &AuthorizationRequest{
			Email:       "test@example.com",
			ClientID:    "client-123",
			Scopes:      nil,
			RedirectURI: "https://example.com/callback",
		}

		req.Normalize()

		assert.Equal(t, []string{string(ScopeOpenID)}, req.Scopes)
	})

	t.Run("deduplicates scopes", func(t *testing.T) {
		req := &AuthorizationRequest{
			Email:       "test@example.com",
			ClientID:    "client-123",
			Scopes:      []string{"openid", "profile", "openid", "profile"},
			RedirectURI: "https://example.com/callback",
		}

		req.Normalize()

		assert.Len(t, req.Scopes, 2)
	})

	t.Run("nil request does not panic", func(t *testing.T) {
		var req *AuthorizationRequest
		assert.NotPanics(t, func() { req.Normalize() })
	})
}

func TestTokenRequest_Validate(t *testing.T) {
	t.Run("valid authorization_code request", func(t *testing.T) {
		req := &TokenRequest{
			GrantType:   "authorization_code",
			ClientID:    "test-client",
			Code:        "auth-code-123",
			RedirectURI: "https://example.com/callback",
		}

		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid refresh_token request", func(t *testing.T) {
		req := &TokenRequest{
			GrantType:    "refresh_token",
			ClientID:     "test-client",
			RefreshToken: "refresh-token-123",
		}

		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing grant_type rejected", func(t *testing.T) {
		req := &TokenRequest{
			ClientID: "test-client",
			Code:     "auth-code-123",
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "grant_type is required")
	})

	t.Run("unsupported grant_type rejected", func(t *testing.T) {
		req := &TokenRequest{
			GrantType: "client_credentials",
			ClientID:  "test-client",
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported grant_type")
	})

	t.Run("authorization_code without code rejected", func(t *testing.T) {
		req := &TokenRequest{
			GrantType:   "authorization_code",
			ClientID:    "test-client",
			RedirectURI: "https://example.com/callback",
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code is required")
	})

	t.Run("refresh_token without token rejected", func(t *testing.T) {
		req := &TokenRequest{
			GrantType: "refresh_token",
			ClientID:  "test-client",
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refresh_token is required")
	})
}

func TestRevokeTokenRequest_Validate(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		req := &RevokeTokenRequest{
			Token:    "token-to-revoke",
			ClientID: "test-client",
		}

		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing token rejected", func(t *testing.T) {
		req := &RevokeTokenRequest{
			ClientID: "test-client",
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token is required")
	})

	t.Run("valid token_type_hint access_token", func(t *testing.T) {
		req := &RevokeTokenRequest{
			Token:         "token-to-revoke",
			TokenTypeHint: "access_token",
		}

		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid token_type_hint refresh_token", func(t *testing.T) {
		req := &RevokeTokenRequest{
			Token:         "token-to-revoke",
			TokenTypeHint: "refresh_token",
		}

		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid token_type_hint rejected", func(t *testing.T) {
		req := &RevokeTokenRequest{
			Token:         "token-to-revoke",
			TokenTypeHint: "invalid_hint",
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token_type_hint must be")
	})
}
