package handler

import (
	"strings"
	"testing"

	"credo/pkg/platform/validation"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateClientRequest_Validate_SizeLimits(t *testing.T) {
	validRequest := func() *CreateClientRequest {
		return &CreateClientRequest{
			TenantID:      "550e8400-e29b-41d4-a716-446655440000",
			Name:          "Test Client",
			RedirectURIs:  []string{"https://example.com/callback"},
			AllowedGrants: []string{"authorization_code"},
			AllowedScopes: []string{"openid", "profile"},
		}
	}

	t.Run("valid request passes validation", func(t *testing.T) {
		req := validRequest()
		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("too many redirect URIs rejected", func(t *testing.T) {
		req := validRequest()
		req.RedirectURIs = make([]string, validation.MaxRedirectURIs+1)
		for i := range req.RedirectURIs {
			req.RedirectURIs[i] = "https://example.com/callback"
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many redirect URIs")
	})

	t.Run("max redirect URIs allowed", func(t *testing.T) {
		req := validRequest()
		req.RedirectURIs = make([]string, validation.MaxRedirectURIs)
		for i := range req.RedirectURIs {
			req.RedirectURIs[i] = "https://example.com/callback"
		}

		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("too many grant types rejected", func(t *testing.T) {
		req := validRequest()
		req.AllowedGrants = make([]string, validation.MaxGrants+1)
		for i := range req.AllowedGrants {
			req.AllowedGrants[i] = "authorization_code"
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many grant types")
	})

	t.Run("max grant types allowed", func(t *testing.T) {
		req := validRequest()
		req.AllowedGrants = make([]string, validation.MaxGrants)
		for i := range req.AllowedGrants {
			req.AllowedGrants[i] = "authorization_code"
		}

		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("too many scopes rejected", func(t *testing.T) {
		req := validRequest()
		req.AllowedScopes = make([]string, validation.MaxScopes+1)
		for i := range req.AllowedScopes {
			req.AllowedScopes[i] = "scope"
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many scopes")
	})

	t.Run("max scopes allowed", func(t *testing.T) {
		req := validRequest()
		req.AllowedScopes = make([]string, validation.MaxScopes)
		for i := range req.AllowedScopes {
			req.AllowedScopes[i] = "scope"
		}

		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("redirect URI exceeds max length rejected", func(t *testing.T) {
		req := validRequest()
		req.RedirectURIs = []string{"https://example.com/" + strings.Repeat("a", validation.MaxRedirectURILength)}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redirect URI exceeds max length")
	})

	t.Run("redirect URI at max length allowed", func(t *testing.T) {
		req := validRequest()
		// Create a URL that's exactly at the max length
		baseURL := "https://example.com/"
		padding := strings.Repeat("a", validation.MaxRedirectURILength-len(baseURL))
		req.RedirectURIs = []string{baseURL + padding}

		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("scope exceeds max length rejected", func(t *testing.T) {
		req := validRequest()
		req.AllowedScopes = []string{strings.Repeat("a", validation.MaxScopeLength+1)}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scope exceeds max length")
	})

	t.Run("scope at max length allowed", func(t *testing.T) {
		req := validRequest()
		req.AllowedScopes = []string{strings.Repeat("a", validation.MaxScopeLength)}

		err := req.Validate()
		assert.NoError(t, err)
	})
}

func TestCreateClientRequest_Validate_RequiredFields(t *testing.T) {
	t.Run("missing name rejected", func(t *testing.T) {
		req := &CreateClientRequest{
			TenantID:      "550e8400-e29b-41d4-a716-446655440000",
			RedirectURIs:  []string{"https://example.com/callback"},
			AllowedGrants: []string{"authorization_code"},
			AllowedScopes: []string{"openid"},
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("missing redirect_uris rejected", func(t *testing.T) {
		req := &CreateClientRequest{
			TenantID:      "550e8400-e29b-41d4-a716-446655440000",
			Name:          "Test Client",
			AllowedGrants: []string{"authorization_code"},
			AllowedScopes: []string{"openid"},
		}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one redirect_uri is required")
	})

	t.Run("nil request rejected", func(t *testing.T) {
		var req *CreateClientRequest
		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "request is required")
	})
}

func TestCreateClientRequest_Normalize(t *testing.T) {
	t.Run("trims whitespace and deduplicates", func(t *testing.T) {
		req := &CreateClientRequest{
			Name:          "  Test Client  ",
			RedirectURIs:  []string{"  https://example.com/callback  ", "https://example.com/callback"},
			AllowedGrants: []string{"  AUTHORIZATION_CODE  ", "authorization_code"},
			AllowedScopes: []string{"  openid  ", "openid"},
		}

		req.Normalize()

		assert.Equal(t, "Test Client", req.Name)
		assert.Len(t, req.RedirectURIs, 1)
		assert.Equal(t, "https://example.com/callback", req.RedirectURIs[0])
		assert.Len(t, req.AllowedGrants, 1)
		assert.Equal(t, "authorization_code", req.AllowedGrants[0])
		assert.Len(t, req.AllowedScopes, 1)
		assert.Equal(t, "openid", req.AllowedScopes[0])
	})

	t.Run("nil request does not panic", func(t *testing.T) {
		var req *CreateClientRequest
		assert.NotPanics(t, func() { req.Normalize() })
	})
}

func TestUpdateClientRequest_Validate_SizeLimits(t *testing.T) {
	t.Run("empty request is valid", func(t *testing.T) {
		req := &UpdateClientRequest{}
		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("too many redirect URIs rejected", func(t *testing.T) {
		uris := make([]string, validation.MaxRedirectURIs+1)
		for i := range uris {
			uris[i] = "https://example.com/callback"
		}
		req := &UpdateClientRequest{RedirectURIs: &uris}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many redirect URIs")
	})

	t.Run("max redirect URIs allowed", func(t *testing.T) {
		uris := make([]string, validation.MaxRedirectURIs)
		for i := range uris {
			uris[i] = "https://example.com/callback"
		}
		req := &UpdateClientRequest{RedirectURIs: &uris}

		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("too many grant types rejected", func(t *testing.T) {
		grants := make([]string, validation.MaxGrants+1)
		for i := range grants {
			grants[i] = "authorization_code"
		}
		req := &UpdateClientRequest{AllowedGrants: &grants}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many grant types")
	})

	t.Run("too many scopes rejected", func(t *testing.T) {
		scopes := make([]string, validation.MaxScopes+1)
		for i := range scopes {
			scopes[i] = "scope"
		}
		req := &UpdateClientRequest{AllowedScopes: &scopes}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many scopes")
	})

	t.Run("redirect URI exceeds max length rejected", func(t *testing.T) {
		uris := []string{"https://example.com/" + strings.Repeat("a", validation.MaxRedirectURILength)}
		req := &UpdateClientRequest{RedirectURIs: &uris}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redirect URI exceeds max length")
	})

	t.Run("scope exceeds max length rejected", func(t *testing.T) {
		scopes := []string{strings.Repeat("a", validation.MaxScopeLength+1)}
		req := &UpdateClientRequest{AllowedScopes: &scopes}

		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scope exceeds max length")
	})

	t.Run("nil request rejected", func(t *testing.T) {
		var req *UpdateClientRequest
		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "request is required")
	})
}

func TestUpdateClientRequest_Normalize(t *testing.T) {
	t.Run("trims and deduplicates pointer fields", func(t *testing.T) {
		name := "  Test Client  "
		uris := []string{"  https://example.com/callback  ", "https://example.com/callback"}
		grants := []string{"  AUTHORIZATION_CODE  ", "authorization_code"}
		scopes := []string{"  openid  ", "openid"}

		req := &UpdateClientRequest{
			Name:          &name,
			RedirectURIs:  &uris,
			AllowedGrants: &grants,
			AllowedScopes: &scopes,
		}

		req.Normalize()

		assert.Equal(t, "Test Client", *req.Name)
		assert.Len(t, *req.RedirectURIs, 1)
		assert.Equal(t, "https://example.com/callback", (*req.RedirectURIs)[0])
		assert.Len(t, *req.AllowedGrants, 1)
		assert.Equal(t, "authorization_code", (*req.AllowedGrants)[0])
		assert.Len(t, *req.AllowedScopes, 1)
		assert.Equal(t, "openid", (*req.AllowedScopes)[0])
	})

	t.Run("nil request does not panic", func(t *testing.T) {
		var req *UpdateClientRequest
		assert.NotPanics(t, func() { req.Normalize() })
	})

	t.Run("nil fields do not cause panic", func(t *testing.T) {
		req := &UpdateClientRequest{}
		assert.NotPanics(t, func() { req.Normalize() })
	})
}

func TestCreateTenantRequest_Validate(t *testing.T) {
	t.Run("valid request passes", func(t *testing.T) {
		req := &CreateTenantRequest{Name: "Test Tenant"}
		err := req.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing name rejected", func(t *testing.T) {
		req := &CreateTenantRequest{}
		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("nil request rejected", func(t *testing.T) {
		var req *CreateTenantRequest
		err := req.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "request is required")
	})
}

func TestCreateTenantRequest_Normalize(t *testing.T) {
	t.Run("trims whitespace", func(t *testing.T) {
		req := &CreateTenantRequest{Name: "  Test Tenant  "}
		req.Normalize()
		assert.Equal(t, "Test Tenant", req.Name)
	})

	t.Run("nil request does not panic", func(t *testing.T) {
		var req *CreateTenantRequest
		assert.NotPanics(t, func() { req.Normalize() })
	})
}
