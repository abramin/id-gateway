package jwttoken

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var userID = uuid.New()
var sessionID = uuid.New()
var clientID = "test-client"
var tenantID = "test-tenant"
var expiresIn = time.Second * 1

var jwtService = NewJWTService(
	"test-signing-key",
	"test-issuer",
	"test-audience",
	expiresIn,
)

func Test_GenerateAccessToken(t *testing.T) {
	token, err := jwtService.GenerateAccessToken(userID, sessionID, clientID, tenantID, []string{"read", "write"})
	require.NoError(t, err)
	require.NotEmpty(t, token)
	claims, err := jwtService.ValidateToken(token)
	require.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, userID.String(), claims.UserID)
	assert.Equal(t, sessionID.String(), claims.SessionID)
	assert.Equal(t, clientID, claims.ClientID)
	assert.WithinDuration(t, time.Now().Add(expiresIn), claims.ExpiresAt.Time, time.Minute)
}

func Test_ValidateToken_InvalidToken(t *testing.T) {
	_, err := jwtService.ValidateToken("invalid-token-string")
	require.ErrorContains(t, err, "invalid token")
}

func Test_ValidateToken_ExpiredToken(t *testing.T) {
	token, err := jwtService.GenerateAccessToken(userID, sessionID, clientID, tenantID, []string{"read", "write"})
	time.Sleep(expiresIn + time.Second)
	require.NoError(t, err)

	_, err = jwtService.ValidateToken(token)
	require.ErrorContains(t, err, "token has expired")
}

func Test_ValidateToken_ValidTokent(t *testing.T) {
	token, err := jwtService.GenerateAccessToken(userID, sessionID, clientID, tenantID, []string{"read", "write"})
	require.NoError(t, err)

	claims, err := jwtService.ValidateToken(token)
	require.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, userID.String(), claims.UserID)
	assert.Equal(t, sessionID.String(), claims.SessionID)
	assert.Equal(t, clientID, claims.ClientID)
}

func Test_GenerateIDToken(t *testing.T) {
	token, err := jwtService.GenerateIDToken(userID, sessionID, clientID, tenantID)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	claims, err := jwtService.ValidateIDToken(token)
	require.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, userID.String(), claims.Subject)
	assert.Equal(t, sessionID.String(), claims.SessionID)
	assert.Equal(t, clientID, claims.ClientID)
	assert.WithinDuration(t, time.Now().Add(expiresIn), claims.ExpiresAt.Time, time.Minute)
}
func Test_ParseTokenSkipClaimsValidation(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		token, err := jwtService.GenerateAccessToken(userID, sessionID, clientID, tenantID, []string{"read", "write"})
		require.NoError(t, err)

		claims, err := jwtService.ParseTokenSkipClaimsValidation(token)
		require.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, userID.String(), claims.UserID)
		assert.Equal(t, sessionID.String(), claims.SessionID)
		assert.Equal(t, clientID, claims.ClientID)
	})

	t.Run("expired token still parses", func(t *testing.T) {
		token, err := jwtService.GenerateAccessToken(userID, sessionID, clientID, tenantID, []string{"read", "write"})
		require.NoError(t, err)
		time.Sleep(expiresIn + time.Second)

		claims, err := jwtService.ParseTokenSkipClaimsValidation(token)
		require.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, userID.String(), claims.UserID)
	})

	t.Run("error cases", func(t *testing.T) {
		tests := []struct {
			name        string
			tokenFunc   func() string
			expectedErr string
		}{
			{
				name: "empty token string",
				tokenFunc: func() string {
					return ""
				},
				expectedErr: "empty token",
			},
			{
				name: "invalid token string",
				tokenFunc: func() string {
					return "invalid-token"
				},
				expectedErr: "jwt parse failed",
			},
			{
				name: "invalid signature",
				tokenFunc: func() string {
					token, err := jwtService.GenerateAccessToken(userID, sessionID, clientID, tenantID, []string{"read"})
					require.NoError(t, err)
					return token
				},
				expectedErr: "invalid jwt signature",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				token := tt.tokenFunc()
				var service *JWTService

				if tt.name == "invalid signature" {
					service = NewJWTService("wrong-key", "test-issuer", "test-audience", expiresIn)
				} else {
					service = jwtService
				}

				_, err := service.ParseTokenSkipClaimsValidation(token)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			})
		}
	})
}

func Test_BuildIssuer(t *testing.T) {
	service := NewJWTService("key", "https://auth.example.com", "audience", time.Hour)

	t.Run("builds per-tenant issuer", func(t *testing.T) {
		tenantID := "550e8400-e29b-41d4-a716-446655440000"
		issuer := service.BuildIssuer(tenantID)
		assert.Equal(t, "https://auth.example.com/tenants/550e8400-e29b-41d4-a716-446655440000", issuer)
	})

	t.Run("returns base URL for empty tenant", func(t *testing.T) {
		issuer := service.BuildIssuer("")
		assert.Equal(t, "https://auth.example.com", issuer)
	})
}

func Test_ExtractTenantFromIssuer(t *testing.T) {
	service := NewJWTService("key", "https://auth.example.com", "audience", time.Hour)

	t.Run("extracts tenant from valid issuer", func(t *testing.T) {
		tenantID, err := service.ExtractTenantFromIssuer("https://auth.example.com/tenants/550e8400-e29b-41d4-a716-446655440000")
		require.NoError(t, err)
		assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", tenantID)
	})

	t.Run("returns empty for base URL issuer", func(t *testing.T) {
		tenantID, err := service.ExtractTenantFromIssuer("https://auth.example.com")
		require.NoError(t, err)
		assert.Equal(t, "", tenantID)
	})

	t.Run("returns error for invalid issuer format", func(t *testing.T) {
		_, err := service.ExtractTenantFromIssuer("https://other.domain.com/tenants/xyz")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer format")
	})

	t.Run("returns error for malformed issuer", func(t *testing.T) {
		_, err := service.ExtractTenantFromIssuer("not-a-url")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer format")
	})
}

func Test_PerTenantIssuerInToken(t *testing.T) {
	service := NewJWTService("signing-key", "https://auth.example.com", "audience", time.Hour)
	testTenantID := "tenant-abc-123"

	t.Run("access token has per-tenant issuer", func(t *testing.T) {
		token, err := service.GenerateAccessToken(userID, sessionID, clientID, testTenantID, []string{"openid"})
		require.NoError(t, err)

		claims, err := service.ValidateToken(token)
		require.NoError(t, err)

		assert.Equal(t, "https://auth.example.com/tenants/tenant-abc-123", claims.Issuer)
		assert.Equal(t, testTenantID, claims.TenantID)
	})

	t.Run("ID token has per-tenant issuer", func(t *testing.T) {
		token, err := service.GenerateIDToken(userID, sessionID, clientID, testTenantID)
		require.NoError(t, err)

		claims, err := service.ValidateIDToken(token)
		require.NoError(t, err)

		assert.Equal(t, "https://auth.example.com/tenants/tenant-abc-123", claims.Issuer)
	})
}
