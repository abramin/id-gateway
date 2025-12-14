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
	token, err := jwtService.GenerateIDToken(userID, sessionID, clientID)
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
