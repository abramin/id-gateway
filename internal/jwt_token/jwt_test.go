package jwttoken

import (
	dErrors "id-gateway/pkg/domain-errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var userID = uuid.New()
var sessionID = uuid.New()
var clientID = "test-client"
var expiresIn = time.Second * 1

var jwtService = NewJWTService(
	"test-signing-key",
	"test-issuer",
	"test-audience",
	expiresIn,
)

func Test_GenerateAccessToken(t *testing.T) {
	token, err := jwtService.GenerateAccessToken(userID, sessionID, clientID)
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
	require.ErrorIs(t, err, dErrors.New(dErrors.CodeUnauthorized, "invalid token"))
}

func Test_ValidateToken_ExpiredToken(t *testing.T) {
	token, err := jwtService.GenerateAccessToken(userID, sessionID, clientID)
	time.Sleep(expiresIn + time.Second)
	require.NoError(t, err)

	_, err = jwtService.ValidateToken(token)
	require.ErrorIs(t, err, dErrors.New(dErrors.CodeUnauthorized, "token has expired"))
}

func Test_ValidateToken_ValidTokent(t *testing.T) {
	token, err := jwtService.GenerateAccessToken(userID, sessionID, clientID)
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
	claims, err := jwtService.ValidateToken(token)
	require.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, userID.String(), claims.UserID)
	assert.Equal(t, sessionID.String(), claims.SessionID)
	assert.Equal(t, clientID, claims.ClientID)
	assert.WithinDuration(t, time.Now().Add(expiresIn), claims.ExpiresAt.Time, time.Minute)
}
