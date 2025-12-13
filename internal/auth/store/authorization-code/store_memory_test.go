package authorizationcode

import (
	"context"
	"testing"
	"time"

	"credo/internal/auth/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type InMemoryAuthorizationCodeStoreSuite struct {
	suite.Suite
	store *InMemoryAuthorizationCodeStore
}

func (s *InMemoryAuthorizationCodeStoreSuite) SetupTest() {
	s.store = NewInMemoryAuthorizationCodeStore()
}

func (s *InMemoryAuthorizationCodeStoreSuite) TestSave() {
	authCode := &models.AuthorizationCodeRecord{
		SessionID:   uuid.New(),
		ExpiresAt:   time.Now().Add(time.Minute * 10),
		Code:        "authz_123456",
		CreatedAt:   time.Now(),
		RedirectURI: "https://example.com/callback",
	}

	err := s.store.Create(context.Background(), authCode)
	require.NoError(s.T(), err)

	foundByCode, err := s.store.FindByCode(context.Background(), "authz_123456")
	require.NoError(s.T(), err)
	assert.Equal(s.T(), authCode, foundByCode)
}

func (s *InMemoryAuthorizationCodeStoreSuite) TestFindNotFound() {
	_, err := s.store.FindByCode(context.Background(), "non_existent_code")
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func (s *InMemoryAuthorizationCodeStoreSuite) TestDelete() {
	sessionID := uuid.New()
	otherSessionID := uuid.New()
	matching := &models.AuthorizationCodeRecord{Code: "authz_match", SessionID: sessionID}
	other := &models.AuthorizationCodeRecord{Code: "authz_other", SessionID: otherSessionID}

	require.NoError(s.T(), s.store.Create(context.Background(), matching))
	require.NoError(s.T(), s.store.Create(context.Background(), other))

	err := s.store.Delete(context.Background(), matching.Code)
	require.NoError(s.T(), err)

	_, err = s.store.FindByCode(context.Background(), matching.Code)
	assert.ErrorIs(s.T(), err, ErrNotFound)

	fetchedOther, err := s.store.FindByCode(context.Background(), other.Code)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), other, fetchedOther)

	err = s.store.Delete(context.Background(), other.Code)
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func TestInMemoryAuthorizationCodeStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemoryAuthorizationCodeStoreSuite))
}
