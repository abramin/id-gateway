package session

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

type InMemorySessionStoreSuite struct {
	suite.Suite
	store *InMemorySessionStore
}

func (s *InMemorySessionStoreSuite) SetupTest() {
	s.store = NewInMemorySessionStore()
}

func (s *InMemorySessionStoreSuite) TestCreateAndFind() {
	session := &models.Session{
		ID:             uuid.New(),
		UserID:         uuid.New(),
		RequestedScope: []string{"openid"},
		Status:         "pending",
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	err := s.store.Create(context.Background(), session)
	require.NoError(s.T(), err)

	foundByID, err := s.store.FindByID(context.Background(), session.ID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), session, foundByID)

	foundByCode, err := s.store.FindByCode(context.Background(), "session.Code")
	require.NoError(s.T(), err)
	assert.Equal(s.T(), session, foundByCode)
}

func (s *InMemorySessionStoreSuite) TestFindNotFound() {
	_, err := s.store.FindByID(context.Background(), uuid.New())
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func (s *InMemorySessionStoreSuite) TestUpdateSession() {
	session := &models.Session{
		ID:             uuid.New(),
		UserID:         uuid.New(),
		RequestedScope: []string{"openid"},
		Status:         "pending",
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	// Create initial session
	err := s.store.Create(context.Background(), session)
	require.NoError(s.T(), err)

	// Update session status
	session.Status = "active"
	err = s.store.UpdateSession(context.Background(), session)
	require.NoError(s.T(), err)

	// Verify the update
	found, err := s.store.FindByID(context.Background(), session.ID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "active", found.Status)
}

func (s *InMemorySessionStoreSuite) TestUpdateSessionNotFound() {
	session := &models.Session{
		ID:             uuid.New(),
		UserID:         uuid.New(),
		RequestedScope: []string{"openid"},
		Status:         "active",
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	err := s.store.UpdateSession(context.Background(), session)
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func (s *InMemorySessionStoreSuite) TestDeleteSessionsByUser() {
	userID := uuid.New()
	otherUserID := uuid.New()
	matching := &models.Session{ID: uuid.New(), UserID: userID}
	other := &models.Session{ID: uuid.New(), UserID: otherUserID}

	require.NoError(s.T(), s.store.Create(context.Background(), matching))
	require.NoError(s.T(), s.store.Create(context.Background(), other))

	err := s.store.DeleteSessionsByUser(context.Background(), userID)
	require.NoError(s.T(), err)

	_, err = s.store.FindByID(context.Background(), matching.ID)
	assert.ErrorIs(s.T(), err, ErrNotFound)

	fetchedOther, err := s.store.FindByID(context.Background(), other.ID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), other, fetchedOther)

	err = s.store.DeleteSessionsByUser(context.Background(), userID)
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func (s *InMemorySessionStoreSuite) TestRevokeSessionMarksRevoked() {
	session := &models.Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Status:    "active",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	require.NoError(s.T(), s.store.Create(context.Background(), session))

	err := s.store.RevokeSession(context.Background(), session.ID)
	require.NoError(s.T(), err)

	found, err := s.store.FindByID(context.Background(), session.ID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "revoked", found.Status)
	require.NotNil(s.T(), found.RevokedAt)
}

func (s *InMemorySessionStoreSuite) TestRevokeSessionNotFound() {
	err := s.store.RevokeSession(context.Background(), uuid.New())
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func TestInMemorySessionStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemorySessionStoreSuite))
}
