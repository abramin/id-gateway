package refreshtoken

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

type InMemoryRefreshTokenStoreSuite struct {
	suite.Suite
	store *InMemoryRefreshTokenStore
}

func (s *InMemoryRefreshTokenStoreSuite) SetupTest() {
	s.store = NewInMemoryRefreshTokenStore()
}

func (s *InMemoryRefreshTokenStoreSuite) TestCreateAndFind() {
	sessionID := uuid.New()
	record := &models.RefreshTokenRecord{
		ID:        uuid.New(),
		Token:     "ref_123",
		SessionID: sessionID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := s.store.Create(context.Background(), record)
	require.NoError(s.T(), err)

	foundByID, err := s.store.FindBySessionID(context.Background(), sessionID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), record, foundByID)
}

func (s *InMemoryRefreshTokenStoreSuite) TestFindNotFound() {
	_, err := s.store.FindBySessionID(context.Background(), uuid.New())
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func (s *InMemoryRefreshTokenStoreSuite) TestDeleteSessionsByUser() {
	sessionID := uuid.New()
	otherSessionID := uuid.New()
	matching := &models.RefreshTokenRecord{ID: uuid.New(), Token: "ref_match", SessionID: sessionID}
	other := &models.RefreshTokenRecord{ID: uuid.New(), Token: "ref_other", SessionID: otherSessionID}

	require.NoError(s.T(), s.store.Create(context.Background(), matching))
	require.NoError(s.T(), s.store.Create(context.Background(), other))

	err := s.store.DeleteBySessionID(context.Background(), sessionID)
	require.NoError(s.T(), err)

	_, err = s.store.FindBySessionID(context.Background(), matching.SessionID)
	assert.ErrorIs(s.T(), err, ErrNotFound)

	fetchedOther, err := s.store.FindBySessionID(context.Background(), other.SessionID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), other, fetchedOther)

	err = s.store.DeleteBySessionID(context.Background(), sessionID)
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func (s *InMemoryRefreshTokenStoreSuite) TestConsumeMarksUsedAndTouches() {
	sessionID := uuid.New()
	now := time.Now()
	record := &models.RefreshTokenRecord{
		ID:        uuid.New(),
		Token:     "ref_123",
		SessionID: sessionID,
		CreatedAt: now.Add(-1 * time.Minute),
		ExpiresAt: now.Add(1 * time.Hour),
		Used:      false,
	}

	require.NoError(s.T(), s.store.Create(context.Background(), record))

	consumeAt := now.Add(10 * time.Second)
	consumed, err := s.store.ConsumeRefreshToken(context.Background(), record.Token, consumeAt)
	require.NoError(s.T(), err)

	assert.True(s.T(), consumed.Used)
	require.NotNil(s.T(), consumed.LastRefreshedAt)
	assert.Equal(s.T(), consumeAt, *consumed.LastRefreshedAt)

	_, err = s.store.ConsumeRefreshToken(context.Background(), record.Token, consumeAt)
	assert.ErrorIs(s.T(), err, ErrRefreshTokenUsed)
}

func (s *InMemoryRefreshTokenStoreSuite) TestFindBySessionIDReturnsNewestActive() {
	sessionID := uuid.New()
	now := time.Now()

	old := &models.RefreshTokenRecord{
		ID:        uuid.New(),
		Token:     "ref_old",
		SessionID: sessionID,
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(24 * time.Hour),
		Used:      false,
	}
	newer := &models.RefreshTokenRecord{
		ID:        uuid.New(),
		Token:     "ref_new",
		SessionID: sessionID,
		CreatedAt: now.Add(-1 * time.Hour),
		ExpiresAt: now.Add(24 * time.Hour),
		Used:      false,
	}

	require.NoError(s.T(), s.store.Create(context.Background(), old))
	require.NoError(s.T(), s.store.Create(context.Background(), newer))

	found, err := s.store.FindBySessionID(context.Background(), sessionID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), newer, found)

	// Once the newest is used, it should return the remaining active token.
	_, err = s.store.ConsumeRefreshToken(context.Background(), newer.Token, now)
	require.NoError(s.T(), err)
	found, err = s.store.FindBySessionID(context.Background(), sessionID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), old, found)
}

func (s *InMemoryRefreshTokenStoreSuite) TestConsumeRefreshTokenRejectsExpired() {
	now := time.Now()
	record := &models.RefreshTokenRecord{
		ID:        uuid.New(),
		Token:     "ref_expired",
		SessionID: uuid.New(),
		CreatedAt: now.Add(-time.Hour),
		ExpiresAt: now.Add(-time.Minute),
		Used:      false,
	}
	require.NoError(s.T(), s.store.Create(context.Background(), record))

	_, err := s.store.ConsumeRefreshToken(context.Background(), record.Token, now)
	assert.ErrorIs(s.T(), err, ErrRefreshTokenExpired)
}

func TestInMemoryRefreshTokenStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemoryRefreshTokenStoreSuite))
}
