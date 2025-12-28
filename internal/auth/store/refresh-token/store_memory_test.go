package refreshtoken

import (
	"context"
	"testing"
	"time"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
)

// AGENTS.MD JUSTIFICATION: Refresh token lifecycle invariants (consume, newest active)
// are verified here because feature tests exercise only external behavior.
type InMemoryRefreshTokenStoreSuite struct {
	suite.Suite
	store *InMemoryRefreshTokenStore
}

func (s *InMemoryRefreshTokenStoreSuite) SetupTest() {
	s.store = New()
}

func (s *InMemoryRefreshTokenStoreSuite) TestRefreshTokenStore_PersistAndLookup() {
	sessionID := id.SessionID(uuid.New())
	record := &models.RefreshTokenRecord{
		ID:        uuid.New(),
		Token:     "ref_123",
		SessionID: sessionID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := s.store.Create(context.Background(), record)
	s.Require().NoError(err)

	foundByID, err := s.store.FindBySessionID(context.Background(), sessionID)
	s.Require().NoError(err)
	s.Equal(record, foundByID)
}

func (s *InMemoryRefreshTokenStoreSuite) TestRefreshTokenStore_NotFound() {
	_, err := s.store.FindBySessionID(context.Background(), id.SessionID(uuid.New()))
	s.Require().ErrorIs(err, sentinel.ErrNotFound)
}

func (s *InMemoryRefreshTokenStoreSuite) TestRefreshTokenStore_DeleteBySession() {
	sessionID := id.SessionID(uuid.New())
	otherSessionID := id.SessionID(uuid.New())
	matching := &models.RefreshTokenRecord{ID: uuid.New(), Token: "ref_match", SessionID: sessionID}
	other := &models.RefreshTokenRecord{ID: uuid.New(), Token: "ref_other", SessionID: otherSessionID}

	s.Require().NoError(s.store.Create(context.Background(), matching))
	s.Require().NoError(s.store.Create(context.Background(), other))

	err := s.store.DeleteBySessionID(context.Background(), sessionID)
	s.Require().NoError(err)

	_, err = s.store.FindBySessionID(context.Background(), matching.SessionID)
	s.Require().ErrorIs(err, sentinel.ErrNotFound)

	fetchedOther, err := s.store.FindBySessionID(context.Background(), other.SessionID)
	s.Require().NoError(err)
	s.Equal(other, fetchedOther)

	err = s.store.DeleteBySessionID(context.Background(), sessionID)
	s.Require().ErrorIs(err, sentinel.ErrNotFound)
}

func (s *InMemoryRefreshTokenStoreSuite) TestRefreshTokenStore_ConsumeMarksUsedAndTouches() {
	sessionID := id.SessionID(uuid.New())
	now := time.Now()
	record := &models.RefreshTokenRecord{
		ID:        uuid.New(),
		Token:     "ref_123",
		SessionID: sessionID,
		CreatedAt: now.Add(-1 * time.Minute),
		ExpiresAt: now.Add(1 * time.Hour),
		Used:      false,
	}

	s.Require().NoError(s.store.Create(context.Background(), record))

	consumeAt := now.Add(10 * time.Second)
	consumed, err := s.store.ConsumeRefreshToken(context.Background(), record.Token, consumeAt)
	s.Require().NoError(err)

	s.True(consumed.Used)
	s.Require().NotNil(consumed.LastRefreshedAt)
	s.Equal(consumeAt, *consumed.LastRefreshedAt)

	_, err = s.store.ConsumeRefreshToken(context.Background(), record.Token, consumeAt)
	s.Require().ErrorIs(err, sentinel.ErrAlreadyUsed)
}

func (s *InMemoryRefreshTokenStoreSuite) TestRefreshTokenStore_NewestActiveSelection() {
	sessionID := id.SessionID(uuid.New())
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

	s.Require().NoError(s.store.Create(context.Background(), old))
	s.Require().NoError(s.store.Create(context.Background(), newer))

	found, err := s.store.FindBySessionID(context.Background(), sessionID)
	s.Require().NoError(err)
	s.Equal(newer, found)

	// Once the newest is used, it should return the remaining active token.
	_, err = s.store.ConsumeRefreshToken(context.Background(), newer.Token, now)
	s.Require().NoError(err)
	found, err = s.store.FindBySessionID(context.Background(), sessionID)
	s.Require().NoError(err)
	s.Equal(old, found)
}

func (s *InMemoryRefreshTokenStoreSuite) TestRefreshTokenStore_RejectsExpired() {
	now := time.Now()
	record := &models.RefreshTokenRecord{
		ID:        uuid.New(),
		Token:     "ref_expired",
		SessionID: id.SessionID(uuid.New()),
		CreatedAt: now.Add(-time.Hour),
		ExpiresAt: now.Add(-time.Minute),
		Used:      false,
	}
	s.Require().NoError(s.store.Create(context.Background(), record))

	_, err := s.store.ConsumeRefreshToken(context.Background(), record.Token, now)
	s.Require().ErrorIs(err, sentinel.ErrExpired)
}

func TestInMemoryRefreshTokenStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemoryRefreshTokenStoreSuite))
}
