package session

import (
	"context"
	"testing"
	"time"

	"credo/internal/auth/models"
	id "credo/pkg/domain"

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
		ID:             id.SessionID(uuid.New()),
		UserID:         id.UserID(uuid.New()),
		RequestedScope: []string{"openid"},
		Status:         models.SessionStatusPendingConsent,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	err := s.store.Create(context.Background(), session)
	require.NoError(s.T(), err)

	foundByID, err := s.store.FindByID(context.Background(), session.ID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), session, foundByID)

}

func (s *InMemorySessionStoreSuite) TestFindNotFound() {
	_, err := s.store.FindByID(context.Background(), id.SessionID(uuid.New()))
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func (s *InMemorySessionStoreSuite) TestUpdateSession() {
	session := &models.Session{
		ID:             id.SessionID(uuid.New()),
		UserID:         id.UserID(uuid.New()),
		RequestedScope: []string{"openid"},
		Status:         models.SessionStatusPendingConsent,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	// Create initial session
	err := s.store.Create(context.Background(), session)
	require.NoError(s.T(), err)

	// Update session status
	session.Status = models.SessionStatusActive
	err = s.store.UpdateSession(context.Background(), session)
	require.NoError(s.T(), err)

	// Verify the update
	found, err := s.store.FindByID(context.Background(), session.ID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), models.SessionStatusActive, found.Status)
}

func (s *InMemorySessionStoreSuite) TestUpdateSessionNotFound() {
	session := &models.Session{
		ID:             id.SessionID(uuid.New()),
		UserID:         id.UserID(uuid.New()),
		RequestedScope: []string{"openid"},
		Status:         models.SessionStatusActive,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	err := s.store.UpdateSession(context.Background(), session)
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func (s *InMemorySessionStoreSuite) TestDeleteSessionsByUser() {
	userID := id.UserID(uuid.New())
	otherUserID := id.UserID(uuid.New())
	matching := &models.Session{ID: id.SessionID(uuid.New()), UserID: userID}
	other := &models.Session{ID: id.SessionID(uuid.New()), UserID: otherUserID}

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
		ID:        id.SessionID(uuid.New()),
		UserID:    id.UserID(uuid.New()),
		Status:    models.SessionStatusActive,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	require.NoError(s.T(), s.store.Create(context.Background(), session))

	err := s.store.RevokeSession(context.Background(), session.ID)
	require.NoError(s.T(), err)

	found, err := s.store.FindByID(context.Background(), session.ID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), models.SessionStatusRevoked, found.Status)
	require.NotNil(s.T(), found.RevokedAt)

	err = s.store.RevokeSessionIfActive(context.Background(), session.ID, time.Now())
	assert.ErrorIs(s.T(), err, ErrSessionRevoked)
}

func (s *InMemorySessionStoreSuite) TestRevokeSessionNotFound() {
	err := s.store.RevokeSession(context.Background(), id.SessionID(uuid.New()))
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func (s *InMemorySessionStoreSuite) TestAdvanceLastSeen() {
	ctx := context.Background()
	now := time.Now()
	session := &models.Session{
		ID:         id.SessionID(uuid.New()),
		UserID:     id.UserID(uuid.New()),
		ClientID:   id.ClientID(uuid.New()),
		Status:     models.SessionStatusPendingConsent,
		CreatedAt:  now.Add(-time.Hour),
		ExpiresAt:  now.Add(time.Hour),
		LastSeenAt: now.Add(-time.Minute),
	}
	require.NoError(s.T(), s.store.Create(ctx, session))

	updated, err := s.store.AdvanceLastSeen(ctx, session.ID, session.ClientID.String(), now, "jti-1", true, "device-1", "fp-1")
	require.NoError(s.T(), err)
	assert.Equal(s.T(), models.SessionStatusActive, updated.Status)
	assert.Equal(s.T(), "jti-1", updated.LastAccessTokenJTI)
	assert.Equal(s.T(), "device-1", updated.DeviceID)
	assert.Equal(s.T(), "fp-1", updated.DeviceFingerprintHash)
	assert.Equal(s.T(), now, updated.LastSeenAt)

	// Monotonic update should retain the newer timestamp
	older := now.Add(-time.Minute)
	updated, err = s.store.AdvanceLastSeen(ctx, session.ID, session.ClientID.String(), older, "jti-2", false, "", "")
	require.NoError(s.T(), err)
	assert.Equal(s.T(), now, updated.LastSeenAt)
	assert.Equal(s.T(), "jti-2", updated.LastAccessTokenJTI)
}

func (s *InMemorySessionStoreSuite) TestAdvanceLastSeenRejectsInvalid() {
	ctx := context.Background()
	now := time.Now()
	session := &models.Session{
		ID:         id.SessionID(uuid.New()),
		UserID:     id.UserID(uuid.New()),
		ClientID:   id.ClientID(uuid.New()),
		Status:     models.SessionStatusRevoked,
		CreatedAt:  now.Add(-time.Hour),
		ExpiresAt:  now.Add(time.Hour),
		LastSeenAt: now.Add(-time.Minute),
	}
	require.NoError(s.T(), s.store.Create(ctx, session))

	_, err := s.store.AdvanceLastSeen(ctx, session.ID, session.ClientID.String(), now, "", false, "", "")
	assert.ErrorIs(s.T(), err, ErrSessionRevoked)
}

func (s *InMemorySessionStoreSuite) TestAdvanceLastRefreshed() {
	ctx := context.Background()
	now := time.Now()
	session := &models.Session{
		ID:         id.SessionID(uuid.New()),
		UserID:     id.UserID(uuid.New()),
		ClientID:   id.ClientID(uuid.New()),
		Status:     models.SessionStatusActive,
		CreatedAt:  now.Add(-time.Hour),
		ExpiresAt:  now.Add(time.Hour),
		LastSeenAt: now.Add(-time.Minute),
	}
	require.NoError(s.T(), s.store.Create(ctx, session))

	updated, err := s.store.AdvanceLastRefreshed(ctx, session.ID, session.ClientID.String(), now, "jti-1", "", "")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), updated.LastRefreshedAt)
	assert.Equal(s.T(), now, *updated.LastRefreshedAt)
	assert.Equal(s.T(), now, updated.LastSeenAt)
	assert.Equal(s.T(), "jti-1", updated.LastAccessTokenJTI)

	// Older timestamps should not move the fields backwards
	past := now.Add(-time.Minute)
	updated, err = s.store.AdvanceLastRefreshed(ctx, session.ID, session.ClientID.String(), past, "jti-2", "", "")
	require.NoError(s.T(), err)
	assert.Equal(s.T(), now, *updated.LastRefreshedAt)
	assert.Equal(s.T(), "jti-2", updated.LastAccessTokenJTI)
}

func TestInMemorySessionStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemorySessionStoreSuite))
}
