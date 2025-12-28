package session

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

// AGENTS.MD JUSTIFICATION: Session store invariants (not-found, revocation, monotonic timestamps)
// are exercised here because feature tests do not cover in-memory persistence semantics.
type InMemorySessionStoreSuite struct {
	suite.Suite
	store *InMemorySessionStore
}

func (s *InMemorySessionStoreSuite) SetupTest() {
	s.store = New()
}

func (s *InMemorySessionStoreSuite) TestSessionStore_PersistAndLookup() {
	session := &models.Session{
		ID:             id.SessionID(uuid.New()),
		UserID:         id.UserID(uuid.New()),
		RequestedScope: []string{"openid"},
		Status:         models.SessionStatusPendingConsent,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	err := s.store.Create(context.Background(), session)
	s.Require().NoError(err)

	foundByID, err := s.store.FindByID(context.Background(), session.ID)
	s.Require().NoError(err)
	s.Equal(session, foundByID)

}

func (s *InMemorySessionStoreSuite) TestSessionStore_NotFound() {
	_, err := s.store.FindByID(context.Background(), id.SessionID(uuid.New()))
	s.Require().ErrorIs(err, sentinel.ErrNotFound)
}

func (s *InMemorySessionStoreSuite) TestSessionStore_UpdateStatus() {
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
	s.Require().NoError(err)

	// Update session status
	session.Status = models.SessionStatusActive
	err = s.store.UpdateSession(context.Background(), session)
	s.Require().NoError(err)

	// Verify the update
	found, err := s.store.FindByID(context.Background(), session.ID)
	s.Require().NoError(err)
	s.Equal(models.SessionStatusActive, found.Status)
}

func (s *InMemorySessionStoreSuite) TestSessionStore_UpdateMissing() {
	session := &models.Session{
		ID:             id.SessionID(uuid.New()),
		UserID:         id.UserID(uuid.New()),
		RequestedScope: []string{"openid"},
		Status:         models.SessionStatusActive,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	err := s.store.UpdateSession(context.Background(), session)
	s.Require().ErrorIs(err, sentinel.ErrNotFound)
}

func (s *InMemorySessionStoreSuite) TestSessionStore_DeleteByUser() {
	userID := id.UserID(uuid.New())
	otherUserID := id.UserID(uuid.New())
	matching := &models.Session{ID: id.SessionID(uuid.New()), UserID: userID}
	other := &models.Session{ID: id.SessionID(uuid.New()), UserID: otherUserID}

	s.Require().NoError(s.store.Create(context.Background(), matching))
	s.Require().NoError(s.store.Create(context.Background(), other))

	err := s.store.DeleteSessionsByUser(context.Background(), userID)
	s.Require().NoError(err)

	_, err = s.store.FindByID(context.Background(), matching.ID)
	s.Require().ErrorIs(err, sentinel.ErrNotFound)

	fetchedOther, err := s.store.FindByID(context.Background(), other.ID)
	s.Require().NoError(err)
	s.Equal(other, fetchedOther)

	err = s.store.DeleteSessionsByUser(context.Background(), userID)
	s.Require().ErrorIs(err, sentinel.ErrNotFound)
}

func (s *InMemorySessionStoreSuite) TestSessionStore_RevocationMarksStatus() {
	session := &models.Session{
		ID:        id.SessionID(uuid.New()),
		UserID:    id.UserID(uuid.New()),
		Status:    models.SessionStatusActive,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	s.Require().NoError(s.store.Create(context.Background(), session))

	err := s.store.RevokeSession(context.Background(), session.ID)
	s.Require().NoError(err)

	found, err := s.store.FindByID(context.Background(), session.ID)
	s.Require().NoError(err)
	s.Equal(models.SessionStatusRevoked, found.Status)
	s.Require().NotNil(found.RevokedAt)

	err = s.store.RevokeSessionIfActive(context.Background(), session.ID, time.Now())
	s.Require().ErrorIs(err, ErrSessionRevoked)
}

func (s *InMemorySessionStoreSuite) TestSessionStore_RevocationMissing() {
	err := s.store.RevokeSession(context.Background(), id.SessionID(uuid.New()))
	s.Require().ErrorIs(err, sentinel.ErrNotFound)
}

func (s *InMemorySessionStoreSuite) TestSessionStore_AdvanceLastSeen() {
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
	s.Require().NoError(s.store.Create(ctx, session))

	updated, err := s.store.AdvanceLastSeen(ctx, session.ID, session.ClientID, now, "jti-1", true, "device-1", "fp-1")
	s.Require().NoError(err)
	s.Equal(models.SessionStatusActive, updated.Status)
	s.Equal("jti-1", updated.LastAccessTokenJTI)
	s.Equal("device-1", updated.DeviceID)
	s.Equal("fp-1", updated.DeviceFingerprintHash)
	s.Equal(now, updated.LastSeenAt)

	// Monotonic update should retain the newer timestamp
	older := now.Add(-time.Minute)
	updated, err = s.store.AdvanceLastSeen(ctx, session.ID, session.ClientID, older, "jti-2", false, "", "")
	s.Require().NoError(err)
	s.Equal(now, updated.LastSeenAt)
	s.Equal("jti-2", updated.LastAccessTokenJTI)
}

func (s *InMemorySessionStoreSuite) TestSessionStore_AdvanceLastSeenRejectsRevoked() {
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
	s.Require().NoError(s.store.Create(ctx, session))

	_, err := s.store.AdvanceLastSeen(ctx, session.ID, session.ClientID, now, "", false, "", "")
	s.Require().ErrorIs(err, ErrSessionRevoked)
}

func (s *InMemorySessionStoreSuite) TestSessionStore_AdvanceLastRefreshed() {
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
	s.Require().NoError(s.store.Create(ctx, session))

	updated, err := s.store.AdvanceLastRefreshed(ctx, session.ID, session.ClientID, now, "jti-1", "", "")
	s.Require().NoError(err)
	s.Require().NotNil(updated.LastRefreshedAt)
	s.Equal(now, *updated.LastRefreshedAt)
	s.Equal(now, updated.LastSeenAt)
	s.Equal("jti-1", updated.LastAccessTokenJTI)

	// Older timestamps should not move the fields backwards
	past := now.Add(-time.Minute)
	updated, err = s.store.AdvanceLastRefreshed(ctx, session.ID, session.ClientID, past, "jti-2", "", "")
	s.Require().NoError(err)
	s.Equal(now, *updated.LastRefreshedAt)
	s.Equal("jti-2", updated.LastAccessTokenJTI)
}

func TestInMemorySessionStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemorySessionStoreSuite))
}
