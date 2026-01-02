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

	err := s.store.RevokeSessionIfActive(context.Background(), session.ID, time.Now())
	s.Require().NoError(err)

	found, err := s.store.FindByID(context.Background(), session.ID)
	s.Require().NoError(err)
	s.Equal(models.SessionStatusRevoked, found.Status)
	s.Require().NotNil(found.RevokedAt)

	err = s.store.RevokeSessionIfActive(context.Background(), session.ID, time.Now())
	s.Require().ErrorIs(err, ErrSessionRevoked)
}

func (s *InMemorySessionStoreSuite) TestSessionStore_RevocationMissing() {
	err := s.store.RevokeSessionIfActive(context.Background(), id.SessionID(uuid.New()), time.Now())
	s.Require().ErrorIs(err, sentinel.ErrNotFound)
}

func TestInMemorySessionStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemorySessionStoreSuite))
}
