package store

import (
	"context"
	"testing"
	"time"

	"id-gateway/internal/auth/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type InMemoryUserStoreSuite struct {
	suite.Suite
	store *InMemoryUserStore
}

func (s *InMemoryUserStoreSuite) SetupTest() {
	s.store = NewInMemoryUserStore()
}

func (s *InMemoryUserStoreSuite) TestSaveAndFind() {
	user := &models.User{
		ID:        uuid.New(),
		Email:     "jane.doe@example.com",
		FirstName: "Jane",
		LastName:  "Doe",
		Verified:  false,
	}

	err := s.store.Save(context.Background(), user)
	require.NoError(s.T(), err)

	foundByID, err := s.store.FindByID(context.Background(), user.ID.String())
	require.NoError(s.T(), err)
	assert.Equal(s.T(), user, foundByID)

	foundByEmail, err := s.store.FindByEmail(context.Background(), user.Email)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), user, foundByEmail)
}

func (s *InMemoryUserStoreSuite) TestFindNotFound() {
	_, err := s.store.FindByID(context.Background(), uuid.New().String())
	assert.ErrorIs(s.T(), err, ErrNotFound)

	_, err = s.store.FindByEmail(context.Background(), "missing@example.com")
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

type InMemorySessionStoreSuite struct {
	suite.Suite
	store *InMemorySessionStore
}

func (s *InMemorySessionStoreSuite) SetupTest() {
	s.store = NewInMemorySessionStore()
}

func (s *InMemorySessionStoreSuite) TestSaveAndFind() {
	session := &models.Session{
		ID:             uuid.New(),
		UserID:         uuid.New(),
		RequestedScope: []string{"openid"},
		Status:         "pending",
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	err := s.store.Save(context.Background(), session)
	require.NoError(s.T(), err)

	found, err := s.store.FindByID(context.Background(), session.ID.String())
	require.NoError(s.T(), err)
	assert.Equal(s.T(), session, found)
}

func (s *InMemorySessionStoreSuite) TestFindNotFound() {
	_, err := s.store.FindByID(context.Background(), uuid.New().String())
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func TestInMemoryUserStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemoryUserStoreSuite))
}

func TestInMemorySessionStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemorySessionStoreSuite))
}
