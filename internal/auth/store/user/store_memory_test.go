package user

import (
	"context"
	"testing"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

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
		ID:        id.UserID(uuid.New()),
		Email:     "jane.doe@example.com",
		FirstName: "Jane",
		LastName:  "Doe",
		Verified:  false,
	}

	err := s.store.Save(context.Background(), user)
	require.NoError(s.T(), err)

	foundByID, err := s.store.FindByID(context.Background(), user.ID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), user, foundByID)

	foundByEmail, err := s.store.FindByEmail(context.Background(), user.Email)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), user, foundByEmail)
}

func (s *InMemoryUserStoreSuite) TestFindNotFound() {
	_, err := s.store.FindByID(context.Background(), id.UserID(uuid.New()))
	assert.ErrorIs(s.T(), err, sentinel.ErrNotFound)

	_, err = s.store.FindByEmail(context.Background(), "missing@example.com")
	assert.ErrorIs(s.T(), err, sentinel.ErrNotFound)
}

func (s *InMemoryUserStoreSuite) TestDelete() {
	user := &models.User{
		ID:        id.UserID(uuid.New()),
		Email:     "delete.me@example.com",
		FirstName: "Delete",
		LastName:  "Me",
	}
	require.NoError(s.T(), s.store.Save(context.Background(), user))

	require.NoError(s.T(), s.store.Delete(context.Background(), user.ID))

	_, err := s.store.FindByID(context.Background(), user.ID)
	assert.ErrorIs(s.T(), err, sentinel.ErrNotFound)

	err = s.store.Delete(context.Background(), user.ID)
	assert.ErrorIs(s.T(), err, sentinel.ErrNotFound)
}

func TestInMemoryUserStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemoryUserStoreSuite))
}
