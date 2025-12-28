package user

import (
	"context"
	"testing"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
)

// AGENTS.MD JUSTIFICATION: User store invariants (lookup, delete, ErrNotFound)
// are validated here to protect service behavior outside feature coverage.
type InMemoryUserStoreSuite struct {
	suite.Suite
	store *InMemoryUserStore
}

func (s *InMemoryUserStoreSuite) SetupTest() {
	s.store = New()
}

func (s *InMemoryUserStoreSuite) TestUserStore_PersistAndLookup() {
	user := &models.User{
		ID:        id.UserID(uuid.New()),
		Email:     "jane.doe@example.com",
		FirstName: "Jane",
		LastName:  "Doe",
		Verified:  false,
	}

	err := s.store.Save(context.Background(), user)
	s.Require().NoError(err)

	foundByID, err := s.store.FindByID(context.Background(), user.ID)
	s.Require().NoError(err)
	s.Equal(user, foundByID)

	foundByEmail, err := s.store.FindByEmail(context.Background(), user.Email)
	s.Require().NoError(err)
	s.Equal(user, foundByEmail)
}

func (s *InMemoryUserStoreSuite) TestUserStore_NotFound() {
	_, err := s.store.FindByID(context.Background(), id.UserID(uuid.New()))
	s.Require().ErrorIs(err, sentinel.ErrNotFound)

	_, err = s.store.FindByEmail(context.Background(), "missing@example.com")
	s.Require().ErrorIs(err, sentinel.ErrNotFound)
}

func (s *InMemoryUserStoreSuite) TestUserStore_Delete() {
	user := &models.User{
		ID:        id.UserID(uuid.New()),
		Email:     "delete.me@example.com",
		FirstName: "Delete",
		LastName:  "Me",
	}
	s.Require().NoError(s.store.Save(context.Background(), user))

	s.Require().NoError(s.store.Delete(context.Background(), user.ID))

	_, err := s.store.FindByID(context.Background(), user.ID)
	s.Require().ErrorIs(err, sentinel.ErrNotFound)

	err = s.store.Delete(context.Background(), user.ID)
	s.Require().ErrorIs(err, sentinel.ErrNotFound)
}

func TestInMemoryUserStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemoryUserStoreSuite))
}
