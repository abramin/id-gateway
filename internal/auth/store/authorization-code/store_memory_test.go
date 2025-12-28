package authorizationcode

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

// AGENTS.MD JUSTIFICATION: Authorization code persistence and consume semantics
// (expired, already used, redirect mismatch) are enforced here beyond feature tests.
type InMemoryAuthorizationCodeStoreSuite struct {
	suite.Suite
	store *InMemoryAuthorizationCodeStore
}

func (s *InMemoryAuthorizationCodeStoreSuite) SetupTest() {
	s.store = New()
}

func (s *InMemoryAuthorizationCodeStoreSuite) TestAuthorizationCodeStore_PersistAndLookup() {
	authCode := &models.AuthorizationCodeRecord{
		SessionID:   id.SessionID(uuid.New()),
		ExpiresAt:   time.Now().Add(time.Minute * 10),
		Code:        "authz_123456",
		CreatedAt:   time.Now(),
		RedirectURI: "https://example.com/callback",
	}

	err := s.store.Create(context.Background(), authCode)
	s.Require().NoError(err)

	foundByCode, err := s.store.FindByCode(context.Background(), "authz_123456")
	s.Require().NoError(err)
	s.Equal(authCode, foundByCode)
}

func (s *InMemoryAuthorizationCodeStoreSuite) TestAuthorizationCodeStore_NotFound() {
	_, err := s.store.FindByCode(context.Background(), "non_existent_code")
	s.Require().ErrorIs(err, sentinel.ErrNotFound)
}

func TestInMemoryAuthorizationCodeStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemoryAuthorizationCodeStoreSuite))
}

func (s *InMemoryAuthorizationCodeStoreSuite) TestAuthorizationCodeStore_Consume() {
	ctx := context.Background()
	now := time.Now()
	record := &models.AuthorizationCodeRecord{
		Code:        "authz_consume",
		SessionID:   id.SessionID(uuid.New()),
		RedirectURI: "https://app/callback",
		ExpiresAt:   now.Add(time.Minute),
		Used:        false,
		CreatedAt:   now.Add(-time.Minute),
	}
	s.Require().NoError(s.store.Create(ctx, record))

	consumed, err := s.store.ConsumeAuthCode(ctx, record.Code, record.RedirectURI, now)
	s.Require().NoError(err)
	s.True(consumed.Used)

	_, err = s.store.ConsumeAuthCode(ctx, record.Code, record.RedirectURI, now)
	s.Require().ErrorIs(err, sentinel.ErrAlreadyUsed)

	_, err = s.store.ConsumeAuthCode(ctx, "missing", record.RedirectURI, now)
	s.Require().ErrorIs(err, sentinel.ErrNotFound)
}

func (s *InMemoryAuthorizationCodeStoreSuite) TestAuthorizationCodeStore_ConsumeRejectsInvalid() {
	ctx := context.Background()
	now := time.Now()
	record := &models.AuthorizationCodeRecord{
		Code:        "authz_expired",
		SessionID:   id.SessionID(uuid.New()),
		RedirectURI: "https://app/callback",
		ExpiresAt:   now.Add(-time.Minute),
		Used:        false,
		CreatedAt:   now.Add(-2 * time.Minute),
	}
	s.Require().NoError(s.store.Create(ctx, record))

	_, err := s.store.ConsumeAuthCode(ctx, record.Code, record.RedirectURI, now)
	s.Require().ErrorIs(err, sentinel.ErrExpired)

	record2 := *record
	record2.Code = "authz_redirect"
	record2.ExpiresAt = now.Add(time.Minute)
	record2.RedirectURI = "https://expected"
	s.Require().NoError(s.store.Create(ctx, &record2))

	_, err = s.store.ConsumeAuthCode(ctx, record2.Code, "https://wrong", now)
	s.Require().Error(err)
	s.Contains(err.Error(), "redirect_uri mismatch")
}
