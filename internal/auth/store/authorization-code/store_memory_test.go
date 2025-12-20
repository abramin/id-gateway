package authorizationcode

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

type InMemoryAuthorizationCodeStoreSuite struct {
	suite.Suite
	store *InMemoryAuthorizationCodeStore
}

func (s *InMemoryAuthorizationCodeStoreSuite) SetupTest() {
	s.store = NewInMemoryAuthorizationCodeStore()
}

func (s *InMemoryAuthorizationCodeStoreSuite) TestSave() {
	authCode := &models.AuthorizationCodeRecord{
		SessionID:   id.SessionID(uuid.New()),
		ExpiresAt:   time.Now().Add(time.Minute * 10),
		Code:        "authz_123456",
		CreatedAt:   time.Now(),
		RedirectURI: "https://example.com/callback",
	}

	err := s.store.Create(context.Background(), authCode)
	require.NoError(s.T(), err)

	foundByCode, err := s.store.FindByCode(context.Background(), "authz_123456")
	require.NoError(s.T(), err)
	assert.Equal(s.T(), authCode, foundByCode)
}

func (s *InMemoryAuthorizationCodeStoreSuite) TestFindNotFound() {
	_, err := s.store.FindByCode(context.Background(), "non_existent_code")
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func TestInMemoryAuthorizationCodeStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemoryAuthorizationCodeStoreSuite))
}

func (s *InMemoryAuthorizationCodeStoreSuite) TestConsumeAuthCode() {
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
	require.NoError(s.T(), s.store.Create(ctx, record))

	consumed, err := s.store.ConsumeAuthCode(ctx, record.Code, record.RedirectURI, now)
	require.NoError(s.T(), err)
	assert.True(s.T(), consumed.Used)

	_, err = s.store.ConsumeAuthCode(ctx, record.Code, record.RedirectURI, now)
	assert.ErrorIs(s.T(), err, ErrAuthCodeUsed)

	_, err = s.store.ConsumeAuthCode(ctx, "missing", record.RedirectURI, now)
	assert.ErrorIs(s.T(), err, ErrNotFound)
}

func (s *InMemoryAuthorizationCodeStoreSuite) TestConsumeAuthCodeRejectsInvalid() {
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
	require.NoError(s.T(), s.store.Create(ctx, record))

	_, err := s.store.ConsumeAuthCode(ctx, record.Code, record.RedirectURI, now)
	assert.ErrorIs(s.T(), err, ErrAuthCodeExpired)

	record2 := *record
	record2.Code = "authz_redirect"
	record2.ExpiresAt = now.Add(time.Minute)
	record2.RedirectURI = "https://expected"
	require.NoError(s.T(), s.store.Create(ctx, &record2))

	_, err = s.store.ConsumeAuthCode(ctx, record2.Code, "https://wrong", now)
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "redirect_uri mismatch")
}
