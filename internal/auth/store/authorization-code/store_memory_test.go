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

func (s *InMemoryAuthorizationCodeStoreSuite) TestAuthorizationCodeStore_Execute() {
	ctx := context.Background()
	now := time.Now()
	record := &models.AuthorizationCodeRecord{
		Code:        "authz_execute",
		SessionID:   id.SessionID(uuid.New()),
		RedirectURI: "https://app/callback",
		ExpiresAt:   now.Add(time.Minute),
		Used:        false,
		CreatedAt:   now.Add(-time.Minute),
	}
	s.Require().NoError(s.store.Create(ctx, record))

	// Execute with domain validation and mutation
	consumed, err := s.store.Execute(ctx, record.Code,
		func(r *models.AuthorizationCodeRecord) error {
			return r.ValidateForConsume(record.RedirectURI, now)
		},
		func(r *models.AuthorizationCodeRecord) {
			r.MarkUsed()
		},
	)
	s.Require().NoError(err)
	s.True(consumed.Used)

	// Already used - validation fails, record returned for replay detection
	consumed, err = s.store.Execute(ctx, record.Code,
		func(r *models.AuthorizationCodeRecord) error {
			return r.ValidateForConsume(record.RedirectURI, now)
		},
		func(r *models.AuthorizationCodeRecord) {
			r.MarkUsed()
		},
	)
	s.Require().Error(err)
	s.Contains(err.Error(), "already used")
	s.NotNil(consumed) // Record returned for replay detection

	// Not found
	_, err = s.store.Execute(ctx, "missing",
		func(r *models.AuthorizationCodeRecord) error { return nil },
		func(r *models.AuthorizationCodeRecord) {},
	)
	s.Require().ErrorIs(err, sentinel.ErrNotFound)
}

func (s *InMemoryAuthorizationCodeStoreSuite) TestAuthorizationCodeStore_ExecuteValidation() {
	ctx := context.Background()
	now := time.Now()

	// Expired code
	expired := &models.AuthorizationCodeRecord{
		Code:        "authz_expired",
		SessionID:   id.SessionID(uuid.New()),
		RedirectURI: "https://app/callback",
		ExpiresAt:   now.Add(-time.Minute),
		Used:        false,
		CreatedAt:   now.Add(-2 * time.Minute),
	}
	s.Require().NoError(s.store.Create(ctx, expired))

	_, err := s.store.Execute(ctx, expired.Code,
		func(r *models.AuthorizationCodeRecord) error {
			return r.ValidateForConsume(expired.RedirectURI, now)
		},
		func(r *models.AuthorizationCodeRecord) {
			r.MarkUsed()
		},
	)
	s.Require().Error(err)
	s.Contains(err.Error(), "expired")

	// Redirect URI mismatch
	record := &models.AuthorizationCodeRecord{
		Code:        "authz_redirect",
		SessionID:   id.SessionID(uuid.New()),
		RedirectURI: "https://expected",
		ExpiresAt:   now.Add(time.Minute),
		Used:        false,
		CreatedAt:   now.Add(-time.Minute),
	}
	s.Require().NoError(s.store.Create(ctx, record))

	_, err = s.store.Execute(ctx, record.Code,
		func(r *models.AuthorizationCodeRecord) error {
			return r.ValidateForConsume("https://wrong", now)
		},
		func(r *models.AuthorizationCodeRecord) {
			r.MarkUsed()
		},
	)
	s.Require().Error(err)
	s.Contains(err.Error(), "redirect_uri mismatch")
}
