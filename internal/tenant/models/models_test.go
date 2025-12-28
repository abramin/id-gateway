package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// TenantModelSuite tests Tenant domain model behaviors.
type TenantModelSuite struct {
	suite.Suite
}

func TestTenantModelSuite(t *testing.T) {
	suite.Run(t, new(TenantModelSuite))
}

func (s *TenantModelSuite) newTenant(status TenantStatus) *Tenant {
	return &Tenant{
		ID:        id.TenantID(uuid.New()),
		Name:      "Test",
		Status:    status,
		CreatedAt: time.Now(),
	}
}

// TestLifecycle verifies tenant activation/deactivation state transitions
// and the domain invariants that prevent invalid transitions.
func (s *TenantModelSuite) TestLifecycle() {
	s.Run("deactivate active tenant succeeds", func() {
		now := time.Now()
		tenant := s.newTenant(TenantStatusActive)

		err := tenant.Deactivate(now)
		s.Require().NoError(err)
		s.Equal(TenantStatusInactive, tenant.Status)
		s.Equal(now, tenant.UpdatedAt)
	})

	s.Run("deactivate inactive tenant returns invariant violation", func() {
		tenant := s.newTenant(TenantStatusInactive)

		err := tenant.Deactivate(time.Now())
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeInvariantViolation),
			"expected invariant violation for double-deactivation")
	})

	s.Run("reactivate inactive tenant succeeds", func() {
		now := time.Now()
		tenant := s.newTenant(TenantStatusInactive)

		err := tenant.Reactivate(now)
		s.Require().NoError(err)
		s.Equal(TenantStatusActive, tenant.Status)
		s.Equal(now, tenant.UpdatedAt)
	})

	s.Run("reactivate active tenant returns invariant violation", func() {
		tenant := s.newTenant(TenantStatusActive)

		err := tenant.Reactivate(time.Now())
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeInvariantViolation),
			"expected invariant violation for double-reactivation")
	})
}

// TestIsActive verifies the IsActive helper method.
func (s *TenantModelSuite) TestIsActive() {
	s.True(s.newTenant(TenantStatusActive).IsActive())
	s.False(s.newTenant(TenantStatusInactive).IsActive())
}

// ClientModelSuite tests Client domain model behaviors.
type ClientModelSuite struct {
	suite.Suite
}

func TestClientModelSuite(t *testing.T) {
	suite.Run(t, new(ClientModelSuite))
}

func (s *ClientModelSuite) newClient(status ClientStatus, secretHash string) *Client {
	return &Client{
		ID:               id.ClientID(uuid.New()),
		TenantID:         id.TenantID(uuid.New()),
		Name:             "Test Client",
		OAuthClientID:    "test-client-id",
		ClientSecretHash: secretHash,
		Status:           status,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

// TestLifecycle verifies client activation/deactivation state transitions
// and the domain invariants that prevent invalid transitions.
func (s *ClientModelSuite) TestLifecycle() {
	s.Run("deactivate active client succeeds", func() {
		now := time.Now()
		client := s.newClient(ClientStatusActive, "hash")

		err := client.Deactivate(now)
		s.Require().NoError(err)
		s.Equal(ClientStatusInactive, client.Status)
		s.Equal(now, client.UpdatedAt)
	})

	s.Run("deactivate inactive client returns invariant violation", func() {
		client := s.newClient(ClientStatusInactive, "hash")

		err := client.Deactivate(time.Now())
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeInvariantViolation),
			"expected invariant violation for double-deactivation")
	})

	s.Run("reactivate inactive client succeeds", func() {
		now := time.Now()
		client := s.newClient(ClientStatusInactive, "hash")

		err := client.Reactivate(now)
		s.Require().NoError(err)
		s.Equal(ClientStatusActive, client.Status)
		s.Equal(now, client.UpdatedAt)
	})

	s.Run("reactivate active client returns invariant violation", func() {
		client := s.newClient(ClientStatusActive, "hash")

		err := client.Reactivate(time.Now())
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeInvariantViolation),
			"expected invariant violation for double-reactivation")
	})
}

// TestIsActive verifies the IsActive helper method.
func (s *ClientModelSuite) TestIsActive() {
	s.True(s.newClient(ClientStatusActive, "hash").IsActive())
	s.False(s.newClient(ClientStatusInactive, "hash").IsActive())
}

// TestConfidentiality verifies client type detection and grant restrictions.
func (s *ClientModelSuite) TestConfidentiality() {
	s.Run("IsConfidential checks for secret hash", func() {
		s.True(s.newClient(ClientStatusActive, "hashed-secret").IsConfidential())
		s.False(s.newClient(ClientStatusActive, "").IsConfidential())
	})

	s.Run("CanUseGrant restricts public clients from client_credentials", func() {
		confidential := s.newClient(ClientStatusActive, "hashed-secret")
		public := s.newClient(ClientStatusActive, "")

		// Confidential clients can use any grant
		s.True(confidential.CanUseGrant("authorization_code"))
		s.True(confidential.CanUseGrant("client_credentials"))
		s.True(confidential.CanUseGrant("refresh_token"))

		// Public clients cannot use client_credentials
		s.True(public.CanUseGrant("authorization_code"))
		s.False(public.CanUseGrant("client_credentials"))
		s.True(public.CanUseGrant("refresh_token"))
	})
}
