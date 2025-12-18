package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"

	tenant "credo/internal/tenant/models"
	clientstore "credo/internal/tenant/store/client"
	tenantstore "credo/internal/tenant/store/tenant"
	dErrors "credo/pkg/domain-errors"
)

// ServiceSuite provides shared test setup for tenant service tests.
type ServiceSuite struct {
	suite.Suite
	tenantStore *tenantstore.InMemory
	clientStore *clientstore.InMemory
	service     *Service
}

func (s *ServiceSuite) SetupTest() {
	s.tenantStore = tenantstore.NewInMemory()
	s.clientStore = clientstore.NewInMemory()
	s.service = New(s.tenantStore, s.clientStore, nil)
}

func TestServiceSuite(t *testing.T) {
	suite.Run(t, new(ServiceSuite))
}

// Shared test helpers

func (s *ServiceSuite) createTestTenant(name string) *tenant.Tenant {
	t, err := s.service.CreateTenant(context.Background(), name)
	require.NoError(s.T(), err)
	return t
}

func (s *ServiceSuite) createTestClient(tenantID uuid.UUID) *tenant.Client {
	client, _, err := s.service.CreateClient(context.Background(), &tenant.CreateClientRequest{
		TenantID:      tenantID,
		Name:          "Web",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []string{"authorization_code"},
		AllowedScopes: []string{"openid"},
	})
	require.NoError(s.T(), err)
	return client
}

// Tenant Tests

func (s *ServiceSuite) TestCreateTenantValidation() {
	s.T().Run("validates empty name", func(t *testing.T) {
		_, err := s.service.CreateTenant(context.Background(), "")
		require.Error(s.T(), err)
		assert.True(s.T(), dErrors.HasCode(err, dErrors.CodeInvariantViolation))
	})

	s.T().Run("validates name length", func(t *testing.T) {
		longName := make([]byte, 129)
		_, err := s.service.CreateTenant(context.Background(), string(longName))
		require.Error(s.T(), err)
		assert.True(s.T(), dErrors.HasCode(err, dErrors.CodeInvariantViolation))
	})
}

func (s *ServiceSuite) TestCreateTenantSuccess() {
	tenant, err := s.service.CreateTenant(context.Background(), "Acme")
	require.NoError(s.T(), err)
	assert.NotEqual(s.T(), uuid.Nil, tenant.ID)
	assert.Equal(s.T(), "Acme", tenant.Name)
}

func (s *ServiceSuite) TestCreateTenantEnforcesUniqueName() {
	_, err := s.service.CreateTenant(context.Background(), "UniqueTest")
	require.NoError(s.T(), err)

	_, err = s.service.CreateTenant(context.Background(), "uniquetest")
	require.Error(s.T(), err, "expected conflict for duplicate name")
}

// Client Tests

func (s *ServiceSuite) TestCreateAndGetClient() {
	tenantRecord := s.createTestTenant("Acme")

	req := &tenant.CreateClientRequest{
		TenantID:      tenantRecord.ID,
		Name:          "Web",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []string{"authorization_code"},
		AllowedScopes: []string{"openid"},
	}

	created, secret, err := s.service.CreateClient(context.Background(), req)
	require.NoError(s.T(), err)
	assert.NotEmpty(s.T(), secret, "expected client secret for confidential client")
	assert.NotEqual(s.T(), uuid.Nil, created.ID)

	fetched, err := s.service.GetClient(context.Background(), created.ID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), req.Name, fetched.Name)
}

func (s *ServiceSuite) TestUpdateClient() {
	tenantRecord := s.createTestTenant("Acme")
	created := s.createTestClient(tenantRecord.ID)

	newName := "Updated"
	newRedirects := []string{"https://app.example.com/new"}
	updated, secret, err := s.service.UpdateClient(context.Background(), created.ID, &tenant.UpdateClientRequest{
		Name:         &newName,
		RedirectURIs: &newRedirects,
		RotateSecret: true,
	})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), newName, updated.Name)
	assert.NotEmpty(s.T(), secret, "expected rotated secret to be returned")
}

func (s *ServiceSuite) TestGetTenantCounts() {
	tenantRecord := s.createTestTenant("Acme")
	s.createTestClient(tenantRecord.ID)

	details, err := s.service.GetTenant(context.Background(), tenantRecord.ID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 1, details.ClientCount)
	assert.Equal(s.T(), tenantRecord.ID, details.Tenant.ID)
}

func (s *ServiceSuite) TestValidationErrors() {
	s.T().Run("create client with missing fields", func(t *testing.T) {
		_, _, err := s.service.CreateClient(context.Background(), &tenant.CreateClientRequest{TenantID: uuid.New()})
		require.Error(s.T(), err)
		assert.True(s.T(), dErrors.HasCode(err, dErrors.CodeValidation) || dErrors.HasCode(err, dErrors.CodeNotFound))
	})

	s.T().Run("update client with invalid redirect uri", func(t *testing.T) {
		_, _, err := s.service.UpdateClient(context.Background(), uuid.New(), &tenant.UpdateClientRequest{
			RedirectURIs: &[]string{"invalid"},
		})
		require.Error(s.T(), err)
	})
}

func (s *ServiceSuite) TestCreateClientHashesSecret() {
	tenantRecord := s.createTestTenant("Acme")

	client, secret, err := s.service.CreateClient(context.Background(), &tenant.CreateClientRequest{
		TenantID:      tenantRecord.ID,
		Name:          "Web",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []string{"authorization_code"},
		AllowedScopes: []string{"openid"},
	})
	require.NoError(s.T(), err)
	assert.NotEmpty(s.T(), secret, "expected secret for confidential client")

	stored, err := s.clientStore.FindByID(context.Background(), client.ID)
	require.NoError(s.T(), err)
	assert.NotEmpty(s.T(), stored.ClientSecretHash, "expected stored client secret hash")

	err = bcrypt.CompareHashAndPassword([]byte(stored.ClientSecretHash), []byte(secret))
	assert.NoError(s.T(), err, "stored hash should match client secret")
}

func (s *ServiceSuite) TestPublicClientValidation() {
	tenantRecord := s.createTestTenant("Acme")

	_, _, err := s.service.CreateClient(context.Background(), &tenant.CreateClientRequest{
		TenantID:      tenantRecord.ID,
		Name:          "Public",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []string{"client_credentials"},
		AllowedScopes: []string{"openid"},
		Public:        true,
	})
	require.Error(s.T(), err)
	assert.True(s.T(), dErrors.HasCode(err, dErrors.CodeValidation), "expected validation error for public client with client_credentials")
}

func (s *ServiceSuite) TestRedirectURIRequiresHost() {
	tenantRecord := s.createTestTenant("Acme")

	_, _, err := s.service.CreateClient(context.Background(), &tenant.CreateClientRequest{
		TenantID:      tenantRecord.ID,
		Name:          "Web",
		RedirectURIs:  []string{"https:///callback"},
		AllowedGrants: []string{"authorization_code"},
		AllowedScopes: []string{"openid"},
	})
	require.Error(s.T(), err)
	assert.True(s.T(), dErrors.HasCode(err, dErrors.CodeValidation), "expected validation error for redirect without host")
}

func (s *ServiceSuite) TestTenantScopedClientAccess() {
	t1 := s.createTestTenant("Acme")
	t2 := s.createTestTenant("Beta")
	created := s.createTestClient(t1.ID)

	_, err := s.service.GetClientForTenant(context.Background(), t2.ID, created.ID)
	require.Error(s.T(), err)
	assert.True(s.T(), dErrors.HasCode(err, dErrors.CodeNotFound), "expected not found when tenant mismatched")
}

func (s *ServiceSuite) TestResolveClient() {
	tenantRecord := s.createTestTenant("Acme")
	created := s.createTestClient(tenantRecord.ID)

	client, tenantObj, err := s.service.ResolveClient(context.Background(), created.ClientID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), tenantRecord.ID, tenantObj.ID)
	assert.Equal(s.T(), created.ID, client.ID)
}

func (s *ServiceSuite) TestCreateClientNormalizesInput() {
	tenantRecord := s.createTestTenant("Acme")

	client, _, err := s.service.CreateClient(context.Background(), &tenant.CreateClientRequest{
		TenantID:      tenantRecord.ID,
		Name:          "  Web  ",
		RedirectURIs:  []string{" https://app.example.com/callback ", "https://app.example.com/callback"},
		AllowedGrants: []string{"AUTHORIZATION_CODE"},
		AllowedScopes: []string{"openid", "openid"},
	})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "Web", client.Name, "expected trimmed name")
	assert.Len(s.T(), client.RedirectURIs, 1, "expected deduplicated redirect URIs")
	assert.Equal(s.T(), "https://app.example.com/callback", client.RedirectURIs[0])
	assert.Len(s.T(), client.AllowedGrants, 1, "expected deduplicated grants")
	assert.Equal(s.T(), "authorization_code", client.AllowedGrants[0], "expected lowercased grants")
	assert.Len(s.T(), client.AllowedScopes, 1, "expected deduplicated scopes")
}
