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
	id "credo/pkg/domain"
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

func (s *ServiceSuite) createTestClient(tenantID id.TenantID) *tenant.Client {
	client, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
		TenantID:      tenantID,
		Name:          "Web",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
		AllowedScopes: []string{"openid"},
	})
	require.NoError(s.T(), err)
	return client
}

// Tenant Tests

// TestCreateTenantValidation tests domain invariants for tenant creation.
// While feature file tests cover the HTTP-level "empty name returns 400" behavior,
// these tests verify the specific error CODE (CodeInvariantViolation) and the
// exact boundary (129 chars) that cannot be easily asserted in Gherkin.
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
	tenantObj, err := s.service.CreateTenant(context.Background(), "Acme")
	require.NoError(s.T(), err)
	assert.NotEqual(s.T(), uuid.Nil, tenantObj.ID)
	assert.Equal(s.T(), "Acme", tenantObj.Name)
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

	cmd := &CreateClientCommand{
		TenantID:      tenantRecord.ID,
		Name:          "Web",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
		AllowedScopes: []string{"openid"},
	}

	created, secret, err := s.service.CreateClient(context.Background(), cmd)
	require.NoError(s.T(), err)
	assert.NotEmpty(s.T(), secret, "expected client secret for confidential client")
	assert.NotEqual(s.T(), uuid.Nil, created.ID)

	fetched, err := s.service.GetClient(context.Background(), created.ID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), cmd.Name, fetched.Name)
}

func (s *ServiceSuite) TestUpdateClient() {
	tenantRecord := s.createTestTenant("Acme")
	created := s.createTestClient(tenantRecord.ID)

	newName := "Updated"
	cmd := &UpdateClientCommand{
		Name:         &newName,
		RotateSecret: true,
	}
	cmd.SetRedirectURIs([]string{"https://app.example.com/new"})

	updated, secret, err := s.service.UpdateClient(context.Background(), created.ID, cmd)
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
	assert.Equal(s.T(), tenantRecord.ID, details.ID)
}

func (s *ServiceSuite) TestValidationErrors() {
	s.T().Run("create client with missing fields", func(t *testing.T) {
		_, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{TenantID: id.TenantID(uuid.New())})
		require.Error(s.T(), err)
		assert.True(s.T(), dErrors.HasCode(err, dErrors.CodeValidation) || dErrors.HasCode(err, dErrors.CodeNotFound))
	})

	s.T().Run("update client with invalid redirect uri", func(t *testing.T) {
		cmd := &UpdateClientCommand{}
		cmd.SetRedirectURIs([]string{"invalid"})
		_, _, err := s.service.UpdateClient(context.Background(), id.ClientID(uuid.New()), cmd)
		require.Error(s.T(), err)
	})
}

// TestCreateClientHashesSecret verifies the security invariant that client secrets
// are stored as bcrypt hashes, not plaintext. This cannot be tested via feature files
// because they cannot inspect the stored hash value.
func (s *ServiceSuite) TestCreateClientHashesSecret() {
	tenantRecord := s.createTestTenant("Acme")

	client, secret, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
		TenantID:      tenantRecord.ID,
		Name:          "Web",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
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

	_, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
		TenantID:      tenantRecord.ID,
		Name:          "Public",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []tenant.GrantType{tenant.GrantTypeClientCredentials},
		AllowedScopes: []string{"openid"},
		Public:        true,
	})
	require.Error(s.T(), err)
	assert.True(s.T(), dErrors.HasCode(err, dErrors.CodeValidation), "expected validation error for public client with client_credentials")
}

func (s *ServiceSuite) TestRedirectURIRequiresHost() {
	tenantRecord := s.createTestTenant("Acme")

	_, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
		TenantID:      tenantRecord.ID,
		Name:          "Web",
		RedirectURIs:  []string{"https:///callback"},
		AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
		AllowedScopes: []string{"openid"},
	})
	require.Error(s.T(), err)
	assert.True(s.T(), dErrors.HasCode(err, dErrors.CodeValidation), "expected validation error for redirect without host")
}

// TestTenantScopedClientAccess verifies the multi-tenancy security invariant:
// a client cannot be accessed via a different tenant's scope. This is tested here
// because the feature file tests use platform admin auth (X-Admin-Token) which
// bypasses tenant scoping. When tenant admin auth is implemented, this should be
// covered by a feature scenario.
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

	client, tenantObj, err := s.service.ResolveClient(context.Background(), created.OAuthClientID)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), tenantRecord.ID, tenantObj.ID)
	assert.Equal(s.T(), created.ID, client.ID)
}

func (s *ServiceSuite) TestCreateClientWithValidInput() {
	tenantRecord := s.createTestTenant("Acme")

	client, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
		TenantID:      tenantRecord.ID,
		Name:          "Web",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
		AllowedScopes: []string{"openid"},
	})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "Web", client.Name)
	assert.Len(s.T(), client.RedirectURIs, 1)
	assert.Equal(s.T(), "https://app.example.com/callback", client.RedirectURIs[0])
	assert.Len(s.T(), client.AllowedGrants, 1)
	assert.Equal(s.T(), "authorization_code", client.AllowedGrants[0])
	assert.Len(s.T(), client.AllowedScopes, 1)
}

// TestUpdateClientRejectsClientCredentialsForPublicClient verifies the security invariant
// that public clients cannot be updated to use client_credentials grant.
// This is a separate path from creation and must be validated independently.
func (s *ServiceSuite) TestUpdateClientRejectsClientCredentialsForPublicClient() {
	tenantRecord := s.createTestTenant("Acme")

	// Create a public client with authorization_code grant
	publicClient, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
		TenantID:      tenantRecord.ID,
		Name:          "Public SPA",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
		AllowedScopes: []string{"openid"},
		Public:        true,
	})
	require.NoError(s.T(), err)
	assert.False(s.T(), publicClient.IsConfidential(), "expected public client")

	// Attempt to update with client_credentials grant - should fail
	cmd := &UpdateClientCommand{}
	cmd.SetAllowedGrants([]tenant.GrantType{tenant.GrantTypeClientCredentials})
	_, _, err = s.service.UpdateClient(context.Background(), publicClient.ID, cmd)
	require.Error(s.T(), err)
	assert.True(s.T(), dErrors.HasCode(err, dErrors.CodeValidation),
		"expected validation error when adding client_credentials to public client")
}

// TestRedirectURIRejectsLocalhostSubdomain verifies that redirect URIs with
// localhost-like subdomains (e.g., localhost.attacker.com) are rejected.
// This prevents DNS rebinding attacks.
func (s *ServiceSuite) TestRedirectURIRejectsLocalhostSubdomain() {
	tenantRecord := s.createTestTenant("Acme")

	_, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
		TenantID:      tenantRecord.ID,
		Name:          "Web",
		RedirectURIs:  []string{"http://localhost.attacker.com/callback"},
		AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
		AllowedScopes: []string{"openid"},
	})
	require.Error(s.T(), err)
	assert.True(s.T(), dErrors.HasCode(err, dErrors.CodeValidation),
		"expected validation error for localhost subdomain bypass attempt")
}

// TestRedirectURIAllowsValidLocalhost verifies legitimate localhost URIs are allowed.
func (s *ServiceSuite) TestRedirectURIAllowsValidLocalhost() {
	tenantRecord := s.createTestTenant("Acme")

	s.T().Run("localhost without port", func(t *testing.T) {
		_, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
			TenantID:      tenantRecord.ID,
			Name:          "Local Dev",
			RedirectURIs:  []string{"http://localhost/callback"},
			AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
			AllowedScopes: []string{"openid"},
		})
		require.NoError(s.T(), err)
	})

	s.T().Run("localhost with port", func(t *testing.T) {
		_, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
			TenantID:      tenantRecord.ID,
			Name:          "Local Dev 2",
			RedirectURIs:  []string{"http://localhost:3000/callback"},
			AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
			AllowedScopes: []string{"openid"},
		})
		require.NoError(s.T(), err)
	})
}
