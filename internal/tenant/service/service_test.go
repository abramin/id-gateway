package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
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
	svc, err := New(s.tenantStore, s.clientStore, nil)
	s.Require().NoError(err)
	s.service = svc
}

func TestServiceSuite(t *testing.T) {
	suite.Run(t, new(ServiceSuite))
}

// Shared test helpers

func (s *ServiceSuite) createTestTenant(name string) *tenant.Tenant {
	t, err := s.service.CreateTenant(context.Background(), name)
	s.Require().NoError(err)
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
	s.Require().NoError(err)
	return client
}

// TestTenantCreation verifies tenant creation domain invariants.
// Feature files test HTTP-level behavior; these tests verify specific error CODEs
// and exact boundaries that cannot be easily asserted in Gherkin.
func (s *ServiceSuite) TestTenantCreation() {
	s.Run("rejects empty name with invariant violation", func() {
		_, err := s.service.CreateTenant(context.Background(), "")
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeInvariantViolation))
	})

	s.Run("rejects name exceeding 128 chars", func() {
		longName := make([]byte, 129)
		_, err := s.service.CreateTenant(context.Background(), string(longName))
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeInvariantViolation))
	})

	s.Run("enforces case-insensitive name uniqueness", func() {
		_, err := s.service.CreateTenant(context.Background(), "UniqueTest")
		s.Require().NoError(err)

		_, err = s.service.CreateTenant(context.Background(), "uniquetest")
		s.Require().Error(err, "expected conflict for duplicate name")
	})
}

// TestTenantDetails verifies tenant retrieval includes accurate counts.
func (s *ServiceSuite) TestTenantDetails() {
	s.Run("includes client count", func() {
		tenantRecord := s.createTestTenant("Acme")
		s.createTestClient(tenantRecord.ID)

		details, err := s.service.GetTenant(context.Background(), tenantRecord.ID)
		s.Require().NoError(err)
		s.Equal(1, details.ClientCount)
		s.Equal(tenantRecord.ID, details.ID)
	})
}

// TestClientCreation verifies client creation behaviors and security invariants.
// Security-related tests verify specific error codes that cannot be tested via E2E.
func (s *ServiceSuite) TestClientCreation() {
	s.Run("stores secret as bcrypt hash", func() {
		// This cannot be tested via feature files because they cannot inspect the stored hash value.
		tenantRecord := s.createTestTenant("Acme")

		client, secret, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
			TenantID:      tenantRecord.ID,
			Name:          "Web",
			RedirectURIs:  []string{"https://app.example.com/callback"},
			AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
			AllowedScopes: []string{"openid"},
		})
		s.Require().NoError(err)
		s.NotEmpty(secret, "expected secret for confidential client")

		stored, err := s.clientStore.FindByID(context.Background(), client.ID)
		s.Require().NoError(err)
		s.NotEmpty(stored.ClientSecretHash, "expected stored client secret hash")

		err = bcrypt.CompareHashAndPassword([]byte(stored.ClientSecretHash), []byte(secret))
		s.NoError(err, "stored hash should match client secret")
	})

	s.Run("rejects public client with client_credentials grant", func() {
		// Feature files can only assert HTTP status codes, not the specific domain error codes.
		tenantRecord := s.createTestTenant("PublicValidation")

		_, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
			TenantID:      tenantRecord.ID,
			Name:          "Public",
			RedirectURIs:  []string{"https://app.example.com/callback"},
			AllowedGrants: []tenant.GrantType{tenant.GrantTypeClientCredentials},
			AllowedScopes: []string{"openid"},
			Public:        true,
		})
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeValidation), "expected validation error for public client with client_credentials")
	})

	s.Run("rejects missing required fields", func() {
		_, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{TenantID: id.TenantID(uuid.New())})
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeValidation) || dErrors.HasCode(err, dErrors.CodeNotFound))
	})
}

// TestClientRedirectURIValidation verifies redirect URI security rules.
// Feature files test HTTP 400, but these verify the specific CodeValidation error code.
func (s *ServiceSuite) TestClientRedirectURIValidation() {
	s.Run("rejects URI without host", func() {
		tenantRecord := s.createTestTenant("URIHost")

		_, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
			TenantID:      tenantRecord.ID,
			Name:          "Web",
			RedirectURIs:  []string{"https:///callback"},
			AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
			AllowedScopes: []string{"openid"},
		})
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeValidation), "expected validation error for redirect without host")
	})

	s.Run("rejects localhost subdomain bypass attempt", func() {
		// Prevents DNS rebinding attacks (e.g., localhost.attacker.com).
		tenantRecord := s.createTestTenant("LocalhostBypass")

		_, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
			TenantID:      tenantRecord.ID,
			Name:          "Web",
			RedirectURIs:  []string{"http://localhost.attacker.com/callback"},
			AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
			AllowedScopes: []string{"openid"},
		})
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeValidation),
			"expected validation error for localhost subdomain bypass attempt")
	})

	s.Run("allows valid localhost URIs", func() {
		tenantRecord := s.createTestTenant("ValidLocalhost")

		_, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
			TenantID:      tenantRecord.ID,
			Name:          "Local Dev",
			RedirectURIs:  []string{"http://localhost/callback"},
			AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
			AllowedScopes: []string{"openid"},
		})
		s.Require().NoError(err)

		_, _, err = s.service.CreateClient(context.Background(), &CreateClientCommand{
			TenantID:      tenantRecord.ID,
			Name:          "Local Dev 2",
			RedirectURIs:  []string{"http://localhost:3000/callback"},
			AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
			AllowedScopes: []string{"openid"},
		})
		s.Require().NoError(err)
	})
}

// TestClientUpdates verifies client update behaviors and security invariants.
func (s *ServiceSuite) TestClientUpdates() {
	s.Run("rejects client_credentials grant for public client", func() {
		// This is a separate path from creation and must be validated independently.
		tenantRecord := s.createTestTenant("PublicUpdate")

		publicClient, _, err := s.service.CreateClient(context.Background(), &CreateClientCommand{
			TenantID:      tenantRecord.ID,
			Name:          "Public SPA",
			RedirectURIs:  []string{"https://app.example.com/callback"},
			AllowedGrants: []tenant.GrantType{tenant.GrantTypeAuthorizationCode},
			AllowedScopes: []string{"openid"},
			Public:        true,
		})
		s.Require().NoError(err)
		s.False(publicClient.IsConfidential(), "expected public client")

		cmd := &UpdateClientCommand{}
		cmd.SetAllowedGrants([]tenant.GrantType{tenant.GrantTypeClientCredentials})
		_, _, err = s.service.UpdateClient(context.Background(), publicClient.ID, cmd)
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeValidation),
			"expected validation error when adding client_credentials to public client")
	})

	s.Run("rejects invalid redirect URI", func() {
		cmd := &UpdateClientCommand{}
		cmd.SetRedirectURIs([]string{"invalid"})
		_, _, err := s.service.UpdateClient(context.Background(), id.ClientID(uuid.New()), cmd)
		s.Require().Error(err)
	})
}

// TestClientResolution verifies client lookup and tenant scoping behaviors.
func (s *ServiceSuite) TestClientResolution() {
	s.Run("resolves client by OAuth client ID", func() {
		tenantRecord := s.createTestTenant("Resolve")
		created := s.createTestClient(tenantRecord.ID)

		client, tenantObj, err := s.service.ResolveClient(context.Background(), created.OAuthClientID)
		s.Require().NoError(err)
		s.Equal(tenantRecord.ID, tenantObj.ID)
		s.Equal(created.ID, client.ID)
	})

	s.Run("enforces tenant isolation", func() {
		// This is tested here because the feature file tests use platform admin auth
		// (X-Admin-Token) which bypasses tenant scoping. When tenant admin auth is
		// implemented, this should be covered by a feature scenario.
		t1 := s.createTestTenant("Acme")
		t2 := s.createTestTenant("Beta")
		created := s.createTestClient(t1.ID)

		_, err := s.service.GetClientForTenant(context.Background(), t2.ID, created.ID)
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeNotFound), "expected not found when tenant mismatched")
	})
}
