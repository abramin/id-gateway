package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// TestContext interface defines the methods needed from the main test context
type TestContext interface {
	POST(path string, body interface{}) error
	POSTWithHeaders(path string, body interface{}, headers map[string]string) error
	PUT(path string, body interface{}) error
	PUTWithHeaders(path string, body interface{}, headers map[string]string) error
	GET(path string, headers map[string]string) error
	GetResponseField(field string) (interface{}, error)
	ResponseContains(text string) bool
	GetLastResponseStatus() int
	GetLastResponseBody() []byte
	GetAdminToken() string
	GetRedirectURI() string

	// Tenant/Client management
	GetTenantID() string
	SetTenantID(tenantID string)
	GetTestClientID() string
	SetTestClientID(clientID string)
	GetClientSecret() string
	SetClientSecret(secret string)
	GetOAuthClientID() string
	SetOAuthClientID(oauthClientID string)
}

// RegisterSteps registers admin-related step definitions
func RegisterSteps(ctx *godog.ScenarioContext, tc TestContext) {
	steps := &adminSteps{
		tc:             tc,
		exactNameCache: make(map[string]string),
	}

	// Reset cache before each scenario to ensure isolation
	ctx.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		steps.exactNameCache = make(map[string]string)
		return ctx, nil
	})

	// Tenant steps
	ctx.Step(`^I create a tenant with name "([^"]*)"$`, steps.createTenant)
	ctx.Step(`^I create a tenant with exact name "([^"]*)"$`, steps.createTenantWithExactName)
	ctx.Step(`^I create a tenant with name "([^"]*)" and token "([^"]*)"$`, steps.createTenantWithToken)
	ctx.Step(`^I save the tenant ID from the response$`, steps.saveTenantIDFromResponse)
	ctx.Step(`^I get the tenant details$`, steps.getTenantDetails)
	ctx.Step(`^I deactivate the tenant$`, steps.deactivateTenant)
	ctx.Step(`^I reactivate the tenant$`, steps.reactivateTenant)

	// Client steps
	ctx.Step(`^I create a client "([^"]*)" under the tenant$`, steps.createClientUnderTenant)
	ctx.Step(`^I create a client "([^"]*)" under tenant "([^"]*)"$`, steps.createClientUnderSpecificTenant)
	ctx.Step(`^I create a client "([^"]*)" under the tenant without admin token$`, steps.createClientWithoutAdminToken)
	ctx.Step(`^I save the client ID from the response$`, steps.saveClientIDFromResponse)
	ctx.Step(`^I save the client secret from the response$`, steps.saveClientSecretFromResponse)
	ctx.Step(`^I save the OAuth client_id from the response$`, steps.saveOAuthClientIDFromResponse)
	ctx.Step(`^I get the client details$`, steps.getClientDetails)
	ctx.Step(`^I update the client name to "([^"]*)"$`, steps.updateClientName)
	ctx.Step(`^I rotate the client secret$`, steps.rotateClientSecret)
	ctx.Step(`^the new secret should be different from the saved secret$`, steps.newSecretShouldBeDifferent)
	ctx.Step(`^I deactivate the client$`, steps.deactivateClient)
	ctx.Step(`^I reactivate the client$`, steps.reactivateClient)
	ctx.Step(`^I deactivate the client without admin token$`, steps.deactivateClientWithoutAdminToken)
	ctx.Step(`^I deactivate client with id "([^"]*)"$`, steps.deactivateClientByID)

	// OAuth flow with dynamic client
	ctx.Step(`^I initiate authorization with the client$`, steps.initiateAuthorizationWithClient)

	// Security tests for tenant lifecycle
	ctx.Step(`^I deactivate the tenant without admin token$`, steps.deactivateTenantWithoutAdminToken)
	ctx.Step(`^I deactivate tenant with id "([^"]*)"$`, steps.deactivateTenantByID)

	// Public client creation
	ctx.Step(`^I create a public client "([^"]*)" under the tenant$`, steps.createPublicClientUnderTenant)
	ctx.Step(`^I create a public client "([^"]*)" with client_credentials grant under the tenant$`, steps.createPublicClientWithClientCredentialsGrant)
	ctx.Step(`^I create a client with redirect URI "([^"]*)" under the tenant$`, steps.createClientWithRedirectURI)

	// Auth tests without admin token
	ctx.Step(`^I reactivate the tenant without admin token$`, steps.reactivateTenantWithoutAdminToken)
	ctx.Step(`^I reactivate the client without admin token$`, steps.reactivateClientWithoutAdminToken)
	ctx.Step(`^I get the tenant details without admin token$`, steps.getTenantDetailsWithoutAdminToken)
	ctx.Step(`^I get the client details without admin token$`, steps.getClientDetailsWithoutAdminToken)
	ctx.Step(`^I update the client name to "([^"]*)" without admin token$`, steps.updateClientNameWithoutAdminToken)
	ctx.Step(`^I rotate the client secret without admin token$`, steps.rotateClientSecretWithoutAdminToken)

	// Update validation
	ctx.Step(`^I update the client with redirect URI "([^"]*)"$`, steps.updateClientWithRedirectURI)
	ctx.Step(`^I update the client with client_credentials grant$`, steps.updateClientWithClientCredentialsGrant)

	// Secret rotation validation
	ctx.Step(`^I authenticate with the old client secret$`, steps.authenticateWithOldClientSecret)
	ctx.Step(`^the authentication should fail$`, steps.authenticationShouldFail)

	// Name length boundary tests
	ctx.Step(`^I create a tenant with name of exactly (\d+) characters$`, steps.createTenantWithExactLength)
	ctx.Step(`^I create a client with name of exactly (\d+) characters under the tenant$`, steps.createClientWithExactLength)
}

type adminSteps struct {
	tc             TestContext
	exactNameCache map[string]string // Tracks generated names for exact name testing
}

// Tenant Steps

func (s *adminSteps) createTenant(ctx context.Context, name string) error {
	// Append unique suffix to avoid conflicts between test runs
	// Don't add suffix for empty names (validation tests)
	finalName := name
	if name != "" {
		finalName = fmt.Sprintf("%s-%d", name, time.Now().UnixNano())
	}
	body := map[string]interface{}{
		"name": finalName,
	}
	return s.tc.POSTWithHeaders("/admin/tenants", body, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

// createTenantWithExactName creates a tenant with a consistent name for duplicate testing.
// First call with a base name generates a unique name and caches it.
// Subsequent calls with the same base name (case-insensitive) reuse the cached name.
// This ensures test isolation while allowing duplicate/case-insensitive name testing.
func (s *adminSteps) createTenantWithExactName(ctx context.Context, baseName string) error {
	// Use lowercase key for case-insensitive matching (tests backend case-insensitive uniqueness)
	cacheKey := strings.ToLower(baseName)
	// Check if we already have a generated name for this base
	name, exists := s.exactNameCache[cacheKey]
	if !exists {
		// Generate unique name and cache it
		name = fmt.Sprintf("%s-%d", baseName, time.Now().UnixNano())
		s.exactNameCache[cacheKey] = name
	}
	body := map[string]interface{}{
		"name": name,
	}
	return s.tc.POSTWithHeaders("/admin/tenants", body, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *adminSteps) createTenantWithToken(ctx context.Context, name, token string) error {
	// Append unique suffix to avoid conflicts between test runs
	// Don't add suffix for empty names (validation tests)
	finalName := name
	if name != "" {
		finalName = fmt.Sprintf("%s-%d", name, time.Now().UnixNano())
	}
	body := map[string]interface{}{
		"name": finalName,
	}
	return s.tc.POSTWithHeaders("/admin/tenants", body, map[string]string{
		"X-Admin-Token": token,
	})
}

func (s *adminSteps) saveTenantIDFromResponse(ctx context.Context) error {
	tenantID, err := s.tc.GetResponseField("tenant_id")
	if err != nil {
		return fmt.Errorf("failed to get tenant_id from response: %w", err)
	}
	tenantIDStr, ok := tenantID.(string)
	if !ok {
		return fmt.Errorf("tenant_id is not a string: %T", tenantID)
	}
	s.tc.SetTenantID(tenantIDStr)
	return nil
}

func (s *adminSteps) getTenantDetails(ctx context.Context) error {
	tenantID := s.tc.GetTenantID()
	if tenantID == "" {
		return fmt.Errorf("tenant ID not set")
	}
	return s.tc.GET("/admin/tenants/"+tenantID, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

// Client Steps

func (s *adminSteps) createClientUnderTenant(ctx context.Context, clientName string) error {
	tenantID := s.tc.GetTenantID()
	if tenantID == "" {
		return fmt.Errorf("tenant ID not set")
	}
	return s.createClientUnderSpecificTenant(ctx, clientName, tenantID)
}

func (s *adminSteps) createClientUnderSpecificTenant(ctx context.Context, clientName, tenantID string) error {
	body := map[string]interface{}{
		"tenant_id":      tenantID,
		"name":           clientName,
		"redirect_uris":  []string{"http://localhost:3000/callback"},
		"allowed_grants": []string{"authorization_code", "refresh_token"},
		"allowed_scopes": []string{"openid", "profile", "email"},
		"public_client":  false,
	}
	return s.tc.POSTWithHeaders("/admin/clients", body, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *adminSteps) createClientWithoutAdminToken(ctx context.Context, clientName string) error {
	tenantID := s.tc.GetTenantID()
	if tenantID == "" {
		return fmt.Errorf("tenant ID not set")
	}
	body := map[string]interface{}{
		"tenant_id":      tenantID,
		"name":           clientName,
		"redirect_uris":  []string{"http://localhost:3000/callback"},
		"allowed_grants": []string{"authorization_code", "refresh_token"},
		"allowed_scopes": []string{"openid", "profile", "email"},
		"public_client":  false,
	}
	return s.tc.POSTWithHeaders("/admin/clients", body, map[string]string{
		"X-Admin-Token": "", // Empty token
	})
}

func (s *adminSteps) saveClientIDFromResponse(ctx context.Context) error {
	// Parse the full response to get the client object
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// The response structure is {"client_id": "...", "id": "...", ...}
	// For admin API, we use "id" (UUID) for subsequent requests
	clientID, ok := data["id"].(string)
	if !ok {
		// Try alternate field name
		clientID, ok = data["client_id"].(string)
		if !ok {
			return fmt.Errorf("client id not found in response: %s", string(s.tc.GetLastResponseBody()))
		}
	}
	s.tc.SetTestClientID(clientID)
	return nil
}

func (s *adminSteps) saveClientSecretFromResponse(ctx context.Context) error {
	secret, err := s.tc.GetResponseField("client_secret")
	if err != nil {
		return fmt.Errorf("failed to get client_secret from response: %w", err)
	}
	secretStr, ok := secret.(string)
	if !ok {
		return fmt.Errorf("client_secret is not a string: %T", secret)
	}
	s.tc.SetClientSecret(secretStr)
	return nil
}

func (s *adminSteps) getClientDetails(ctx context.Context) error {
	clientID := s.tc.GetTestClientID()
	if clientID == "" {
		return fmt.Errorf("client ID not set")
	}
	return s.tc.GET("/admin/clients/"+clientID, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *adminSteps) updateClientName(ctx context.Context, newName string) error {
	clientID := s.tc.GetTestClientID()
	if clientID == "" {
		return fmt.Errorf("client ID not set")
	}
	body := map[string]interface{}{
		"name": newName,
	}
	return s.tc.PUTWithHeaders("/admin/clients/"+clientID, body, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *adminSteps) rotateClientSecret(ctx context.Context) error {
	clientID := s.tc.GetTestClientID()
	if clientID == "" {
		return fmt.Errorf("client ID not set")
	}
	body := map[string]interface{}{
		"rotate_secret": true,
	}
	return s.tc.PUTWithHeaders("/admin/clients/"+clientID, body, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *adminSteps) newSecretShouldBeDifferent(ctx context.Context) error {
	newSecret, err := s.tc.GetResponseField("client_secret")
	if err != nil {
		return fmt.Errorf("failed to get new client_secret from response: %w", err)
	}
	newSecretStr, ok := newSecret.(string)
	if !ok {
		return fmt.Errorf("new client_secret is not a string: %T", newSecret)
	}

	oldSecret := s.tc.GetClientSecret()
	if oldSecret == "" {
		return fmt.Errorf("previous client secret not saved")
	}

	if newSecretStr == oldSecret {
		return fmt.Errorf("new secret should be different from old secret")
	}

	return nil
}

// Tenant Lifecycle Steps

func (s *adminSteps) deactivateTenant(ctx context.Context) error {
	tenantID := s.tc.GetTenantID()
	if tenantID == "" {
		return fmt.Errorf("tenant ID not set")
	}
	return s.tc.POSTWithHeaders("/admin/tenants/"+tenantID+"/deactivate", nil, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *adminSteps) reactivateTenant(ctx context.Context) error {
	tenantID := s.tc.GetTenantID()
	if tenantID == "" {
		return fmt.Errorf("tenant ID not set")
	}
	return s.tc.POSTWithHeaders("/admin/tenants/"+tenantID+"/reactivate", nil, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

// Client Lifecycle Steps

func (s *adminSteps) deactivateClient(ctx context.Context) error {
	clientID := s.tc.GetTestClientID()
	if clientID == "" {
		return fmt.Errorf("client ID not set")
	}
	return s.tc.POSTWithHeaders("/admin/clients/"+clientID+"/deactivate", nil, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *adminSteps) reactivateClient(ctx context.Context) error {
	clientID := s.tc.GetTestClientID()
	if clientID == "" {
		return fmt.Errorf("client ID not set")
	}
	return s.tc.POSTWithHeaders("/admin/clients/"+clientID+"/reactivate", nil, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *adminSteps) saveOAuthClientIDFromResponse(ctx context.Context) error {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	oauthClientID, ok := data["client_id"].(string)
	if !ok {
		return fmt.Errorf("client_id not found in response: %s", string(s.tc.GetLastResponseBody()))
	}
	s.tc.SetOAuthClientID(oauthClientID)
	return nil
}

func (s *adminSteps) initiateAuthorizationWithClient(ctx context.Context) error {
	oauthClientID := s.tc.GetOAuthClientID()
	if oauthClientID == "" {
		return fmt.Errorf("OAuth client_id not set")
	}
	body := map[string]interface{}{
		"email":        "lifecycle-test@example.com",
		"client_id":    oauthClientID,
		"scopes":       []string{"openid", "profile"},
		"redirect_uri": s.tc.GetRedirectURI(),
		"state":        "test-state-lifecycle",
	}
	return s.tc.POST("/auth/authorize", body)
}

// Security test steps

func (s *adminSteps) deactivateTenantWithoutAdminToken(ctx context.Context) error {
	tenantID := s.tc.GetTenantID()
	if tenantID == "" {
		return fmt.Errorf("tenant ID not set")
	}
	return s.tc.POSTWithHeaders("/admin/tenants/"+tenantID+"/deactivate", nil, map[string]string{
		"X-Admin-Token": "", // Empty token
	})
}

func (s *adminSteps) deactivateTenantByID(ctx context.Context, tenantID string) error {
	return s.tc.POSTWithHeaders("/admin/tenants/"+tenantID+"/deactivate", nil, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *adminSteps) deactivateClientWithoutAdminToken(ctx context.Context) error {
	clientID := s.tc.GetTestClientID()
	if clientID == "" {
		return fmt.Errorf("client ID not set")
	}
	return s.tc.POSTWithHeaders("/admin/clients/"+clientID+"/deactivate", nil, map[string]string{
		"X-Admin-Token": "", // Empty token
	})
}

func (s *adminSteps) deactivateClientByID(ctx context.Context, clientID string) error {
	return s.tc.POSTWithHeaders("/admin/clients/"+clientID+"/deactivate", nil, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

// Public Client Steps

func (s *adminSteps) createPublicClientUnderTenant(ctx context.Context, clientName string) error {
	tenantID := s.tc.GetTenantID()
	if tenantID == "" {
		return fmt.Errorf("tenant ID not set")
	}
	body := map[string]interface{}{
		"tenant_id":      tenantID,
		"name":           clientName,
		"redirect_uris":  []string{"http://localhost:3000/callback"},
		"allowed_grants": []string{"authorization_code", "refresh_token"},
		"allowed_scopes": []string{"openid", "profile", "email"},
		"public_client":  true,
	}
	return s.tc.POSTWithHeaders("/admin/clients", body, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *adminSteps) createPublicClientWithClientCredentialsGrant(ctx context.Context, clientName string) error {
	tenantID := s.tc.GetTenantID()
	if tenantID == "" {
		return fmt.Errorf("tenant ID not set")
	}
	body := map[string]interface{}{
		"tenant_id":      tenantID,
		"name":           clientName,
		"redirect_uris":  []string{"http://localhost:3000/callback"},
		"allowed_grants": []string{"authorization_code", "client_credentials"},
		"allowed_scopes": []string{"openid", "profile", "email"},
		"public_client":  true,
	}
	return s.tc.POSTWithHeaders("/admin/clients", body, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *adminSteps) createClientWithRedirectURI(ctx context.Context, redirectURI string) error {
	tenantID := s.tc.GetTenantID()
	if tenantID == "" {
		return fmt.Errorf("tenant ID not set")
	}
	body := map[string]interface{}{
		"tenant_id":      tenantID,
		"name":           "Redirect URI Test Client",
		"redirect_uris":  []string{redirectURI},
		"allowed_grants": []string{"authorization_code", "refresh_token"},
		"allowed_scopes": []string{"openid", "profile", "email"},
		"public_client":  false,
	}
	return s.tc.POSTWithHeaders("/admin/clients", body, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

// Auth tests without admin token

func (s *adminSteps) reactivateTenantWithoutAdminToken(ctx context.Context) error {
	tenantID := s.tc.GetTenantID()
	if tenantID == "" {
		return fmt.Errorf("tenant ID not set")
	}
	return s.tc.POSTWithHeaders("/admin/tenants/"+tenantID+"/reactivate", nil, map[string]string{
		"X-Admin-Token": "", // Empty token
	})
}

func (s *adminSteps) reactivateClientWithoutAdminToken(ctx context.Context) error {
	clientID := s.tc.GetTestClientID()
	if clientID == "" {
		return fmt.Errorf("client ID not set")
	}
	return s.tc.POSTWithHeaders("/admin/clients/"+clientID+"/reactivate", nil, map[string]string{
		"X-Admin-Token": "", // Empty token
	})
}

func (s *adminSteps) getTenantDetailsWithoutAdminToken(ctx context.Context) error {
	tenantID := s.tc.GetTenantID()
	if tenantID == "" {
		return fmt.Errorf("tenant ID not set")
	}
	return s.tc.GET("/admin/tenants/"+tenantID, map[string]string{
		"X-Admin-Token": "", // Empty token
	})
}

func (s *adminSteps) getClientDetailsWithoutAdminToken(ctx context.Context) error {
	clientID := s.tc.GetTestClientID()
	if clientID == "" {
		return fmt.Errorf("client ID not set")
	}
	return s.tc.GET("/admin/clients/"+clientID, map[string]string{
		"X-Admin-Token": "", // Empty token
	})
}

func (s *adminSteps) updateClientNameWithoutAdminToken(ctx context.Context, newName string) error {
	clientID := s.tc.GetTestClientID()
	if clientID == "" {
		return fmt.Errorf("client ID not set")
	}
	body := map[string]interface{}{
		"name": newName,
	}
	return s.tc.PUTWithHeaders("/admin/clients/"+clientID, body, map[string]string{
		"X-Admin-Token": "", // Empty token
	})
}

func (s *adminSteps) rotateClientSecretWithoutAdminToken(ctx context.Context) error {
	clientID := s.tc.GetTestClientID()
	if clientID == "" {
		return fmt.Errorf("client ID not set")
	}
	body := map[string]interface{}{
		"rotate_secret": true,
	}
	return s.tc.PUTWithHeaders("/admin/clients/"+clientID, body, map[string]string{
		"X-Admin-Token": "", // Empty token
	})
}

// Update validation steps

func (s *adminSteps) updateClientWithRedirectURI(ctx context.Context, redirectURI string) error {
	clientID := s.tc.GetTestClientID()
	if clientID == "" {
		return fmt.Errorf("client ID not set")
	}
	body := map[string]interface{}{
		"redirect_uris": []string{redirectURI},
	}
	return s.tc.PUTWithHeaders("/admin/clients/"+clientID, body, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *adminSteps) updateClientWithClientCredentialsGrant(ctx context.Context) error {
	clientID := s.tc.GetTestClientID()
	if clientID == "" {
		return fmt.Errorf("client ID not set")
	}
	body := map[string]interface{}{
		"allowed_grants": []string{"authorization_code", "client_credentials"},
	}
	return s.tc.PUTWithHeaders("/admin/clients/"+clientID, body, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

// Secret rotation validation

func (s *adminSteps) authenticateWithOldClientSecret(ctx context.Context) error {
	oauthClientID := s.tc.GetOAuthClientID()
	oldSecret := s.tc.GetClientSecret()
	if oauthClientID == "" {
		return fmt.Errorf("OAuth client_id not set")
	}
	if oldSecret == "" {
		return fmt.Errorf("old client secret not set")
	}
	// Attempt token exchange with old credentials
	body := map[string]interface{}{
		"grant_type":    "client_credentials",
		"client_id":     oauthClientID,
		"client_secret": oldSecret,
		"scope":         "openid",
	}
	return s.tc.POST("/oauth/token", body)
}

func (s *adminSteps) authenticationShouldFail(ctx context.Context) error {
	status := s.tc.GetLastResponseStatus()
	if status >= 200 && status < 300 {
		return fmt.Errorf("expected authentication to fail, but got status %d", status)
	}
	return nil
}

// Name length boundary tests

func (s *adminSteps) createTenantWithExactLength(ctx context.Context, length int) error {
	// Generate a unique name of exactly the specified length
	// Use a timestamp-based prefix and pad with 'x' characters
	uniquePrefix := fmt.Sprintf("T%d", time.Now().UnixNano())
	name := generateStringOfLength(uniquePrefix, length)
	body := map[string]interface{}{
		"name": name,
	}
	return s.tc.POSTWithHeaders("/admin/tenants", body, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *adminSteps) createClientWithExactLength(ctx context.Context, length int) error {
	tenantID := s.tc.GetTenantID()
	if tenantID == "" {
		return fmt.Errorf("tenant ID not set")
	}
	// Generate a unique client name of exactly the specified length
	uniquePrefix := fmt.Sprintf("C%d", time.Now().UnixNano())
	name := generateStringOfLength(uniquePrefix, length)
	body := map[string]interface{}{
		"tenant_id":      tenantID,
		"name":           name,
		"redirect_uris":  []string{"http://localhost:3000/callback"},
		"allowed_grants": []string{"authorization_code", "refresh_token"},
		"allowed_scopes": []string{"openid", "profile", "email"},
		"public_client":  false,
	}
	return s.tc.POSTWithHeaders("/admin/clients", body, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

// generateStringOfLength creates a string of exactly the specified length
func generateStringOfLength(prefix string, length int) string {
	if length <= 0 {
		return ""
	}
	if len(prefix) >= length {
		return prefix[:length]
	}
	// Pad with 'x' characters to reach exact length
	padding := length - len(prefix)
	result := prefix
	for i := 0; i < padding; i++ {
		result += "x"
	}
	return result
}
