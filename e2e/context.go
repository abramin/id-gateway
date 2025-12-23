package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// TestContext holds state between test steps
type TestContext struct {
	BaseURL              string
	AdminBaseURL         string
	HTTPClient           *http.Client
	LastResponse         *http.Response
	LastResponseBody     []byte
	AuthCode             string
	AccessToken          string
	IDToken              string
	RefreshToken         string
	PreviousRefreshToken string
	State                string
	ClientID             string
	RedirectURI          string
	UserID               string
	AdminToken           string
	TenantID             string
	TestClientID         string // UUID of client for admin API tests
	ClientSecret         string // Saved client secret for rotation tests
	AccessTokens         map[string]string
	RefreshTokens        map[string]string
	SessionIDs           map[string]string
}

// NewTestContext creates a new test context
func NewTestContext() *TestContext {
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	adminBaseURL := os.Getenv("ADMIN_BASE_URL")
	if adminBaseURL == "" {
		adminBaseURL = "http://localhost:8081"
	}

	adminToken := os.Getenv("ADMIN_API_TOKEN")
	if adminToken == "" {
		adminToken = "demo-admin-token"
	}

	return &TestContext{
		BaseURL:       baseURL,
		AdminBaseURL:  adminBaseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ClientID:      "", // Will be set by EnsureTestClient
		RedirectURI:   "http://localhost:3000/callback",
		AdminToken:    adminToken,
		AccessTokens:  make(map[string]string),
		RefreshTokens: make(map[string]string),
		SessionIDs:    make(map[string]string),
	}
}

// POST makes a POST request and stores the response
func (tc *TestContext) POST(path string, body interface{}) error {
	return tc.POSTWithHeaders(path, body, nil)
}

// POSTWithHeaders makes a POST request with optional headers
func (tc *TestContext) POSTWithHeaders(path string, body interface{}, headers map[string]string) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", tc.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := tc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}

	tc.LastResponse = resp
	tc.LastResponseBody, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	return nil
}

// GET makes a GET request and stores the response
func (tc *TestContext) GET(path string, headers map[string]string) error {
	req, err := http.NewRequestWithContext(context.Background(), "GET", tc.BaseURL+path, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := tc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}

	tc.LastResponse = resp
	tc.LastResponseBody, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	return nil
}

// DELETE makes a DELETE request and stores the response
func (tc *TestContext) DELETE(path string, headers map[string]string) error {
	req, err := http.NewRequestWithContext(context.Background(), "DELETE", tc.BaseURL+path, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := tc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}

	tc.LastResponse = resp
	tc.LastResponseBody, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	return nil
}

// PUT makes a PUT request with optional headers
func (tc *TestContext) PUT(path string, body interface{}) error {
	return tc.PUTWithHeaders(path, body, nil)
}

// PUTWithHeaders makes a PUT request with optional headers
func (tc *TestContext) PUTWithHeaders(path string, body interface{}, headers map[string]string) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "PUT", tc.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := tc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}

	tc.LastResponse = resp
	tc.LastResponseBody, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	return nil
}

// GetResponseField extracts a field from the JSON response
func (tc *TestContext) GetResponseField(field string) (interface{}, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(tc.LastResponseBody, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	value, ok := data[field]
	if !ok {
		return nil, fmt.Errorf("field %s not found in response", field)
	}

	return value, nil
}

// ResponseContains checks if the response body contains a field or text
func (tc *TestContext) ResponseContains(text string) bool {
	if strings.Contains(string(tc.LastResponseBody), text) {
		return true
	}

	var data map[string]interface{}
	if err := json.Unmarshal(tc.LastResponseBody, &data); err == nil {
		if _, ok := data[text]; ok {
			return true
		}
	}

	return false
}

// Getter methods for step package interfaces

func (tc *TestContext) GetClientID() string {
	return tc.ClientID
}

func (tc *TestContext) GetRedirectURI() string {
	return tc.RedirectURI
}

func (tc *TestContext) GetAuthCode() string {
	return tc.AuthCode
}

func (tc *TestContext) SetAuthCode(code string) {
	tc.AuthCode = code
}

func (tc *TestContext) GetAccessToken() string {
	return tc.AccessToken
}

func (tc *TestContext) SetAccessToken(token string) {
	tc.AccessToken = token
	tc.SetAccessTokenFor("default", token)
}

func (tc *TestContext) GetLastResponseStatus() int {
	if tc.LastResponse == nil {
		return 0
	}
	return tc.LastResponse.StatusCode
}

func (tc *TestContext) GetLastResponseBody() []byte {
	return tc.LastResponseBody
}

func (tc *TestContext) GetLastResponse() *http.Response {
	return tc.LastResponse
}

func (tc *TestContext) GetResponseHeader(header string) string {
	if tc.LastResponse == nil {
		return ""
	}
	return tc.LastResponse.Header.Get(header)
}

func (tc *TestContext) GetUserID() string {
	return tc.UserID
}

func (tc *TestContext) SetUserID(userID string) {
	tc.UserID = userID
}

func (tc *TestContext) GetAdminToken() string {
	return tc.AdminToken
}

func (tc *TestContext) GetRefreshToken() string {
	return tc.RefreshToken
}

func (tc *TestContext) GetPreviousRefreshToken() string {
	return tc.PreviousRefreshToken
}

func (tc *TestContext) SetPreviousRefreshToken(token string) {
	tc.PreviousRefreshToken = token
}

func (tc *TestContext) SetRefreshToken(token string) {
	if tc.RefreshToken != "" && token != tc.RefreshToken {
		tc.PreviousRefreshToken = tc.RefreshToken
	}
	tc.RefreshToken = token
	tc.SetRefreshTokenFor("default", token)
}

func (tc *TestContext) SetAccessTokenFor(name, token string) {
	if tc.AccessTokens == nil {
		tc.AccessTokens = make(map[string]string)
	}
	tc.AccessTokens[name] = token
}

func (tc *TestContext) GetAccessTokenFor(name string) string {
	return tc.AccessTokens[name]
}

func (tc *TestContext) SetRefreshTokenFor(name, token string) {
	if tc.RefreshTokens == nil {
		tc.RefreshTokens = make(map[string]string)
	}
	tc.RefreshTokens[name] = token
}

func (tc *TestContext) GetRefreshTokenFor(name string) string {
	return tc.RefreshTokens[name]
}

func (tc *TestContext) SetSessionIDFor(name, id string) {
	if tc.SessionIDs == nil {
		tc.SessionIDs = make(map[string]string)
	}
	tc.SessionIDs[name] = id
}

func (tc *TestContext) GetSessionIDFor(name string) string {
	return tc.SessionIDs[name]
}

func (tc *TestContext) GetBaseURL() string {
	return tc.BaseURL
}

func (tc *TestContext) GetHTTPClient() *http.Client {
	return tc.HTTPClient
}

func (tc *TestContext) GetTenantID() string {
	return tc.TenantID
}

func (tc *TestContext) SetTenantID(tenantID string) {
	tc.TenantID = tenantID
}

func (tc *TestContext) GetTestClientID() string {
	return tc.TestClientID
}

func (tc *TestContext) SetTestClientID(clientID string) {
	tc.TestClientID = clientID
}

func (tc *TestContext) GetClientSecret() string {
	return tc.ClientSecret
}

func (tc *TestContext) SetClientSecret(secret string) {
	tc.ClientSecret = secret
}

// EnsureTestClient creates a tenant and client via the admin API if not already set up.
// This should be called once before running tests.
// Uses a unique identifier per test run to avoid conflicts with stale data.
func (tc *TestContext) EnsureTestClient() error {
	if tc.ClientID != "" {
		return nil // Already set up
	}

	// Use a unique tenant name per test run to avoid conflicts
	runID := time.Now().UnixNano()
	tenantName := fmt.Sprintf("e2e-test-tenant-%d", runID)

	// Step 1: Create a tenant
	tenantReq := map[string]interface{}{
		"name": tenantName,
	}
	tenantData, err := json.Marshal(tenantReq)
	if err != nil {
		return fmt.Errorf("failed to marshal tenant request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", tc.BaseURL+"/admin/tenants", bytes.NewReader(tenantData))
	if err != nil {
		return fmt.Errorf("failed to create tenant request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", tc.AdminToken)

	resp, err := tc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read tenant response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create tenant, status %d: %s", resp.StatusCode, string(body))
	}

	var tenantResp map[string]interface{}
	if err := json.Unmarshal(body, &tenantResp); err != nil {
		return fmt.Errorf("failed to parse tenant response: %w", err)
	}

	tenantID, ok := tenantResp["tenant_id"].(string)
	if !ok {
		return fmt.Errorf("tenant_id not found in response: %s", string(body))
	}
	tc.TenantID = tenantID

	// Step 2: Create a client under the tenant
	clientReq := map[string]interface{}{
		"tenant_id":      tenantID,
		"name":           "E2E Test Client",
		"redirect_uris":  []string{"http://localhost:3000/callback"},
		"allowed_grants": []string{"authorization_code", "refresh_token"},
		"allowed_scopes": []string{"openid", "profile", "email"},
		"public_client":  true,
	}
	clientData, err := json.Marshal(clientReq)
	if err != nil {
		return fmt.Errorf("failed to marshal client request: %w", err)
	}

	req, err = http.NewRequestWithContext(context.Background(), "POST", tc.BaseURL+"/admin/clients", bytes.NewReader(clientData))
	if err != nil {
		return fmt.Errorf("failed to create client request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", tc.AdminToken)

	resp, err = tc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read client response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create client, status %d: %s", resp.StatusCode, string(body))
	}

	var clientResp map[string]interface{}
	if err := json.Unmarshal(body, &clientResp); err != nil {
		return fmt.Errorf("failed to parse client response: %w", err)
	}

	clientID, ok := clientResp["client_id"].(string)
	if !ok {
		return fmt.Errorf("client_id not found in response: %s", string(body))
	}
	tc.ClientID = clientID

	return nil
}
