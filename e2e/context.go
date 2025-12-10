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
	BaseURL          string
	HTTPClient       *http.Client
	LastResponse     *http.Response
	LastResponseBody []byte
	AuthCode         string
	AccessToken      string
	IDToken          string
	State            string
	ClientID         string
	RedirectURI      string
}

// NewTestContext creates a new test context
func NewTestContext() *TestContext {
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	return &TestContext{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ClientID:    "test-client",
		RedirectURI: "http://localhost:3000/callback",
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
