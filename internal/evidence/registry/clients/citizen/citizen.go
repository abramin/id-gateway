package citizen

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"credo/internal/evidence/registry/models"
)

// Client is a real HTTP client that calls an external citizen registry API
type Client struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
	Timeout time.Duration
}

type httpCitizenRequest struct {
	NationalID string `json:"national_id"`
}

type httpCitizenResponse struct {
	NationalID  string `json:"national_id"`
	FullName    string `json:"full_name"`
	DateOfBirth string `json:"date_of_birth"`
	Address     string `json:"address"`
	Valid       bool   `json:"valid"`
	CheckedAt   string `json:"checked_at"`
}

type httpErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// NewClient creates a new HTTP client for the citizen registry
func NewClient(baseURL, apiKey string, timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Client: &http.Client{
			Timeout: timeout,
		},
		Timeout: timeout,
	}
}

// Lookup performs a citizen lookup via HTTP API call
func (c *Client) Lookup(ctx context.Context, nationalID string) (*models.CitizenRecord, error) {
	// Prepare request body
	reqBody := httpCitizenRequest{
		NationalID: nationalID,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/api/v1/citizen/lookup", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.APIKey)

	// Execute request
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for error responses
	if resp.StatusCode != http.StatusOK {
		var errResp httpErrorResponse
		if err := json.Unmarshal(respBodyBytes, &errResp); err == nil {
			return nil, fmt.Errorf("registry error (%d): %s - %s", resp.StatusCode, errResp.Error, errResp.Message)
		}
		return nil, fmt.Errorf("registry error: status %d", resp.StatusCode)
	}

	// Parse success response
	var httpResp httpCitizenResponse
	if err := json.Unmarshal(respBodyBytes, &httpResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Convert to domain model
	record := &models.CitizenRecord{
		NationalID:  httpResp.NationalID,
		FullName:    httpResp.FullName,
		DateOfBirth: httpResp.DateOfBirth,
		Valid:       httpResp.Valid,
	}

	return record, nil
}
