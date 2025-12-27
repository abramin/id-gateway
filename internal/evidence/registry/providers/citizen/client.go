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
	"credo/internal/evidence/registry/providers"
	"credo/internal/evidence/registry/service"
)

// HTTPClient implements service.CitizenClient by calling an external HTTP registry service.
type HTTPClient struct {
	baseURL    string
	apiKey     string
	timeout    time.Duration
	httpClient *http.Client
}

// Ensure HTTPClient implements CitizenClient
var _ service.CitizenClient = (*HTTPClient)(nil)

// HTTPClientOption configures the HTTPClient.
type HTTPClientOption func(*HTTPClient)

// WithHTTPClient sets a custom HTTP client (for testing).
func WithHTTPClient(client *http.Client) HTTPClientOption {
	return func(c *HTTPClient) {
		c.httpClient = client
	}
}

// NewHTTPClient creates a new HTTP-based citizen client.
func NewHTTPClient(baseURL, apiKey string, timeout time.Duration, opts ...HTTPClientOption) *HTTPClient {
	c := &HTTPClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		timeout: timeout,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// citizenRequest represents the request body for citizen lookup.
type citizenRequest struct {
	NationalID string `json:"national_id"`
}

// citizenResponse represents the response from the citizen registry service.
type citizenResponse struct {
	NationalID  string `json:"national_id"`
	FullName    string `json:"full_name"`
	DateOfBirth string `json:"date_of_birth"`
	Address     string `json:"address"`
	Valid       bool   `json:"valid"`
	CheckedAt   string `json:"checked_at"`
}

// errorResponse represents an error response from the registry service.
type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// Lookup performs a citizen registry lookup by national ID.
func (c *HTTPClient) Lookup(ctx context.Context, nationalID string) (*models.CitizenRecord, error) {
	// Create request body
	reqBody, err := json.Marshal(citizenRequest{NationalID: nationalID})
	if err != nil {
		return nil, providers.NewProviderError(
			providers.ErrorInternal,
			"citizen-http",
			"failed to marshal request",
			err,
		)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/api/v1/citizen/lookup", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, providers.NewProviderError(
			providers.ErrorInternal,
			"citizen-http",
			"failed to create request",
			err,
		)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Check for context deadline exceeded (timeout)
		if ctx.Err() == context.DeadlineExceeded {
			return nil, providers.NewProviderError(
				providers.ErrorTimeout,
				"citizen-http",
				"request timeout",
				err,
			)
		}
		return nil, providers.NewProviderError(
			providers.ErrorProviderOutage,
			"citizen-http",
			"failed to execute request",
			err,
		)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, providers.NewProviderError(
			providers.ErrorInternal,
			"citizen-http",
			"failed to read response body",
			err,
		)
	}

	// Handle error responses
	switch resp.StatusCode {
	case http.StatusOK:
		// Success - continue to parse
	case http.StatusUnauthorized:
		return nil, providers.NewProviderError(
			providers.ErrorAuthentication,
			"citizen-http",
			"authentication failed",
			nil,
		)
	case http.StatusBadRequest:
		var errResp errorResponse
		if json.Unmarshal(body, &errResp) == nil {
			return nil, providers.NewProviderError(
				providers.ErrorBadData,
				"citizen-http",
				errResp.Message,
				nil,
			)
		}
		return nil, providers.NewProviderError(
			providers.ErrorBadData,
			"citizen-http",
			"bad request",
			nil,
		)
	case http.StatusNotFound:
		return nil, providers.NewProviderError(
			providers.ErrorNotFound,
			"citizen-http",
			"citizen not found",
			nil,
		)
	case http.StatusTooManyRequests:
		return nil, providers.NewProviderError(
			providers.ErrorRateLimited,
			"citizen-http",
			"rate limited",
			nil,
		)
	case http.StatusServiceUnavailable:
		return nil, providers.NewProviderError(
			providers.ErrorProviderOutage,
			"citizen-http",
			"service unavailable",
			nil,
		)
	default:
		return nil, providers.NewProviderError(
			providers.ErrorInternal,
			"citizen-http",
			fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
			nil,
		)
	}

	// Parse successful response
	var citizenResp citizenResponse
	if err := json.Unmarshal(body, &citizenResp); err != nil {
		return nil, providers.NewProviderError(
			providers.ErrorContractMismatch,
			"citizen-http",
			"failed to parse response",
			err,
		)
	}

	// Parse checked_at timestamp
	checkedAt, err := time.Parse(time.RFC3339, citizenResp.CheckedAt)
	if err != nil {
		checkedAt = time.Now()
	}

	return &models.CitizenRecord{
		NationalID:  citizenResp.NationalID,
		FullName:    citizenResp.FullName,
		DateOfBirth: citizenResp.DateOfBirth,
		Address:     citizenResp.Address,
		Valid:       citizenResp.Valid,
		CheckedAt:   checkedAt,
	}, nil
}
