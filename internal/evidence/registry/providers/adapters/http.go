package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"credo/internal/evidence/registry/providers"
)

// HTTPAdapter wraps HTTP-based registry providers
type HTTPAdapter struct {
	id      string
	baseURL string
	apiKey  string
	client  HTTPDoer
	timeout time.Duration
	capabs  providers.Capabilities
	parser  ResponseParser
}

// TODO: revisit this
// HTTPDoer is the minimal interface needed from an HTTP client.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// ResponseParser converts HTTP responses to Evidence
type ResponseParser func(statusCode int, body []byte) (*providers.Evidence, error)

// HTTPAdapterConfig configures an HTTP adapter
type HTTPAdapterConfig struct {
	ID           string
	BaseURL      string
	APIKey       string
	Timeout      time.Duration
	HTTPClient   HTTPDoer
	Capabilities providers.Capabilities
	Parser       ResponseParser
}

// NewHTTPAdapter creates a new HTTP protocol adapter
func NewHTTPAdapter(cfg HTTPAdapterConfig) *HTTPAdapter {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	return &HTTPAdapter{
		id:      cfg.ID,
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		client:  selectHTTPClient(cfg),
		timeout: cfg.Timeout,
		capabs:  cfg.Capabilities,
		parser:  cfg.Parser,
	}
}

func selectHTTPClient(cfg HTTPAdapterConfig) HTTPDoer {
	if cfg.HTTPClient != nil {
		return cfg.HTTPClient
	}

	return &http.Client{
		Timeout: cfg.Timeout,
	}
}

// ID returns the provider identifier
func (a *HTTPAdapter) ID() string {
	return a.id
}

// Capabilities returns what this provider supports
func (a *HTTPAdapter) Capabilities() providers.Capabilities {
	return a.capabs
}

// Lookup performs an evidence check via HTTP
func (a *HTTPAdapter) Lookup(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
	// Build request body from filters
	bodyBytes, err := json.Marshal(filters)
	if err != nil {
		return nil, providers.NewProviderError(
			providers.ErrorBadData,
			a.id,
			"failed to marshal request",
			err,
		)
	}

	// Create HTTP request with context
	url := fmt.Sprintf("%s/lookup", a.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, providers.NewProviderError(
			providers.ErrorInternal,
			a.id,
			"failed to create request",
			err,
		)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		req.Header.Set("X-API-Key", a.apiKey)
	}

	// Execute request
	resp, err := a.client.Do(req)
	if err != nil {
		// Classify error type
		if ctx.Err() == context.DeadlineExceeded {
			return nil, providers.NewProviderError(
				providers.ErrorTimeout,
				a.id,
				"request timeout",
				err,
			)
		}
		return nil, providers.NewProviderError(
			providers.ErrorProviderOutage,
			a.id,
			"failed to execute request",
			err,
		)
	}
	defer resp.Body.Close()

	// Read response body
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, providers.NewProviderError(
			providers.ErrorBadData,
			a.id,
			"failed to read response",
			err,
		)
	}

	// Handle error status codes
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, providers.NewProviderError(
			providers.ErrorAuthentication,
			a.id,
			fmt.Sprintf("authentication failed: %d", resp.StatusCode),
			nil,
		)
	case http.StatusNotFound:
		return nil, providers.NewProviderError(
			providers.ErrorNotFound,
			a.id,
			"record not found",
			nil,
		)
	case http.StatusTooManyRequests:
		return nil, providers.NewProviderError(
			providers.ErrorRateLimited,
			a.id,
			"rate limit exceeded",
			nil,
		)
	case http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return nil, providers.NewProviderError(
			providers.ErrorProviderOutage,
			a.id,
			fmt.Sprintf("provider unavailable: %d", resp.StatusCode),
			nil,
		)
	}

	// Use custom parser to convert response to Evidence
	evidence, err := a.parser(resp.StatusCode, respBodyBytes)
	if err != nil {
		return nil, providers.NewProviderError(
			providers.ErrorBadData,
			a.id,
			"failed to parse response",
			err,
		)
	}

	// Enrich evidence with provider metadata
	if evidence.Metadata == nil {
		evidence.Metadata = make(map[string]string)
	}
	evidence.ProviderID = a.id
	evidence.ProviderType = a.capabs.Type
	evidence.CheckedAt = time.Now()

	return evidence, nil
}

// Health checks if the provider is available
func (a *HTTPAdapter) Health(ctx context.Context) error {
	url := fmt.Sprintf("%s/health", a.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	if a.apiKey != "" {
		req.Header.Set("X-API-Key", a.apiKey)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return providers.NewProviderError(
			providers.ErrorProviderOutage,
			a.id,
			"health check failed",
			err,
		)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return providers.NewProviderError(
			providers.ErrorProviderOutage,
			a.id,
			fmt.Sprintf("unhealthy status: %d", resp.StatusCode),
			nil,
		)
	}

	return nil
}
