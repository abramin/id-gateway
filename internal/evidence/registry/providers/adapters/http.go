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
	"credo/pkg/platform/middleware/requesttime"
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
	req, err := a.buildRequest(ctx, filters)
	if err != nil {
		return nil, err
	}

	resp, body, err := a.executeRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	if err := a.checkStatusCode(resp.StatusCode); err != nil {
		return nil, err
	}

	return a.parseAndEnrich(ctx, resp.StatusCode, body)
}

// buildRequest creates an HTTP request from filters.
func (a *HTTPAdapter) buildRequest(ctx context.Context, filters map[string]string) (*http.Request, error) {
	bodyBytes, err := json.Marshal(filters)
	if err != nil {
		return nil, providers.NewProviderError(
			providers.ErrorBadData,
			a.id,
			"failed to marshal request",
			err,
		)
	}

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

	req.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		req.Header.Set("X-API-Key", a.apiKey)
	}

	return req, nil
}

// executeRequest sends the HTTP request and returns the response with body.
func (a *HTTPAdapter) executeRequest(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
	resp, err := a.client.Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, nil, providers.NewProviderError(
				providers.ErrorTimeout,
				a.id,
				"request timeout",
				err,
			)
		}
		return nil, nil, providers.NewProviderError(
			providers.ErrorProviderOutage,
			a.id,
			"failed to execute request",
			err,
		)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, providers.NewProviderError(
			providers.ErrorBadData,
			a.id,
			"failed to read response",
			err,
		)
	}

	return resp, body, nil
}

// checkStatusCode maps HTTP status codes to provider errors.
func (a *HTTPAdapter) checkStatusCode(statusCode int) error {
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return providers.NewProviderError(
			providers.ErrorAuthentication,
			a.id,
			fmt.Sprintf("authentication failed: %d", statusCode),
			nil,
		)
	case http.StatusNotFound:
		return providers.NewProviderError(
			providers.ErrorNotFound,
			a.id,
			"record not found",
			nil,
		)
	case http.StatusTooManyRequests:
		return providers.NewProviderError(
			providers.ErrorRateLimited,
			a.id,
			"rate limit exceeded",
			nil,
		)
	case http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return providers.NewProviderError(
			providers.ErrorProviderOutage,
			a.id,
			fmt.Sprintf("provider unavailable: %d", statusCode),
			nil,
		)
	}
	return nil
}

// parseAndEnrich converts the response body to Evidence and adds provider metadata.
func (a *HTTPAdapter) parseAndEnrich(ctx context.Context, statusCode int, body []byte) (*providers.Evidence, error) {
	evidence, err := a.parser(statusCode, body)
	if err != nil {
		return nil, providers.NewProviderError(
			providers.ErrorBadData,
			a.id,
			"failed to parse response",
			err,
		)
	}

	if evidence.Metadata == nil {
		evidence.Metadata = make(map[string]string)
	}
	evidence.ProviderID = a.id
	evidence.ProviderType = a.capabs.Type
	if evidence.CheckedAt.IsZero() {
		evidence.CheckedAt = requesttime.Now(ctx)
	}

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
