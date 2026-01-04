package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"credo/internal/evidence/registry/providers"
	"credo/pkg/requestcontext"
)

// Tracer for distributed tracing of outbound HTTP calls.
var adapterTracer = otel.Tracer("credo/registry/adapter")

// MaxResponseSize is the maximum allowed response body size from registry providers.
// This prevents memory exhaustion from malicious or misconfigured providers.
const MaxResponseSize = 10 * 1024 * 1024 // 10MB

// HTTPAdapter wraps HTTP-based registry providers implementing the Provider interface.
//
// This adapter handles the common HTTP concerns (request building, error mapping, response parsing)
// while delegating protocol-specific parsing to a configurable ResponseParser function.
// It maps HTTP status codes to normalized ProviderError categories for consistent error handling.
//
// Emits spans for outbound HTTP calls with the span name based on the provider type
// (e.g., registry.citizen.call, registry.sanctions.call).
type HTTPAdapter struct {
	id      string
	baseURL string
	apiKey  string
	client  HTTPDoer
	timeout time.Duration
	capabs  providers.Capabilities
	parser  ResponseParser
}

// HTTPDoer is the minimal interface needed from an HTTP client.
// This abstraction allows injecting mock clients for testing without depending on the full http.Client.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// ResponseParser converts HTTP responses to Evidence.
// Each provider type (citizen, sanctions) supplies its own parser that understands the API response format.
// The parser should populate Evidence.Data with provider-specific fields; the adapter enriches the rest.
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

// New creates a new HTTP protocol adapter
func New(cfg HTTPAdapterConfig) *HTTPAdapter {
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

// Lookup performs an evidence check via HTTP POST to {baseURL}/lookup.
//
// The method:
//  1. Marshals filters to JSON and sends as POST body
//  2. Maps HTTP status codes to ProviderError categories (401/403→auth, 404→not found, 429→rate limited, 503→outage)
//  3. Parses successful responses using the configured ResponseParser
//  4. Enriches the evidence with ProviderID, ProviderType, and CheckedAt timestamp
//
// When a tracer is configured, emits a span for the outbound call (e.g., registry.citizen.call).
func (a *HTTPAdapter) Lookup(ctx context.Context, filters map[string]string) (evidence *providers.Evidence, err error) {
	// Start span for outbound call if tracer is configured
	ctx, span := a.startSpan(ctx)
	defer func() { a.endSpan(span, err) }()

	req, err := a.buildRequest(ctx, filters)
	if err != nil {
		return nil, err
	}

	resp, body, err := a.executeRequest(ctx, req) //nolint:bodyclose // executeRequest closes body internally
	if err != nil {
		return nil, err
	}

	if err = a.checkStatusCode(resp.StatusCode); err != nil {
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
// Uses io.LimitReader to prevent memory exhaustion from oversized responses.
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
	defer resp.Body.Close() //nolint:errcheck // best-effort cleanup

	// Limit response size to prevent memory exhaustion from malicious providers
	limitedReader := io.LimitReader(resp.Body, MaxResponseSize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, nil, providers.NewProviderError(
			providers.ErrorBadData,
			a.id,
			"failed to read response",
			err,
		)
	}

	// Check if response exceeded the limit (we read MaxResponseSize+1 to detect overflow)
	if int64(len(body)) > MaxResponseSize {
		return nil, nil, providers.NewProviderError(
			providers.ErrorBadData,
			a.id,
			fmt.Sprintf("response too large: exceeds %d bytes", MaxResponseSize),
			nil,
		)
	}

	return resp, body, nil
}

// checkStatusCode maps HTTP status codes to ProviderError categories.
//
// Status code mapping:
//   - 401, 403 → ErrorAuthentication (not retryable)
//   - 404 → ErrorNotFound (not retryable)
//   - 429 → ErrorRateLimited (retryable)
//   - 503, 504 → ErrorProviderOutage (retryable)
//   - 2xx → nil (success, handled by caller)
//   - Other → nil (passed to parser for handling)
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
		evidence.CheckedAt = requestcontext.Now(ctx)
	}

	return evidence, nil
}

// Health checks if the provider is available by making a GET request to {baseURL}/health.
// Returns nil if the endpoint responds with 200 OK, ProviderError otherwise.
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
	defer resp.Body.Close() //nolint:errcheck // best-effort cleanup

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

// -----------------------------------------------------------------------------
// Tracing helpers
// -----------------------------------------------------------------------------

// spanName returns the appropriate span name based on the provider type.
func (a *HTTPAdapter) spanName() string {
	switch a.capabs.Type {
	case providers.ProviderTypeCitizen:
		return "registry.citizen.call"
	case providers.ProviderTypeSanctions:
		return "registry.sanctions.call"
	default:
		return "registry.provider.call"
	}
}

// startSpan starts a new span for the outbound HTTP call.
func (a *HTTPAdapter) startSpan(ctx context.Context) (context.Context, trace.Span) {
	return adapterTracer.Start(ctx, a.spanName(),
		trace.WithAttributes(
			attribute.String("provider.id", a.id),
			attribute.String("provider.type", string(a.capabs.Type)),
			attribute.String("provider.base_url", a.baseURL),
		),
	)
}

// endSpan ends a span and records any error.
func (a *HTTPAdapter) endSpan(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
}
