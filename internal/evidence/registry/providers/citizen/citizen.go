package citizen

import (
	"encoding/json"
	"fmt"
	"time"

	"credo/internal/evidence/registry/providers"
	"credo/internal/evidence/registry/providers/adapters"
	"credo/internal/evidence/registry/tracer"
)

// citizenHTTPResponse represents the response from a citizen registry API
type citizenHTTPResponse struct {
	NationalID  string `json:"national_id"`
	FullName    string `json:"full_name"`
	DateOfBirth string `json:"date_of_birth"`
	Address     string `json:"address"`
	Valid       bool   `json:"valid"`
	CheckedAt   string `json:"checked_at"`
}

func New(id, baseURL, apiKey string, timeout time.Duration) providers.Provider {
	return NewWithClient(id, baseURL, apiKey, timeout, nil)
}

// NewWithTracer creates a citizen provider with distributed tracing enabled.
func NewWithTracer(id, baseURL, apiKey string, timeout time.Duration, t tracer.Tracer) providers.Provider {
	return adapters.New(adapters.HTTPAdapterConfig{
		ID:         id,
		BaseURL:    baseURL,
		APIKey:     apiKey,
		Timeout:    timeout,
		Tracer:     t,
		Capabilities: providers.Capabilities{
			Protocol: providers.ProtocolHTTP,
			Type:     providers.ProviderTypeCitizen,
			Fields: []providers.FieldCapability{
				{FieldName: "full_name", Available: true, Filterable: false},
				{FieldName: "date_of_birth", Available: true, Filterable: false},
				{FieldName: "address", Available: true, Filterable: false},
				{FieldName: "valid", Available: true, Filterable: false},
			},
			Version: "v1.0.0",
			Filters: []string{"national_id"},
		},
		Parser: parseCitizenResponse,
	})
}

// NewWithClient allows injecting a custom HTTP client (for testing).
func NewWithClient(
	id, baseURL, apiKey string,
	timeout time.Duration,
	client adapters.HTTPDoer,
) providers.Provider {
	return adapters.New(adapters.HTTPAdapterConfig{
		ID:         id,
		BaseURL:    baseURL,
		APIKey:     apiKey,
		Timeout:    timeout,
		HTTPClient: client,
		Capabilities: providers.Capabilities{
			Protocol: providers.ProtocolHTTP,
			Type:     providers.ProviderTypeCitizen,
			Fields: []providers.FieldCapability{
				{FieldName: "full_name", Available: true, Filterable: false},
				{FieldName: "date_of_birth", Available: true, Filterable: false},
				{FieldName: "address", Available: true, Filterable: false},
				{FieldName: "valid", Available: true, Filterable: false},
			},
			Version: "v1.0.0",
			Filters: []string{"national_id"},
		},
		Parser: parseCitizenResponse,
	})
}

// parseCitizenResponse converts HTTP response to Evidence
func parseCitizenResponse(statusCode int, body []byte) (*providers.Evidence, error) {
	if statusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", statusCode)
	}

	var resp citizenHTTPResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal citizen response: %w", err)
	}

	// Parse timestamp from response. If parsing fails, leave zero and let the
	// adapter set it from context (maintains domain purity - no time.Now() here).
	checkedAt, _ := time.Parse(time.RFC3339, resp.CheckedAt)

	// Convert to generic Evidence structure
	evidence := &providers.Evidence{
		ProviderType: providers.ProviderTypeCitizen,
		Confidence:   1.0, // Full confidence from authoritative source
		Data: map[string]interface{}{
			"national_id":   resp.NationalID,
			"full_name":     resp.FullName,
			"date_of_birth": resp.DateOfBirth,
			"address":       resp.Address,
			"valid":         resp.Valid,
		},
		CheckedAt: checkedAt,
		Metadata:  make(map[string]string),
	}

	return evidence, nil
}
