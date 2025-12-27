package sanctions

import (
	"encoding/json"
	"fmt"
	"time"

	"credo/internal/evidence/registry/providers"
	"credo/internal/evidence/registry/providers/adapters"
	"credo/internal/evidence/registry/tracer"
)

// sanctionsHTTPResponse represents the response from a sanctions registry API
type sanctionsHTTPResponse struct {
	NationalID string `json:"national_id"`
	Listed     bool   `json:"listed"`
	Source     string `json:"source"`
	CheckedAt  string `json:"checked_at"`
}

func New(id, baseURL, apiKey string, timeout time.Duration) providers.Provider {
	return adapters.New(adapters.HTTPAdapterConfig{
		ID:      id,
		BaseURL: baseURL,
		APIKey:  apiKey,
		Timeout: timeout,
		Capabilities: providers.Capabilities{
			Protocol: providers.ProtocolHTTP,
			Type:     providers.ProviderTypeSanctions,
			Fields: []providers.FieldCapability{
				{FieldName: "listed", Available: true, Filterable: false},
				{FieldName: "source", Available: true, Filterable: false},
			},
			Version: "v1.0.0",
			Filters: []string{"national_id"},
		},
		Parser: parseSanctionsResponse,
	})
}

// NewWithTracer creates a sanctions provider with distributed tracing enabled.
func NewWithTracer(id, baseURL, apiKey string, timeout time.Duration, t tracer.Tracer) providers.Provider {
	return adapters.New(adapters.HTTPAdapterConfig{
		ID:      id,
		BaseURL: baseURL,
		APIKey:  apiKey,
		Timeout: timeout,
		Tracer:  t,
		Capabilities: providers.Capabilities{
			Protocol: providers.ProtocolHTTP,
			Type:     providers.ProviderTypeSanctions,
			Fields: []providers.FieldCapability{
				{FieldName: "listed", Available: true, Filterable: false},
				{FieldName: "source", Available: true, Filterable: false},
			},
			Version: "v1.0.0",
			Filters: []string{"national_id"},
		},
		Parser: parseSanctionsResponse,
	})
}

// parseSanctionsResponse converts HTTP response to Evidence
func parseSanctionsResponse(statusCode int, body []byte) (*providers.Evidence, error) {
	if statusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", statusCode)
	}

	var resp sanctionsHTTPResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sanctions response: %w", err)
	}

	// Parse timestamp from response. If parsing fails, leave zero and let the
	// adapter set it from context (maintains domain purity - no time.Now() here).
	checkedAt, _ := time.Parse(time.RFC3339, resp.CheckedAt)

	// Convert to generic Evidence structure
	evidence := &providers.Evidence{
		ProviderType: providers.ProviderTypeSanctions,
		Confidence:   1.0, // Full confidence from authoritative source
		Data: map[string]interface{}{
			"national_id": resp.NationalID,
			"listed":      resp.Listed,
			"source":      resp.Source,
		},
		CheckedAt: checkedAt,
		Metadata:  make(map[string]string),
	}

	return evidence, nil
}
