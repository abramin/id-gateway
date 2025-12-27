package providers

import (
	"context"
	"fmt"
	"time"
)

// Protocol defines the supported communication protocols for registry providers
type Protocol string

const (
	ProtocolHTTP Protocol = "http"
	ProtocolSOAP Protocol = "soap"
	ProtocolGRPC Protocol = "grpc"
)

// ProviderType identifies the kind of evidence a provider can produce
type ProviderType string

const (
	ProviderTypeCitizen   ProviderType = "citizen"
	ProviderTypeSanctions ProviderType = "sanctions"
	ProviderTypeBiometric ProviderType = "biometric"
	ProviderTypeDocument  ProviderType = "document"
	ProviderTypeWallet    ProviderType = "wallet" // Digital ID wallet
)

// FieldCapability advertises which fields a provider exposes
type FieldCapability struct {
	FieldName  string // e.g., "full_name", "date_of_birth", "address"
	Available  bool
	Filterable bool // Whether this field can be used in queries
}

// Capabilities describes what a provider supports
type Capabilities struct {
	Protocol Protocol
	Type     ProviderType
	Fields   []FieldCapability
	Version  string   // Provider API version
	Filters  []string // Supported filter types: "national_id", "passport", "email"
}

// Evidence is the generic result from any registry provider lookup.
//
// All providers produce Evidence records with a common structure, allowing the orchestrator
// to work with heterogeneous sources uniformly. The Data field contains provider-specific
// key-value pairs that must be interpreted based on ProviderType.
type Evidence struct {
	ProviderID   string // Which provider produced this
	ProviderType ProviderType
	Confidence   float64                // 0.0-1.0 confidence score (1.0 = authoritative source)
	Data         map[string]interface{} // Provider-specific structured data
	CheckedAt    time.Time
	Metadata     map[string]string // Provider metadata, trace IDs, correlation IDs, etc.
}

// Provider is the universal interface all registry sources must implement.
//
// Implementations wrap external registry APIs (citizen registries, sanctions lists, etc.)
// behind a common interface. This allows the orchestrator to work with heterogeneous
// sources without coupling to their specific protocols or data formats.
type Provider interface {
	// ID returns a unique identifier for this provider instance (e.g., "gov-citizen-registry-v1").
	ID() string

	// Capabilities returns what this provider supports including protocol, evidence type,
	// available fields, and supported filters.
	Capabilities() Capabilities

	// Lookup performs an evidence check using the provider.
	// The filters map should contain at least one supported filter (e.g., {"national_id": "..."}).
	// Returns a ProviderError on failure with normalized error categories for retry decisions.
	Lookup(ctx context.Context, filters map[string]string) (*Evidence, error)

	// Health checks if the provider is available and responding.
	// Returns nil if healthy, error otherwise. Used by orchestrator health checks.
	Health(ctx context.Context) error
}

// ProviderRegistry maintains all registered providers indexed by their unique ID.
//
// The registry is the central lookup point for the orchestrator to find providers
// by ID or filter by type. Providers must be registered before the orchestrator starts.
// Note: This implementation is not thread-safe; register all providers during initialization.
type ProviderRegistry struct {
	providers map[string]Provider
}

func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]Provider),
	}
}

// Register adds a provider to the registry, keyed by its ID.
// Returns an error if a provider with the same ID is already registered.
func (r *ProviderRegistry) Register(p Provider) error {
	id := p.ID()
	if _, exists := r.providers[id]; exists {
		return fmt.Errorf("provider %s already registered", id)
	}
	r.providers[id] = p
	return nil
}

func (r *ProviderRegistry) Get(id string) (Provider, bool) {
	p, ok := r.providers[id]
	return p, ok
}

// ListByType returns all providers that produce the specified evidence type.
// Used by the orchestrator to find all citizen or sanctions providers for parallel queries.
func (r *ProviderRegistry) ListByType(t ProviderType) []Provider {
	var result []Provider
	for _, p := range r.providers {
		if p.Capabilities().Type == t {
			result = append(result, p)
		}
	}
	return result
}

func (r *ProviderRegistry) All() []Provider {
	result := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		result = append(result, p)
	}
	return result
}
