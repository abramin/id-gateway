package contract

import (
	"context"
	"testing"

	"credo/internal/evidence/registry/providers"
)

// ContractTest defines a test case for provider contract validation
type ContractTest struct {
	Name         string
	Provider     providers.Provider
	Input        map[string]string
	ExpectedType providers.ProviderType
	ValidateFunc func(evidence *providers.Evidence) error
}

// ContractSuite is a collection of contract tests for a provider
type ContractSuite struct {
	ProviderID      string
	ProviderVersion string
	Tests           []ContractTest
}

// Run executes all contract tests in the suite
func (s *ContractSuite) Run(t *testing.T) {
	for _, test := range s.Tests {
		t.Run(test.Name, func(t *testing.T) {
			ctx := context.Background()

			// Execute lookup
			evidence, err := test.Provider.Lookup(ctx, test.Input)
			if err != nil {
				t.Fatalf("provider lookup failed: %v", err)
			}

			// Validate provider ID matches
			if evidence.ProviderID != s.ProviderID {
				t.Errorf("expected provider ID %s, got %s", s.ProviderID, evidence.ProviderID)
			}

			// Validate provider type
			if evidence.ProviderType != test.ExpectedType {
				t.Errorf("expected type %s, got %s", test.ExpectedType, evidence.ProviderType)
			}

			// Validate confidence is in valid range
			if evidence.Confidence < 0 || evidence.Confidence > 1.0 {
				t.Errorf("confidence %f out of range [0, 1]", evidence.Confidence)
			}

			// Validate CheckedAt is set
			if evidence.CheckedAt.IsZero() {
				t.Error("CheckedAt not set")
			}

			// Run custom validation
			if test.ValidateFunc != nil {
				if err := test.ValidateFunc(evidence); err != nil {
					t.Errorf("custom validation failed: %v", err)
				}
			}
		})
	}
}

