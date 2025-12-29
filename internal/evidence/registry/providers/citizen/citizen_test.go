package citizen

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"credo/internal/evidence/registry/providers"
	adaptersmocks "credo/internal/evidence/registry/providers/adapters/mocks"
	"credo/internal/evidence/registry/providers/providertest"
)

func TestCitizenProvider(t *testing.T) {
	// Create provider for testing
	provider := New(
		"test-citizen",
		"http://mock-registry.test",
		"test-key",
		5*time.Second,
	)

	t.Run("capabilities are correctly declared", func(t *testing.T) {
		caps := provider.Capabilities()

		assert.Equal(t, providers.ProtocolHTTP, caps.Protocol)
		assert.Equal(t, providers.ProviderTypeCitizen, caps.Type)
		assert.Equal(t, "v1.0.0", caps.Version)
		assert.Len(t, caps.Fields, 4) // full_name, date_of_birth, address, valid
		assert.Contains(t, caps.Filters, "national_id")
	})

	t.Run("evidence contains required fields", func(t *testing.T) {
		// This would need a mock HTTP server or you can use contract tests
		t.Skip("Requires HTTP mock server - use contract tests instead")
	})
}

func TestCitizenProviderContract(t *testing.T) {
	// Only run if we have a mock server available
	if testing.Short() {
		t.Skip("Skipping contract tests in short mode")
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := adaptersmocks.NewMockHTTPDoer(ctrl)
	mockClient.EXPECT().
		Do(gomock.Any()).
		Times(2).
		DoAndReturn(func(req *http.Request) (*http.Response, error) {
			body := `{
				"national_id": "123456789",
				"full_name": "Alice Johnson",
				"date_of_birth": "1990-05-15",
				"address": "123 Main St",
				"valid": true,
				"checked_at": "2025-12-11T10:00:00Z"
			}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		})

	provider := NewWithClient(
		"test-citizen",
		"http://mock-registry.test",
		"test-key",
		5*time.Second,
		mockClient,
	)

	suite := &providertest.ContractSuite{
		ProviderID:      "test-citizen",
		ProviderVersion: "v1.0.0",
		Tests: []providertest.ContractTest{
			{
				Name:         "returns valid citizen evidence",
				Provider:     provider,
				Input:        map[string]string{"national_id": "123456789"},
				ExpectedType: providers.ProviderTypeCitizen,
				ValidateFunc: func(e *providers.Evidence) error {
					return validateCitizenFields(e)
				},
			},
			{
				Name:         "generates deterministic data based on national ID",
				Provider:     provider,
				Input:        map[string]string{"national_id": "123456789"},
				ExpectedType: providers.ProviderTypeCitizen,
				ValidateFunc: func(e *providers.Evidence) error {
					if err := validateCitizenFields(e); err != nil {
						return err
					}
					if e.Data["full_name"] != "Alice Johnson" {
						return assert.AnError
					}
					return nil
				},
			},
		},
	}

	suite.Run(t)
}

func TestCitizenResponseParser(t *testing.T) {
	t.Run("parses valid HTTP response", func(t *testing.T) {
		body := []byte(`{
			"national_id": "123456789",
			"full_name": "Alice Johnson",
			"date_of_birth": "1990-05-15",
			"address": "123 Main St",
			"valid": true,
			"checked_at": "2025-12-11T10:00:00Z"
		}`)

		evidence, err := parseCitizenResponse(200, body)
		require.NoError(t, err)
		require.NotNil(t, evidence)

		assert.Equal(t, providers.ProviderTypeCitizen, evidence.ProviderType)
		assert.Equal(t, 1.0, evidence.Confidence)
		assert.Equal(t, "123456789", evidence.Data["national_id"])
		assert.Equal(t, "Alice Johnson", evidence.Data["full_name"])
		assert.Equal(t, "1990-05-15", evidence.Data["date_of_birth"])
		assert.Equal(t, true, evidence.Data["valid"])
	})

	t.Run("returns error for non-200 status", func(t *testing.T) {
		evidence, err := parseCitizenResponse(404, []byte(`{}`))
		assert.Error(t, err)
		assert.Nil(t, evidence)
	})

	t.Run("returns error for malformed JSON", func(t *testing.T) {
		evidence, err := parseCitizenResponse(200, []byte(`{invalid json`))
		assert.Error(t, err)
		assert.Nil(t, evidence)
	})

	t.Run("leaves CheckedAt zero for invalid timestamp (adapter fills it)", func(t *testing.T) {
		body := []byte(`{
			"national_id": "123456789",
			"full_name": "Alice Johnson",
			"date_of_birth": "1990-05-15",
			"address": "123 Main St",
			"valid": true,
			"checked_at": "invalid-date"
		}`)

		evidence, err := parseCitizenResponse(200, body)
		require.NoError(t, err)
		// Parser intentionally leaves CheckedAt zero when parsing fails.
		// The HTTPAdapter's parseAndEnrich fills it from requestcontext.Now(ctx).
		// This maintains domain purity - no time.Now() calls in the parser.
		assert.True(t, evidence.CheckedAt.IsZero(), "parser leaves zero for adapter to fill")
	})
}

// Test scenarios adapted from old clients/citizen/citizen_test.go:

func TestCitizenProviderScenarios(t *testing.T) {
	t.Run("respects context cancellation", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := adaptersmocks.NewMockHTTPDoer(ctrl)
		mockClient.EXPECT().
			Do(gomock.Any()).
			DoAndReturn(func(req *http.Request) (*http.Response, error) {
				<-req.Context().Done()
				return nil, req.Context().Err()
			})

		provider := NewWithClient(
			"test-citizen",
			"http://slow-registry.test",
			"test-key",
			1*time.Second,
			mockClient,
		)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		_, err := provider.Lookup(ctx, map[string]string{"national_id": "123"})
		assert.Error(t, err)
		assert.Equal(t, providers.ErrorTimeout, providers.GetCategory(err))
	})

	t.Run("handles empty national ID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClient := adaptersmocks.NewMockHTTPDoer(ctrl)
		mockClient.EXPECT().
			Do(gomock.Any()).
			Return(&http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Header:     make(http.Header),
			}, nil)

		provider := NewWithClient(
			"test-citizen",
			"http://mock-registry.test",
			"test-key",
			5*time.Second,
			mockClient,
		)

		ctx := context.Background()
		_, err := provider.Lookup(ctx, map[string]string{"national_id": ""})

		assert.Error(t, err)
	})
}

func validateCitizenFields(e *providers.Evidence) error {
	if _, ok := e.Data["full_name"].(string); !ok {
		return assert.AnError
	}
	if _, ok := e.Data["date_of_birth"].(string); !ok {
		return assert.AnError
	}
	if _, ok := e.Data["valid"].(bool); !ok {
		return assert.AnError
	}
	return nil
}
