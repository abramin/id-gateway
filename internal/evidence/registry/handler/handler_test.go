package handler

// Handler tests for registry module following Credo testing doctrine (AGENTS.md, testing.md).
//
// Per testing doctrine, these unit tests exist to verify:
// - HTTP status code mapping from domain errors (CodeUnauthorized -> 401, etc.)
// - Error response format consistency
// - Handler-level validation (request body parsing, national_id format)
//
// Happy-path behavior (200 OK responses) is tested via:
// - Primary: e2e/features/registry_flow.feature (Gherkin scenarios)

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"credo/internal/evidence/registry/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit/publishers/ops"
	auditmemory "credo/pkg/platform/audit/store/memory"
	"credo/pkg/requestcontext"
)

// =============================================================================
// Stub Implementations
// =============================================================================

type stubRegistryService struct {
	sanctionsFunc func(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.SanctionsRecord, error)
	citizenFunc   func(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.CitizenRecord, error)
}

func (s *stubRegistryService) Sanctions(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.SanctionsRecord, error) {
	if s.sanctionsFunc != nil {
		return s.sanctionsFunc(ctx, userID, nationalID)
	}
	return &models.SanctionsRecord{
		NationalID: nationalID.String(),
		Listed:     false,
		Source:     "Test Source",
		CheckedAt:  time.Now(),
	}, nil
}

func (s *stubRegistryService) Citizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.CitizenRecord, error) {
	if s.citizenFunc != nil {
		return s.citizenFunc(ctx, userID, nationalID)
	}
	return &models.CitizenRecord{
		NationalID: nationalID.String(),
		Valid:      true,
		CheckedAt:  time.Now(),
	}, nil
}

func (s *stubRegistryService) Check(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.RegistryResult, error) {
	return nil, nil
}

// newTestOpsPublisher creates an ops publisher with in-memory store for testing.
func newTestOpsPublisher() (*ops.Publisher, *auditmemory.InMemoryStore) {
	store := auditmemory.NewInMemoryStore()
	return ops.New(store, ops.WithSampleRate(1.0)), store
}

// =============================================================================
// Sanctions Lookup Tests - Error Mapping
// =============================================================================

func TestHandleSanctionsLookup_MissingUserContext(t *testing.T) {
	// Handler extracts user from context; if auth middleware ran but userID is missing,
	// this is an internal error (auth middleware malfunction), not an auth failure.
	handler := newTestRegistryHandler(nil, nil)

	body, _ := json.Marshal(map[string]string{"national_id": "TEST123456"})
	req := httptest.NewRequest(http.MethodPost, "/registry/sanctions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleSanctionsLookup(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assertErrorResponse(t, w, string(dErrors.CodeInternal))
}

func TestHandleSanctionsLookup_InvalidNationalIDFormat(t *testing.T) {
	tests := []struct {
		name       string
		nationalID string
	}{
		{"empty", ""},
		{"too short", "ABC"},
		{"invalid chars", "invalid!@#"},
		{"too long", "ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"},
		{"lowercase", "abcdef123456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := newTestRegistryHandler(nil, nil)
			req := newSanctionsRequest(t, tt.nationalID, validUserID())

			w := httptest.NewRecorder()
			handler.HandleSanctionsLookup(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			// Handler returns domain error with CodeBadRequest for invalid input
			assertErrorResponse(t, w, "bad_request")
		})
	}
}

func TestHandleSanctionsLookup_MissingConsent(t *testing.T) {
	// Consent is now checked atomically in the service layer to prevent TOCTOU.
	// The service returns the consent error, which the handler maps to 403.
	service := &stubRegistryService{
		sanctionsFunc: func(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.SanctionsRecord, error) {
			return nil, dErrors.New(dErrors.CodeMissingConsent, "consent required for purpose: registry_check")
		},
	}
	handler := newTestRegistryHandler(service, nil)

	req := newSanctionsRequest(t, "TEST123456", validUserID())
	w := httptest.NewRecorder()
	handler.HandleSanctionsLookup(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assertErrorResponse(t, w, string(dErrors.CodeMissingConsent))
}

func TestHandleSanctionsLookup_ServiceTimeout(t *testing.T) {
	service := &stubRegistryService{
		sanctionsFunc: func(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.SanctionsRecord, error) {
			return nil, dErrors.New(dErrors.CodeTimeout, "registry lookup timed out")
		},
	}
	handler := newTestRegistryHandler(service, nil)

	req := newSanctionsRequest(t, "TIMEOUT123", validUserID())
	w := httptest.NewRecorder()
	handler.HandleSanctionsLookup(w, req)

	assert.Equal(t, http.StatusGatewayTimeout, w.Code)
	// Timeout errors are mapped to "registry_timeout" in HTTP response
	assertErrorResponse(t, w, "registry_timeout")
}

func TestHandleSanctionsLookup_ServiceInternalError(t *testing.T) {
	service := &stubRegistryService{
		sanctionsFunc: func(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.SanctionsRecord, error) {
			return nil, dErrors.New(dErrors.CodeInternal, "storage system unavailable")
		},
	}
	handler := newTestRegistryHandler(service, nil)

	req := newSanctionsRequest(t, "ERROR12345", validUserID())
	w := httptest.NewRecorder()
	handler.HandleSanctionsLookup(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assertErrorResponse(t, w, string(dErrors.CodeInternal))
}

// =============================================================================
// Sanctions Lookup Tests - Audit Events
// =============================================================================

// Note: Audit event tests have moved to service_test.go since audit logic
// is now in the service layer per architectural guidelines.
// Handler tests focus on HTTP request/response mapping.

func TestHandleSanctionsLookup_ServiceAuditFailClosedForListed(t *testing.T) {
	// When the service returns an error due to audit failure for listed sanctions,
	// the handler maps it to 500 Internal Server Error.
	// The fail-closed logic is now in the service layer.
	service := &stubRegistryService{
		sanctionsFunc: func(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.SanctionsRecord, error) {
			// Service returns error when audit fails for listed sanctions
			return nil, dErrors.New(dErrors.CodeInternal, "unable to complete sanctions check")
		},
	}
	handler := newTestRegistryHandler(service, nil)

	req := newSanctionsRequest(t, "SANCT12345", validUserID())
	w := httptest.NewRecorder()
	handler.HandleSanctionsLookup(w, req)

	// Handler maps service error to 500
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assertErrorResponse(t, w, string(dErrors.CodeInternal))
}

func TestHandleSanctionsLookup_SuccessfulLookup(t *testing.T) {
	// Verifies that a successful sanctions lookup returns 200 OK.
	// Audit is handled internally by the service.
	service := &stubRegistryService{
		sanctionsFunc: func(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.SanctionsRecord, error) {
			return &models.SanctionsRecord{
				NationalID: nationalID.String(),
				Listed:     false,
				Source:     "Test DB",
				CheckedAt:  time.Now(),
			}, nil
		},
	}
	handler := newTestRegistryHandler(service, nil)

	req := newSanctionsRequest(t, "CLEAN12345", validUserID())
	w := httptest.NewRecorder()
	handler.HandleSanctionsLookup(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// =============================================================================
// Sanctions Lookup Tests - Response Format
// =============================================================================

func TestHandleSanctionsLookup_ResponseFormat(t *testing.T) {
	checkedAt := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	service := &stubRegistryService{
		sanctionsFunc: func(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.SanctionsRecord, error) {
			return &models.SanctionsRecord{
				NationalID: nationalID.String(),
				Listed:     true,
				Source:     "EU Sanctions List",
				CheckedAt:  checkedAt,
			}, nil
		},
	}
	opsPublisher, _ := newTestOpsPublisher()
	handler := newTestRegistryHandler(service, opsPublisher)

	req := newSanctionsRequest(t, "FORMAT1234", validUserID())
	w := httptest.NewRecorder()
	handler.HandleSanctionsLookup(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response SanctionsCheckResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

	assert.Equal(t, "FORMAT1234", response.NationalID)
	assert.True(t, response.Listed)
	assert.Equal(t, "EU Sanctions List", response.Source)
	assert.Equal(t, "2025-01-15T10:30:00Z", response.CheckedAt)
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestRegistryHandler(service RegistryService, opsPublisher *ops.Publisher) *Handler {
	if service == nil {
		service = &stubRegistryService{}
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(service, opsPublisher, logger)
}

func validUserID() id.UserID {
	userID, _ := id.ParseUserID("550e8400-e29b-41d4-a716-446655440000")
	return userID
}

func newSanctionsRequest(t *testing.T, nationalID string, userID id.UserID) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]string{"national_id": nationalID})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/registry/sanctions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := requestcontext.WithUserID(req.Context(), userID)
	return req.WithContext(ctx)
}

func assertErrorResponse(t *testing.T, w *httptest.ResponseRecorder, expectedCode string) {
	t.Helper()
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, expectedCode, resp["error"])
}
