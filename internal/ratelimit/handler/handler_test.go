package handler

//go:generate mockgen -source=handler.go -destination=mocks/handler_mock.go -package=mocks Service,QuotaService

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"credo/internal/ratelimit/handler/mocks"
	"credo/internal/ratelimit/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// =============================================================================
// Handler Test Suite
// =============================================================================
// Justification: These tests validate request parsing at the HTTP boundary.
// They ensure malformed JSON is rejected with 400 before reaching service layer.
// Full request→service→response flows are covered by E2E feature tests in
// e2e/features/ratelimit.feature (@admin, @allowlist scenarios).
// These tests may be removed once E2E step definitions are fully implemented.

type HandlerSuite struct {
	suite.Suite
	router           http.Handler
	ctrl             *gomock.Controller
	mockService      *mocks.MockService
	mockQuotaService *mocks.MockQuotaService
}

func (s *HandlerSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.mockService = mocks.NewMockService(s.ctrl)
	s.mockQuotaService = mocks.NewMockQuotaService(s.ctrl)
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	h := New(s.mockService, logger).WithQuotaService(s.mockQuotaService)

	r := chi.NewRouter()
	h.RegisterAdmin(r)
	s.router = r
}

func (s *HandlerSuite) TearDownTest() {
	s.ctrl.Finish()
}

func TestHandlerSuite(t *testing.T) {
	suite.Run(t, new(HandlerSuite))
}

func (s *HandlerSuite) TestAddAllowlist_InvalidJSON() {
	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/allowlist",
		bytes.NewReader([]byte("not valid json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)

	assert.Equal(s.T(), http.StatusBadRequest, rec.Code,
		"expected 400 for invalid JSON")
}

func (s *HandlerSuite) TestRemoveAllowlist_InvalidJSON() {
	req := httptest.NewRequest(http.MethodDelete, "/admin/rate-limit/allowlist",
		bytes.NewReader([]byte("not valid json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)

	assert.Equal(s.T(), http.StatusBadRequest, rec.Code,
		"expected 400 for invalid JSON")
}

func (s *HandlerSuite) TestResetRateLimit_InvalidJSON() {
	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/reset",
		bytes.NewReader([]byte("not valid json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)

	assert.Equal(s.T(), http.StatusBadRequest, rec.Code,
		"expected 400 for invalid JSON")
}

// =============================================================================
// Quota API Endpoint Tests (PRD-017 FR-5)
// =============================================================================
// These tests verify the quota API endpoints per PRD-017 FR-5.

func (s *HandlerSuite) TestGetQuotaUsage_ReturnsUsage() {
	apiKeyID := id.APIKeyID("partner-free-123")
	mockQuota := &models.APIKeyQuota{
		APIKeyID:     apiKeyID,
		Tier:         models.QuotaTierFree,
		MonthlyLimit: 1000,
		CurrentUsage: 250,
		PeriodEnd:    time.Now().AddDate(0, 1, 0),
	}

	s.mockQuotaService.EXPECT().Check(gomock.Any(), apiKeyID).Return(mockQuota, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/quota/partner-free-123", nil)
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)

	assert.Equal(s.T(), http.StatusOK, rec.Code,
		"GET /admin/rate-limit/quota/:api_key should return 200")
	assert.Contains(s.T(), rec.Body.String(), "usage",
		"response should contain usage field")
	assert.Contains(s.T(), rec.Body.String(), "limit",
		"response should contain limit field")
	assert.Contains(s.T(), rec.Body.String(), "tier",
		"response should contain tier field")
}

func (s *HandlerSuite) TestGetQuotaUsage_NotFound() {
	apiKeyID := id.APIKeyID("nonexistent-key")

	s.mockQuotaService.EXPECT().Check(gomock.Any(), apiKeyID).Return(nil,
		dErrors.New(dErrors.CodeNotFound, "quota not found"))

	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/quota/nonexistent-key", nil)
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)

	assert.Equal(s.T(), http.StatusNotFound, rec.Code,
		"GET /admin/rate-limit/quota/:api_key should return 404 for unknown key")
}

func (s *HandlerSuite) TestResetQuota_Success() {
	apiKeyID := id.APIKeyID("partner-free-123")

	s.mockQuotaService.EXPECT().Reset(gomock.Any(), apiKeyID).Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/quota/partner-free-123/reset",
		bytes.NewReader([]byte(`{"reason": "Customer support request"}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)

	assert.Equal(s.T(), http.StatusOK, rec.Code,
		"POST /admin/rate-limit/quota/:api_key/reset should return 200")
}

func (s *HandlerSuite) TestListQuotas_ReturnsList() {
	mockQuotas := []*models.APIKeyQuota{
		{
			APIKeyID:     id.APIKeyID("key-1"),
			Tier:         models.QuotaTierFree,
			MonthlyLimit: 1000,
			CurrentUsage: 100,
			PeriodEnd:    time.Now().AddDate(0, 1, 0),
		},
		{
			APIKeyID:     id.APIKeyID("key-2"),
			Tier:         models.QuotaTierStarter,
			MonthlyLimit: 10000,
			CurrentUsage: 5000,
			PeriodEnd:    time.Now().AddDate(0, 1, 0),
		},
	}

	s.mockQuotaService.EXPECT().List(gomock.Any()).Return(mockQuotas, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/rate-limit/quotas", nil)
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)

	assert.Equal(s.T(), http.StatusOK, rec.Code,
		"GET /admin/rate-limit/quotas should return 200")
	assert.Contains(s.T(), rec.Body.String(), "[",
		"response should be a JSON array")
}

func (s *HandlerSuite) TestUpdateQuotaTier_Success() {
	apiKeyID := id.APIKeyID("partner-free-123")

	s.mockQuotaService.EXPECT().UpdateTier(gomock.Any(), apiKeyID, models.QuotaTierStarter).Return(nil)

	req := httptest.NewRequest(http.MethodPut, "/admin/rate-limit/quota/partner-free-123/tier",
		bytes.NewReader([]byte(`{"tier": "starter"}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)

	assert.Equal(s.T(), http.StatusOK, rec.Code,
		"PUT /admin/rate-limit/quota/:api_key/tier should return 200")
}
