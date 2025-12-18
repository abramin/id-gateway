package handler

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"credo/internal/platform/middleware"
	"credo/internal/tenant/service"
	clientstore "credo/internal/tenant/store/client"
	tenantstore "credo/internal/tenant/store/tenant"
)

const adminToken = "secret-token"

// HandlerSuite provides shared test setup for tenant handler tests.
type HandlerSuite struct {
	suite.Suite
	router http.Handler
}

func (s *HandlerSuite) SetupTest() {
	tenants := tenantstore.NewInMemory()
	clients := clientstore.NewInMemory()
	svc := service.New(tenants, clients, nil)
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	h := New(svc, logger)
	r := chi.NewRouter()
	r.Use(middleware.RequireAdminToken(adminToken, logger))
	h.Register(r)
	s.router = r
}

func TestHandlerSuite(t *testing.T) {
	suite.Run(t, new(HandlerSuite))
}

func (s *HandlerSuite) TestAdminTokenRequired() {
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+uuid.New().String(), nil)
	// No admin token header set
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	assert.Equal(s.T(), http.StatusForbidden, rec.Code, "expected 403 when admin token missing")
}

func (s *HandlerSuite) TestCreateTenantAndClientViaHandlers() {
	// Create tenant
	tenantPayload := map[string]string{"name": "Acme"}
	body, _ := json.Marshal(tenantPayload)
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", adminToken)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	require.Equal(s.T(), http.StatusCreated, rec.Code, "expected 201 creating tenant")

	var tenantResp struct {
		TenantID uuid.UUID `json:"tenant_id"`
	}
	err := json.NewDecoder(rec.Body).Decode(&tenantResp)
	require.NoError(s.T(), err, "failed to decode tenant response")
	assert.NotEqual(s.T(), uuid.Nil, tenantResp.TenantID, "expected tenant_id in response")

	// Create client
	clientPayload := map[string]any{
		"tenant_id":      tenantResp.TenantID,
		"name":           "Web",
		"redirect_uris":  []string{"https://app.example.com/callback"},
		"allowed_grants": []string{"authorization_code"},
		"allowed_scopes": []string{"openid"},
	}
	clientBody, _ := json.Marshal(clientPayload)
	clientReq := httptest.NewRequest(http.MethodPost, "/admin/clients", bytes.NewReader(clientBody))
	clientReq.Header.Set("Content-Type", "application/json")
	clientReq.Header.Set("X-Admin-Token", adminToken)
	clientRec := httptest.NewRecorder()
	s.router.ServeHTTP(clientRec, clientReq)

	require.Equal(s.T(), http.StatusCreated, clientRec.Code, "expected 201 creating client")

	var clientResp struct {
		ID           uuid.UUID `json:"id"`
		TenantID     uuid.UUID `json:"tenant_id"`
		ClientSecret string    `json:"client_secret"`
	}
	err = json.NewDecoder(clientRec.Body).Decode(&clientResp)
	require.NoError(s.T(), err, "failed to decode client response")
	assert.NotEqual(s.T(), uuid.Nil, clientResp.ID, "expected client id in response")
	assert.NotEmpty(s.T(), clientResp.ClientSecret, "expected client secret in response")
	assert.Equal(s.T(), tenantResp.TenantID, clientResp.TenantID, "expected client tenant_id to match created tenant")

	// Get tenant details
	tenantGetReq := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantResp.TenantID.String(), nil)
	tenantGetReq.Header.Set("X-Admin-Token", adminToken)
	tenantGetRec := httptest.NewRecorder()
	s.router.ServeHTTP(tenantGetRec, tenantGetReq)

	require.Equal(s.T(), http.StatusOK, tenantGetRec.Code, "expected 200 fetching tenant")

	var tenantDetails struct {
		ClientCount int `json:"client_count"`
		UserCount   int `json:"user_count"`
	}
	err = json.NewDecoder(tenantGetRec.Body).Decode(&tenantDetails)
	require.NoError(s.T(), err, "failed to decode tenant details")
	assert.Equal(s.T(), 1, tenantDetails.ClientCount, "expected client_count 1")
}
