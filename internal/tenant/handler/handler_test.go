package handler

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"credo/internal/tenant/service"
	clientstore "credo/internal/tenant/store/client"
	tenantstore "credo/internal/tenant/store/tenant"
	adminmw "credo/pkg/platform/middleware/admin"
)

const adminToken = "secret-token"

type HandlerSuite struct {
	suite.Suite
	router http.Handler
}

func (s *HandlerSuite) SetupTest() {
	tenants := tenantstore.NewInMemory()
	clients := clientstore.NewInMemory()
	svc, err := service.New(tenants, clients, nil)
	s.Require().NoError(err)
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	h := New(svc, logger)
	r := chi.NewRouter()
	r.Use(adminmw.RequireAdminToken(adminToken, logger))
	h.Register(r)
	s.router = r
}

func TestHandlerSuite(t *testing.T) {
	suite.Run(t, new(HandlerSuite))
}

// TestAdminTokenRequired verifies middleware wiring - admin endpoints reject
// requests without valid admin token. This validates handler-to-middleware
// integration that E2E tests also cover, but kept here to catch wiring regressions
// in isolation without spinning up the full server.
func (s *HandlerSuite) TestAdminTokenRequired() {
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+uuid.New().String(), nil)
	// No admin token header set
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	s.Equal(http.StatusUnauthorized, rec.Code, "expected 401 when admin token missing")
}
