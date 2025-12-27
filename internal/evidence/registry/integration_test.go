package registry_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/suite"

	"credo/internal/evidence/registry/store"
	auditstore "credo/pkg/platform/audit/store/memory"
	authmw "credo/pkg/platform/middleware/auth"
)

type RegistryIntegrationSuite struct {
	suite.Suite
	logger     *slog.Logger
	auditStore *auditstore.InMemoryStore
	cacheStore *store.InMemoryCache
	router     *chi.Mux
	server     *httptest.Server
}

func (s *RegistryIntegrationSuite) SetupTest() {
	// Setup logger
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	// Setup audit store
	s.auditStore = auditstore.NewInMemoryStore()

	// Setup cache store
	s.cacheStore = store.NewInMemoryCache(5 * time.Minute)

	// TODO: Initialize orchestrator and service
	// registry := providers.NewProviderRegistry()
	// citizenProv := citizen.New(...)
	// sanctionsProv := sanctions.New(...)
	// registry.Register(citizenProv)
	// registry.Register(sanctionsProv)
	// orch := orchestrator.NewOrchestrator(...)
	// svc := registryService.New(orch, cache, false)
	// s.handler = handler.New(svc, consentAdapter, auditPort, s.logger)

	// Parse typed IDs for context injection (simulating auth middleware)
	testUserID, _ := id.ParseUserID("550e8400-e29b-41d4-a716-446655440001")
	testSessionID, _ := id.ParseSessionID("550e8400-e29b-41d4-a716-446655440002")
	testClientID, _ := id.ParseClientID("550e8400-e29b-41d4-a716-446655440003")

	// Setup router with middleware
	s.router = chi.NewRouter()
	s.router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Inject test user context
			ctx := context.WithValue(r.Context(), authmw.ContextKeyUserID, testUserID)
			ctx = context.WithValue(ctx, authmw.ContextKeySessionID, testSessionID)
			ctx = context.WithValue(ctx, authmw.ContextKeyClientID, testClientID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// TODO: Register handler routes when handler is implemented
	// s.handler.Register(s.router)

	// Create test server
	s.server = httptest.NewServer(s.router)
}

func (s *RegistryIntegrationSuite) TearDownTest() {
	if s.server != nil {
		s.server.Close()
	}
}

func TestRegistryIntegrationSuite(t *testing.T) {
	suite.Run(t, new(RegistryIntegrationSuite))
}

func (s *RegistryIntegrationSuite) TestFullRegistryFlow() {
	s.T().Run("complete registry check flow with cache and audit", func(t *testing.T) {
		// TODO: Implement full flow integration test
		// See docs for test plan
		t.Skip("Not implemented - full integration test stub")
	})
}
