package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"id-gateway/internal/audit"
	authHandler "id-gateway/internal/auth/handler"
	authService "id-gateway/internal/auth/service"
	authStore "id-gateway/internal/auth/store"
	consentHandler "id-gateway/internal/consent/handler"
	consentService "id-gateway/internal/consent/service"
	consentStore "id-gateway/internal/consent/store"
	jwttoken "id-gateway/internal/jwt_token"
	"id-gateway/internal/platform/config"
	"id-gateway/internal/platform/httpserver"
	"id-gateway/internal/platform/logger"
	"id-gateway/internal/platform/metrics"
	"id-gateway/internal/platform/middleware"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	cfg := config.FromEnv()
	log := logger.New()

	log.Info("initializing id-gateway",
		"addr", cfg.Addr,
		"regulated_mode", cfg.RegulatedMode,
	)

	m := metrics.New()
	jwtService, jwtValidator := initializeJWTService(&cfg)
	authSvc := initializeAuthService(m, log, jwtService)

	r := setupRouter(log, m)
	registerRoutes(r, authSvc, jwtValidator, log, &cfg, m)

	srv := httpserver.New(cfg.Addr, r)
	startServer(srv, log)
	waitForShutdown(srv, log)
}

// initializeAuthService creates and configures the authentication service
func initializeAuthService(m *metrics.Metrics, log *slog.Logger, jwtService *jwttoken.JWTService) *authService.Service {
	return authService.NewService(
		authStore.NewInMemoryUserStore(),
		authStore.NewInMemorySessionStore(),
		24*time.Hour, // TODO Make configurable
		authService.WithMetrics(m),
		authService.WithLogger(log),
		authService.WithJWTService(jwtService),
	)
}

// initializeJWTService creates and configures the JWT service and validator
func initializeJWTService(cfg *config.Server) (*jwttoken.JWTService, *jwttoken.JWTServiceAdapter) {
	jwtService := jwttoken.NewJWTService(
		cfg.JWTSigningKey,
		"id-gateway",
		"id-gateway-client",
		cfg.TokenTTL,
	)
	jwtValidator := jwttoken.NewJWTServiceAdapter(jwtService)
	return jwtService, jwtValidator
}

// setupRouter creates a new router and configures common middleware
func setupRouter(log *slog.Logger, m *metrics.Metrics) *chi.Mux {
	r := chi.NewRouter()

	// Common middleware for all routes (must be defined before routes)
	r.Use(middleware.Recovery(log))
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger(log))
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.ContentTypeJSON)
	r.Use(middleware.LatencyMiddleware(m))

	// Add Prometheus metrics endpoint (no auth required)
	r.Handle("/metrics", promhttp.Handler())

	return r
}

// registerRoutes registers all application routes and handlers
func registerRoutes(
	r *chi.Mux,
	authSvc *authService.Service,
	jwtValidator *jwttoken.JWTServiceAdapter,
	log *slog.Logger,
	cfg *config.Server,
	m *metrics.Metrics,
) {
	authHandler := authHandler.New(authSvc, log, cfg.RegulatedMode, m)
	consentSvc := consentService.NewService(
		consentStore.NewInMemoryStore(),
		audit.NewPublisher(audit.NewInMemoryStore()),
	)
	consentHTTPHandler := consentHandler.New(consentSvc, log, m)

	// Public auth endpoints (no JWT required)
	r.Post("/auth/authorize", authHandler.HandleAuthorize)
	r.Post("/auth/token", authHandler.HandleToken)

	// Protected auth endpoints (JWT required)
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth(jwtValidator, log))
		r.Get("/auth/userinfo", authHandler.HandleUserInfo)
		consentHTTPHandler.Register(r)
	})
}

// startServer starts the HTTP server in a goroutine
func startServer(srv *http.Server, log *slog.Logger) {
	log.Info("starting http server", "addr", srv.Addr)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "error", err)
			os.Exit(1)
		}
	}()
}

// waitForShutdown waits for an interrupt signal and gracefully shuts down the server
func waitForShutdown(srv *http.Server, log *slog.Logger) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	log.Info("shutting down server gracefully")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}

	log.Info("server stopped")
}
