package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"credo/internal/audit"
	authHandler "credo/internal/auth/handler"
	authService "credo/internal/auth/service"
	authCodeStore "credo/internal/auth/store/authorization-code"
	refreshTokenStore "credo/internal/auth/store/refresh-token"
	sessionStore "credo/internal/auth/store/session"
	userStore "credo/internal/auth/store/user"
	consentHandler "credo/internal/consent/handler"
	consentService "credo/internal/consent/service"
	consentStore "credo/internal/consent/store"
	jwttoken "credo/internal/jwt_token"
	"credo/internal/platform/config"
	"credo/internal/platform/httpserver"
	"credo/internal/platform/logger"
	"credo/internal/platform/metrics"
	"credo/internal/platform/middleware"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		panic(err)
	}
	log := logger.New()

	log.Info("initializing credo",
		"addr", cfg.Addr,
		"regulated_mode", cfg.RegulatedMode,
		"env", cfg.Environment,
		"allowed_redirect_schemes", cfg.AllowedRedirectSchemes,
	)
	if cfg.DemoMode {
		log.Info("CRENE_ENV=demo — starting isolated demo environment",
			"stores", "in-memory",
			"issuer", cfg.JWTIssuer,
		)
	}

	m := metrics.New()
	jwtService, jwtValidator := initializeJWTService(&cfg)
	authSvc := initializeAuthService(m, log, jwtService, &cfg)

	r := setupRouter(log, m)
	registerRoutes(r, authSvc, jwtValidator, log, &cfg, m)

	srv := httpserver.New(cfg.Addr, r)
	startServer(srv, log)
	waitForShutdown(srv, log)
}

// initializeAuthService creates and configures the authentication service
func initializeAuthService(m *metrics.Metrics, log *slog.Logger, jwtService *jwttoken.JWTService, cfg *config.Server) *authService.Service {
	authCfg := authService.Config{
		SessionTTL:             cfg.SessionTTL,
		TokenTTL:               cfg.TokenTTL,
		AllowedRedirectSchemes: cfg.AllowedRedirectSchemes,
		DeviceBindingEnabled:   cfg.DeviceBindingEnabled,
	}

	authSvc, err := authService.New(
		userStore.NewInMemoryUserStore(),
		sessionStore.NewInMemorySessionStore(),
		authCodeStore.NewInMemoryAuthorizationCodeStore(),
		refreshTokenStore.NewInMemoryRefreshTokenStore(),
		authCfg,
		authService.WithMetrics(m),
		authService.WithLogger(log),
		authService.WithJWTService(jwtService),
	)
	if err != nil {
		log.Error("failed to initialize auth service", "error", err)
		os.Exit(1)
	}
	return authSvc
}

// initializeJWTService creates and configures the JWT service and validator
func initializeJWTService(cfg *config.Server) (*jwttoken.JWTService, *jwttoken.JWTServiceAdapter) {
	jwtService := jwttoken.NewJWTService(
		cfg.JWTSigningKey,
		cfg.JWTIssuer,
		"credo-client",
		cfg.TokenTTL,
	)
	if cfg.DemoMode {
		jwtService.SetEnv("demo")
	}
	jwtValidator := jwttoken.NewJWTServiceAdapter(jwtService)
	return jwtService, jwtValidator
}

// setupRouter creates a new router and configures common middleware
func setupRouter(log *slog.Logger, m *metrics.Metrics) *chi.Mux {
	r := chi.NewRouter()

	// Common middleware for all routes (must be defined before routes)
	r.Use(middleware.ClientMetadata)
	r.Use(middleware.Recovery(log))
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger(log))
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.ContentTypeJSON)
	r.Use(middleware.LatencyMiddleware(m))

	// Add Prometheus metrics endpoint (no auth required)
	r.Handle("/metrics", promhttp.Handler())
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

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
	authHandler := authHandler.New(authSvc, log)
	consentSvc := consentService.NewService(
		consentStore.NewInMemoryStore(),
		audit.NewPublisher(audit.NewInMemoryStore()),
		log,
		consentService.WithConsentTTL(cfg.ConsentTTL),
		consentService.WithGrantWindow(cfg.ConsentGrantWindow),
	)
	consentHTTPHandler := consentHandler.New(consentSvc, log, m)
	if cfg.DemoMode {
		r.Get("/demo/info", func(w http.ResponseWriter, _ *http.Request) {
			resp := map[string]any{
				"env":        "demo",
				"users":      []string{"alice", "bob", "charlie"},
				"jwt_issuer": cfg.JWTIssuer,
				"data_store": "in-memory",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
	}

	// Public auth endpoints (no JWT required)
	r.Post("/auth/authorize", authHandler.HandleAuthorize)
	r.Post("/auth/token", authHandler.HandleToken)

	// Protected auth endpoints (JWT required)
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth(jwtValidator, log))
		r.Get("/auth/userinfo", authHandler.HandleUserInfo)
		consentHTTPHandler.Register(r)
	})

	if cfg.AdminAPIToken != "" {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdminToken(cfg.AdminAPIToken, log))
			authHandler.RegisterAdmin(r)
		})
	}
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
