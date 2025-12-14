package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"credo/internal/admin"
	"credo/internal/audit"
	authHandler "credo/internal/auth/handler"
	authService "credo/internal/auth/service"
	authCodeStore "credo/internal/auth/store/authorization-code"
	refreshTokenStore "credo/internal/auth/store/refresh-token"
	revocationStore "credo/internal/auth/store/revocation"
	sessionStore "credo/internal/auth/store/session"
	userStore "credo/internal/auth/store/user"
	cleanupWorker "credo/internal/auth/workers/cleanup"
	consentHandler "credo/internal/consent/handler"
	consentService "credo/internal/consent/service"
	consentStore "credo/internal/consent/store"
	jwttoken "credo/internal/jwt_token"
	"credo/internal/platform/config"
	"credo/internal/platform/httpserver"
	"credo/internal/platform/logger"
	"credo/internal/platform/metrics"
	"credo/internal/platform/middleware"
	"credo/internal/seeder"
	tenantHandler "credo/internal/tenant/handler"
	tenantService "credo/internal/tenant/service"
	tenantStore "credo/internal/tenant/store"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type infraBundle struct {
	Cfg          *config.Server
	Log          *slog.Logger
	Metrics      *metrics.Metrics
	JWTService   *jwttoken.JWTService
	JWTValidator *jwttoken.JWTServiceAdapter
}

type authModule struct {
	Service       *authService.Service
	Handler       *authHandler.Handler
	AdminSvc      *admin.Service
	Cleanup       *cleanupWorker.CleanupService
	Users         *userStore.InMemoryUserStore
	Sessions      *sessionStore.InMemorySessionStore
	Codes         *authCodeStore.InMemoryAuthorizationCodeStore
	RefreshTokens *refreshTokenStore.InMemoryRefreshTokenStore
	AuditStore    *audit.InMemoryStore
}

type consentModule struct {
	Service *consentService.Service
	Handler *consentHandler.Handler
}

type tenantModule struct {
	Service *tenantService.Service
	Handler *tenantHandler.Handler
	Tenants *tenantStore.InMemoryTenantStore
	Clients *tenantStore.InMemoryClientStore
}

func main() {
	infra, err := buildInfra()
	if err != nil {
		panic(err)
	}

	appCtx, cancelApp := context.WithCancel(context.Background())
	defer cancelApp()

	authMod, err := buildAuthModule(appCtx, infra)
	if err != nil {
		infra.Log.Error("failed to initialize auth module", "error", err)
		os.Exit(1)
	}
	consentMod := buildConsentModule(infra)
	tenantMod := buildTenantModule(infra)

	startCleanupWorker(appCtx, infra.Log, authMod.Cleanup)

	r := setupRouter(infra.Log, infra.Metrics)
	registerRoutes(r, infra, authMod, consentMod, tenantMod)

	mainSrv := httpserver.New(infra.Cfg.Addr, r)
	startServer(mainSrv, infra.Log, "main API")

	var adminSrv *http.Server
	if infra.Cfg.Security.AdminAPIToken != "" {
		adminRouter := setupAdminRouter(infra.Log, authMod.AdminSvc, tenantMod.Handler, infra.Cfg)
		adminSrv = httpserver.New(":8081", adminRouter)
		startServer(adminSrv, infra.Log, "admin")
	}

	waitForShutdown([]*http.Server{mainSrv, adminSrv}, infra.Log, cancelApp)
}

func buildInfra() (*infraBundle, error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return nil, err
	}
	log := logger.New()

	log.Info("initializing credo",
		"addr", cfg.Addr,
		"regulated_mode", cfg.Security.RegulatedMode,
		"env", cfg.Environment,
		"allowed_redirect_schemes", cfg.Auth.AllowedRedirectSchemes,
	)
	if cfg.DemoMode {
		log.Info("CRENE_ENV=demo — starting isolated demo environment",
			"stores", "in-memory",
			"issuer", cfg.Auth.JWTIssuer,
		)
	}

	m := metrics.New()
	jwtService, jwtValidator := initializeJWTService(&cfg)

	return &infraBundle{
		Cfg:          &cfg,
		Log:          log,
		Metrics:      m,
		JWTService:   jwtService,
		JWTValidator: jwtValidator,
	}, nil
}

func buildAuthModule(ctx context.Context, infra *infraBundle) (*authModule, error) {
	users := userStore.NewInMemoryUserStore()
	sessions := sessionStore.NewInMemorySessionStore()
	codes := authCodeStore.NewInMemoryAuthorizationCodeStore()
	refreshTokens := refreshTokenStore.NewInMemoryRefreshTokenStore()
	auditStore := audit.NewInMemoryStore()

	if infra.Cfg.DemoMode {
		seederSvc := seeder.New(users, sessions, codes, refreshTokens, auditStore, infra.Log)
		if err := seederSvc.SeedAll(ctx); err != nil {
			infra.Log.Warn("failed to seed demo data", "error", err)
		}
	}

	authCfg := &authService.Config{
		SessionTTL:             infra.Cfg.Auth.SessionTTL,
		TokenTTL:               infra.Cfg.Auth.TokenTTL,
		AllowedRedirectSchemes: infra.Cfg.Auth.AllowedRedirectSchemes,
		DeviceBindingEnabled:   infra.Cfg.Auth.DeviceBindingEnabled,
	}
	trl := revocationStore.NewInMemoryTRL(
		revocationStore.WithCleanupInterval(infra.Cfg.Auth.TokenRevocationCleanupInterval),
	)

	authSvc, err := authService.New(
		users,
		sessions,
		codes,
		refreshTokens,
		authCfg,
		authService.WithMetrics(infra.Metrics),
		authService.WithLogger(infra.Log),
		authService.WithJWTService(infra.JWTService),
		authService.WithTRL(trl),
	)
	if err != nil {
		return nil, err
	}

	cleanupSvc, err := cleanupWorker.New(
		sessions,
		codes,
		refreshTokens,
		cleanupWorker.WithCleanupLogger(infra.Log),
		cleanupWorker.WithCleanupInterval(infra.Cfg.Auth.AuthCleanupInterval),
	)
	if err != nil {
		return nil, err
	}

	return &authModule{
		Service:       authSvc,
		Handler:       authHandler.New(authSvc, infra.Log, infra.Cfg.Auth.DeviceCookieName, infra.Cfg.Auth.DeviceCookieMaxAge),
		AdminSvc:      admin.NewService(users, sessions, auditStore),
		Cleanup:       cleanupSvc,
		Users:         users,
		Sessions:      sessions,
		Codes:         codes,
		RefreshTokens: refreshTokens,
		AuditStore:    auditStore,
	}, nil
}

func buildConsentModule(infra *infraBundle) *consentModule {
	consentSvc := consentService.NewService(
		consentStore.NewInMemoryStore(),
		audit.NewPublisher(audit.NewInMemoryStore()),
		infra.Log,
		consentService.WithConsentTTL(infra.Cfg.Consent.ConsentTTL),
		consentService.WithGrantWindow(infra.Cfg.Consent.ConsentGrantWindow),
	)

	return &consentModule{
		Service: consentSvc,
		Handler: consentHandler.New(consentSvc, infra.Log, infra.Metrics),
	}
}

func buildTenantModule(infra *infraBundle) *tenantModule {
	tenants := tenantStore.NewInMemoryTenantStore()
	clients := tenantStore.NewInMemoryClientStore()
	service := tenantService.New(tenants, clients, nil)

	// Bootstrap a default tenant/client for backward compatibility with existing flows.
	tenantStore.SeedBootstrapTenant(tenants, clients)

	return &tenantModule{
		Service: service,
		Handler: tenantHandler.New(service, infra.Log),
		Tenants: tenants,
		Clients: clients,
	}
}

func startCleanupWorker(ctx context.Context, log *slog.Logger, cleanupSvc *cleanupWorker.CleanupService) {
	go func() {
		if err := cleanupSvc.Start(ctx); err != nil && err != context.Canceled {
			log.Error("auth cleanup service stopped", "error", err)
		}
	}()
}

// initializeJWTService creates and configures the JWT service and validator
func initializeJWTService(cfg *config.Server) (*jwttoken.JWTService, *jwttoken.JWTServiceAdapter) {
	jwtService := jwttoken.NewJWTService(
		cfg.Auth.JWTSigningKey,
		cfg.Auth.JWTIssuer,
		"credo-client", // TODO: make configurable
		cfg.Auth.TokenTTL,
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
	r.Use(middleware.Timeout(30 * time.Second)) // TODO: make configurable
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

// registerRoutes wires HTTP handlers to the shared router
func registerRoutes(r *chi.Mux, infra *infraBundle, authMod *authModule, consentMod *consentModule, tenantMod *tenantModule) {
	if infra.Cfg.DemoMode {
		r.Get("/demo/info", func(w http.ResponseWriter, _ *http.Request) {
			resp := map[string]any{
				"env":        "demo",
				"users":      []string{"alice", "bob", "charlie"},
				"jwt_issuer": infra.Cfg.Auth.JWTIssuer,
				"data_store": "in-memory",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
	}

	r.Post("/auth/authorize", authMod.Handler.HandleAuthorize)
	r.Post("/auth/token", authMod.Handler.HandleToken)
	r.Post("/auth/revoke", authMod.Handler.HandleRevoke)

	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth(infra.JWTValidator, authMod.Service, infra.Log))
		r.Get("/auth/userinfo", authMod.Handler.HandleUserInfo)
		r.Get("/auth/sessions", authMod.Handler.HandleListSessions)
		r.Delete("/auth/sessions/{session_id}", authMod.Handler.HandleRevokeSession)
		consentMod.Handler.Register(r)
	})

	if infra.Cfg.Security.AdminAPIToken != "" {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdminToken(infra.Cfg.Security.AdminAPIToken, infra.Log))
			authMod.Handler.RegisterAdmin(r)
			tenantMod.Handler.Register(r)
		})
	}
}

// setupAdminRouter creates a router for the admin server
func setupAdminRouter(log *slog.Logger, adminSvc *admin.Service, tenantHandler *tenantHandler.Handler, cfg *config.Server) *chi.Mux {
	r := chi.NewRouter()

	// Common middleware for all routes
	r.Use(middleware.Recovery(log))
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger(log))
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.ContentTypeJSON)

	// Health check and metrics
	r.Handle("/metrics", promhttp.Handler())
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Admin info endpoint (unauthenticated)
	r.Get("/admin/info", func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"service": "admin",
			"version": "1.0.0",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	// All admin routes require authentication
	adminHandler := admin.New(adminSvc, log)
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdminToken(cfg.Security.AdminAPIToken, log))
		adminHandler.Register(r)
		tenantHandler.Register(r)
	})

	return r
}

// startServer starts the HTTP server in a goroutine
func startServer(srv *http.Server, log *slog.Logger, name string) {
	log.Info("starting http server", "name", name, "addr", srv.Addr)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "name", name, "error", err)
			os.Exit(1)
		}
	}()
}

// waitForShutdown waits for an interrupt signal and gracefully shuts down all servers
func waitForShutdown(servers []*http.Server, log *slog.Logger, cancel context.CancelFunc) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	log.Info("shutting down servers gracefully")
	if cancel != nil {
		cancel()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown all servers
	for _, srv := range servers {
		if srv != nil {
			if err := srv.Shutdown(ctx); err != nil {
				log.Error("graceful shutdown failed", "addr", srv.Addr, "error", err)
			}
		}
	}

	log.Info("servers stopped")
}
