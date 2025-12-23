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
	authAdapters "credo/internal/auth/adapters"
	"credo/internal/auth/device"
	authHandler "credo/internal/auth/handler"
	authPorts "credo/internal/auth/ports"
	authmetrics "credo/internal/auth/metrics"
	authService "credo/internal/auth/service"
	authCodeStore "credo/internal/auth/store/authorization-code"
	refreshTokenStore "credo/internal/auth/store/refresh-token"
	revocationStore "credo/internal/auth/store/revocation"
	sessionStore "credo/internal/auth/store/session"
	userStore "credo/internal/auth/store/user"
	cleanupWorker "credo/internal/auth/workers/cleanup"
	consentHandler "credo/internal/consent/handler"
	consentmetrics "credo/internal/consent/metrics"
	consentService "credo/internal/consent/service"
	consentStore "credo/internal/consent/store"
	jwttoken "credo/internal/jwt_token"
	"credo/internal/platform/config"
	"credo/internal/platform/httpserver"
	"credo/internal/platform/logger"
	rateLimitConfig "credo/internal/ratelimit/config"
	rateLimitMW "credo/internal/ratelimit/middleware"
	rateLimitModels "credo/internal/ratelimit/models"
	"credo/internal/ratelimit/service/authlockout"
	rateLimitChecker "credo/internal/ratelimit/service/checker"
	"credo/internal/ratelimit/service/globalthrottle"
	"credo/internal/ratelimit/service/quota"
	"credo/internal/ratelimit/service/requestlimit"
	rwallowlistStore "credo/internal/ratelimit/store/allowlist"
	authlockoutStore "credo/internal/ratelimit/store/authlockout"
	rwbucketStore "credo/internal/ratelimit/store/bucket"
	globalthrottleStore "credo/internal/ratelimit/store/globalthrottle"
	quotaStore "credo/internal/ratelimit/store/quota"
	"credo/internal/seeder"
	tenantHandler "credo/internal/tenant/handler"
	tenantmetrics "credo/internal/tenant/metrics"
	tenantService "credo/internal/tenant/service"
	clientstore "credo/internal/tenant/store/client"
	tenantstore "credo/internal/tenant/store/tenant"
	auditpublisher "credo/pkg/platform/audit/publisher"
	auditstore "credo/pkg/platform/audit/store/memory"
	adminmw "credo/pkg/platform/middleware/admin"
	auth "credo/pkg/platform/middleware/auth"
	devicemw "credo/pkg/platform/middleware/device"
	metadata "credo/pkg/platform/middleware/metadata"
	request "credo/pkg/platform/middleware/request"
	requesttime "credo/pkg/platform/middleware/requesttime"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type infraBundle struct {
	Cfg            *config.Server
	Log            *slog.Logger
	AuthMetrics    *authmetrics.Metrics
	ConsentMetrics *consentmetrics.Metrics
	TenantMetrics  *tenantmetrics.Metrics
	RequestMetrics *request.Metrics
	JWTService     *jwttoken.JWTService
	JWTValidator   *jwttoken.JWTServiceAdapter
	DeviceService  *device.Service
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
	AuditStore    *auditstore.InMemoryStore
}

type consentModule struct {
	Service *consentService.Service
	Handler *consentHandler.Handler
}

type tenantModule struct {
	Service *tenantService.Service
	Handler *tenantHandler.Handler
	Tenants *tenantstore.InMemory
	Clients *clientstore.InMemory
}

func main() {
	infra, err := buildInfra()
	if err != nil {
		panic(err)
	}

	checkerSvc, allowlistStore, err := buildRateLimitServices(infra.Log)
	if err != nil {
		infra.Log.Error("failed to initialize rate limit services", "error", err)
		os.Exit(1)
	}
	rateLimitMiddleware := rateLimitMW.New(checkerSvc, infra.Log, rateLimitMW.WithDisabled(infra.Cfg.DemoMode || infra.Cfg.DisableRateLimiting))

	appCtx, cancelApp := context.WithCancel(context.Background())
	defer cancelApp()
	tenantMod := buildTenantModule(infra)
	authMod, err := buildAuthModule(appCtx, infra, tenantMod.Service, checkerSvc)
	if err != nil {
		infra.Log.Error("failed to initialize auth module", "error", err)
		os.Exit(1)
	}
	consentMod := buildConsentModule(infra)

	startCleanupWorker(appCtx, infra.Log, authMod.Cleanup)
	go func() {
		if err := allowlistStore.StartCleanup(appCtx, 5*time.Minute); err != nil && err != context.Canceled {
			infra.Log.Error("rate limit cleanup stopped", "error", err)
		}
	}()

	r := setupRouter(infra)
	registerRoutes(r, infra, authMod, consentMod, tenantMod, rateLimitMiddleware)

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

func buildRateLimitServices(logger *slog.Logger) (*rateLimitChecker.Service, *rwallowlistStore.InMemoryAllowlistStore, error) {
	cfg := rateLimitConfig.DefaultConfig()

	// Create stores
	bucketStore := rwbucketStore.New()
	allowlistStore := rwallowlistStore.New()
	authLockoutSt := authlockoutStore.New()
	quotaSt := quotaStore.New(cfg)
	globalThrottleSt := globalthrottleStore.New()

	// Create focused services
	requestSvc, err := requestlimit.New(bucketStore, allowlistStore,
		requestlimit.WithLogger(logger),
	)
	if err != nil {
		logger.Error("failed to create request limit service", "error", err)
		return nil, nil, err
	}

	authLockoutSvc, err := authlockout.New(authLockoutSt,
		authlockout.WithLogger(logger),
	)
	if err != nil {
		logger.Error("failed to create auth lockout service", "error", err)
		return nil, nil, err
	}

	quotaSvc, err := quota.New(quotaSt,
		quota.WithLogger(logger),
	)
	if err != nil {
		logger.Error("failed to create quota service", "error", err)
		return nil, nil, err
	}

	globalThrottleSvc, err := globalthrottle.New(globalThrottleSt,
		globalthrottle.WithLogger(logger),
	)
	if err != nil {
		logger.Error("failed to create global throttle service", "error", err)
		return nil, nil, err
	}

	// Create facade
	checkerSvc, err := rateLimitChecker.New(
		requestSvc,
		authLockoutSvc,
		quotaSvc,
		globalThrottleSvc,
		rateLimitChecker.WithLogger(logger),
	)
	if err != nil {
		logger.Error("failed to create rate limit checker service", "error", err)
		return nil, nil, err
	}

	// Note: Admin service would be created here if needed for rate limit admin handlers
	// adminSvc, err := rateLimitAdmin.New(allowlistStore, bucketStore, rateLimitAdmin.WithLogger(logger))

	return checkerSvc, allowlistStore, nil
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
		log.Info("CREDO_ENV=demo — starting isolated demo environment",
			"stores", "in-memory",
			"issuer_base_url", cfg.Auth.JWTIssuerBaseURL,
		)
	}

	authMetrics := authmetrics.New()
	consentMetrics := consentmetrics.New()
	tenantMetrics := tenantmetrics.New()
	requestMetrics := request.NewMetrics()
	jwtService, jwtValidator := initializeJWTService(&cfg)
	deviceSvc := device.NewService(cfg.Auth.DeviceBindingEnabled)

	return &infraBundle{
		Cfg:            &cfg,
		Log:            log,
		AuthMetrics:    authMetrics,
		ConsentMetrics: consentMetrics,
		TenantMetrics:  tenantMetrics,
		RequestMetrics: requestMetrics,
		JWTService:     jwtService,
		JWTValidator:   jwtValidator,
		DeviceService:  deviceSvc,
	}, nil
}

func buildAuthModule(ctx context.Context, infra *infraBundle, tenantService *tenantService.Service, checkerSvc *rateLimitChecker.Service) (*authModule, error) {
	users := userStore.NewInMemoryUserStore()
	sessions := sessionStore.NewInMemorySessionStore()
	codes := authCodeStore.NewInMemoryAuthorizationCodeStore()
	refreshTokens := refreshTokenStore.NewInMemoryRefreshTokenStore()
	auditStore := auditstore.NewInMemoryStore()

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
		authService.WithMetrics(infra.AuthMetrics),
		authService.WithLogger(infra.Log),
		authService.WithJWTService(infra.JWTService),
		authService.WithTRL(trl),
		authService.WithAuditPublisher(auditpublisher.NewPublisher(auditStore)),
		authService.WithClientResolver(tenantService),
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
		infra.Log.Error("failed to create auth cleanup service", "error", err)
		return nil, err
	}

	// Create rate limit adapter for auth handler (nil if rate limiting is disabled)
	var rateLimitAdapter authPorts.RateLimitPort
	if !infra.Cfg.DemoMode && !infra.Cfg.DisableRateLimiting {
		rateLimitAdapter = authAdapters.NewRateLimitAdapter(checkerSvc)
	}

	return &authModule{
		Service:       authSvc,
		Handler:       authHandler.New(authSvc, rateLimitAdapter, infra.Log, infra.Cfg.Auth.DeviceCookieName, infra.Cfg.Auth.DeviceCookieMaxAge),
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
		auditpublisher.NewPublisher(auditstore.NewInMemoryStore()),
		infra.Log,
		consentService.WithConsentTTL(infra.Cfg.Consent.ConsentTTL),
		consentService.WithGrantWindow(infra.Cfg.Consent.ConsentGrantWindow),
		consentService.WithMetrics(infra.ConsentMetrics),
	)

	return &consentModule{
		Service: consentSvc,
		Handler: consentHandler.New(consentSvc, infra.Log, infra.ConsentMetrics),
	}
}

func buildTenantModule(infra *infraBundle) *tenantModule {
	tenants := tenantstore.NewInMemory()
	clients := clientstore.NewInMemory()
	service := tenantService.New(
		tenants,
		clients,
		nil,
		tenantService.WithMetrics(infra.TenantMetrics),
	)

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
		cfg.Auth.JWTIssuerBaseURL,
		cfg.Auth.JWTAudience,
		cfg.Auth.TokenTTL,
	)
	if cfg.DemoMode {
		jwtService.SetEnv("demo")
	}
	jwtValidator := jwttoken.NewJWTServiceAdapter(jwtService)
	return jwtService, jwtValidator
}

// setupRouter creates a new router and configures common middleware
func setupRouter(infra *infraBundle) *chi.Mux {
	r := chi.NewRouter()

	// Common middleware for all routes (must be defined before routes)
	r.Use(metadata.ClientMetadata)
	r.Use(requesttime.Middleware)
	r.Use(devicemw.Device(&devicemw.DeviceConfig{
		CookieName:    infra.Cfg.Auth.DeviceCookieName,
		FingerprintFn: infra.DeviceService.ComputeFingerprint,
	}))
	r.Use(request.Recovery(infra.Log))
	r.Use(request.RequestID)
	r.Use(request.Logger(infra.Log))
	r.Use(request.Timeout(30 * time.Second)) // TODO: make configurable
	r.Use(request.ContentTypeJSON)
	r.Use(request.LatencyMiddleware(infra.RequestMetrics))

	// Add Prometheus metrics endpoint (no auth required)
	r.Handle("/metrics", promhttp.Handler())
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return r
}

// registerRoutes wires HTTP handlers to the shared router
func registerRoutes(r *chi.Mux, infra *infraBundle, authMod *authModule, consentMod *consentModule, tenantMod *tenantModule, rateLimitMiddleware *rateLimitMW.Middleware) {
	if infra.Cfg.DemoMode {
		r.Get("/demo/info", func(w http.ResponseWriter, _ *http.Request) {
			resp := map[string]any{
				"env":             "demo",
				"users":           []string{"alice", "bob", "charlie"},
				"jwt_issuer_base": infra.Cfg.Auth.JWTIssuerBaseURL,
				"data_store":      "in-memory",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
	}

	// Auth public endpoints - ClassAuth (10 req/min)
	r.Group(func(r chi.Router) {
		r.Use(rateLimitMiddleware.RateLimit(rateLimitModels.ClassAuth))
		r.Post("/auth/authorize", authMod.Handler.HandleAuthorize)
		r.Post("/auth/token", authMod.Handler.HandleToken)
		r.Post("/auth/revoke", authMod.Handler.HandleRevoke)
	})

	// Protected read endpoints - ClassRead (100 req/min)
	r.Group(func(r chi.Router) {
		r.Use(rateLimitMiddleware.RateLimitAuthenticated(rateLimitModels.ClassRead))
		r.Use(auth.RequireAuth(infra.JWTValidator, authMod.Service, infra.Log))
		r.Get("/auth/userinfo", authMod.Handler.HandleUserInfo)
		r.Get("/auth/sessions", authMod.Handler.HandleListSessions)
		r.Get("/auth/consent", consentMod.Handler.HandleGetConsents)
	})

	// Protected sensitive endpoints - ClassSensitive (30 req/min)
	r.Group(func(r chi.Router) {
		r.Use(rateLimitMiddleware.RateLimitAuthenticated(rateLimitModels.ClassSensitive))
		r.Use(auth.RequireAuth(infra.JWTValidator, authMod.Service, infra.Log))
		r.Delete("/auth/sessions/{session_id}", authMod.Handler.HandleRevokeSession)
		r.Post("/auth/consent", consentMod.Handler.HandleGrantConsent)
		r.Post("/auth/consent/revoke", consentMod.Handler.HandleRevokeConsent)
		r.Post("/auth/consent/revoke-all", consentMod.Handler.HandleRevokeAllConsents)
		r.Delete("/auth/consent", consentMod.Handler.HandleDeleteAllConsents)
	})

	// Admin endpoints - ClassWrite (50 req/min)
	if infra.Cfg.Security.AdminAPIToken != "" {
		r.Group(func(r chi.Router) {
			r.Use(rateLimitMiddleware.RateLimitAuthenticated(rateLimitModels.ClassWrite))
			r.Use(adminmw.RequireAdminToken(infra.Cfg.Security.AdminAPIToken, infra.Log))
			authMod.Handler.RegisterAdmin(r)
			tenantMod.Handler.Register(r)
		})
	}
}

// setupAdminRouter creates a router for the admin server
func setupAdminRouter(log *slog.Logger, adminSvc *admin.Service, tenantHandler *tenantHandler.Handler, cfg *config.Server) *chi.Mux {
	r := chi.NewRouter()

	// Common middleware for all routes
	r.Use(requesttime.Middleware)
	r.Use(request.Recovery(log))
	r.Use(request.RequestID)
	r.Use(request.Logger(log))
	r.Use(request.Timeout(30 * time.Second))
	r.Use(request.ContentTypeJSON)

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
		r.Use(adminmw.RequireAdminToken(cfg.Security.AdminAPIToken, log))
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
