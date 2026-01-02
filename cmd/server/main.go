package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"credo/internal/admin"
	authAdapters "credo/internal/auth/adapters"
	"credo/internal/auth/device"
	authHandler "credo/internal/auth/handler"
	authmetrics "credo/internal/auth/metrics"
	authPorts "credo/internal/auth/ports"
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
	"credo/internal/decision"
	decisionAdapters "credo/internal/decision/adapters"
	decisionHandler "credo/internal/decision/handler"
	decisionmetrics "credo/internal/decision/metrics"
	registryAdapters "credo/internal/evidence/registry/adapters"
	registryHandler "credo/internal/evidence/registry/handler"
	registrymetrics "credo/internal/evidence/registry/metrics"
	"credo/internal/evidence/registry/orchestrator"
	"credo/internal/evidence/registry/providers"
	citizenProvider "credo/internal/evidence/registry/providers/citizen"
	sanctionsProvider "credo/internal/evidence/registry/providers/sanctions"
	registryService "credo/internal/evidence/registry/service"
	registryStore "credo/internal/evidence/registry/store"
	vcAdapters "credo/internal/evidence/vc/adapters"
	vcHandler "credo/internal/evidence/vc/handler"
	vcService "credo/internal/evidence/vc/service"
	vcStore "credo/internal/evidence/vc/store"
	jwttoken "credo/internal/jwt_token"
	"credo/internal/platform/config"
	"credo/internal/platform/database"
	"credo/internal/platform/health"
	"credo/internal/platform/httpserver"
	"credo/internal/platform/kafka"
	kafkaconsumer "credo/internal/platform/kafka/consumer"
	kafkaproducer "credo/internal/platform/kafka/producer"
	"credo/internal/platform/logger"
	rateLimitConfig "credo/internal/ratelimit/config"
	rateLimitMW "credo/internal/ratelimit/middleware"
	rateLimitModels "credo/internal/ratelimit/models"
	"credo/internal/ratelimit/service/authlockout"
	rateLimitClientLimit "credo/internal/ratelimit/service/clientlimit"
	"credo/internal/ratelimit/service/globalthrottle"
	"credo/internal/ratelimit/service/requestlimit"
	rwallowlistStore "credo/internal/ratelimit/store/allowlist"
	authlockoutStore "credo/internal/ratelimit/store/authlockout"
	rwbucketStore "credo/internal/ratelimit/store/bucket"
	globalthrottleStore "credo/internal/ratelimit/store/globalthrottle"
	tenantHandler "credo/internal/tenant/handler"
	tenantmetrics "credo/internal/tenant/metrics"
	tenantService "credo/internal/tenant/service"
	clientstore "credo/internal/tenant/store/client"
	tenantstore "credo/internal/tenant/store/tenant"
	audit "credo/pkg/platform/audit"
	auditconsumer "credo/pkg/platform/audit/consumer"
	auditmetrics "credo/pkg/platform/audit/metrics"
	outboxmetrics "credo/pkg/platform/audit/outbox/metrics"
	outboxpostgres "credo/pkg/platform/audit/outbox/store/postgres"
	outboxworker "credo/pkg/platform/audit/outbox/worker"
	auditpublisher "credo/pkg/platform/audit/publisher"
	auditpostgres "credo/pkg/platform/audit/store/postgres"
	adminmw "credo/pkg/platform/middleware/admin"
	auth "credo/pkg/platform/middleware/auth"
	devicemw "credo/pkg/platform/middleware/device"
	metadata "credo/pkg/platform/middleware/metadata"
	request "credo/pkg/platform/middleware/request"
	requesttime "credo/pkg/platform/middleware/requesttime"
	"credo/pkg/platform/validation"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type infraBundle struct {
	Cfg             *config.Server
	Log             *slog.Logger
	AuthMetrics     *authmetrics.Metrics
	ConsentMetrics  *consentmetrics.Metrics
	TenantMetrics   *tenantmetrics.Metrics
	AuditMetrics    *auditmetrics.Metrics
	RegistryMetrics *registrymetrics.Metrics
	RequestMetrics  *request.Metrics
	JWTService      *jwttoken.JWTService
	JWTValidator    *jwttoken.JWTServiceAdapter
	DeviceService   *device.Service

	// Phase 2: Infrastructure
	DBPool             *database.Pool
	KafkaProducer      *kafkaproducer.Producer
	OutboxWorker       *outboxworker.Worker
	OutboxMetrics      *outboxmetrics.Metrics
	KafkaConsumer      *kafkaconsumer.Consumer
	KafkaHealthChecker *kafka.HealthChecker
}

type authModule struct {
	Service    *authService.Service
	Handler    *authHandler.Handler
	AdminSvc   *admin.Service
	Cleanup    *cleanupWorker.CleanupService
	AuditStore audit.Store
}

type consentModule struct {
	Service *consentService.Service
	Handler *consentHandler.Handler
}

type tenantModule struct {
	Service *tenantService.Service
	Handler *tenantHandler.Handler
}

type registryModule struct {
	Service *registryService.Service
	Handler *registryHandler.Handler
}

type vcModule struct {
	Service *vcService.Service
	Handler *vcHandler.Handler
	Store   vcStore.Store
}

type decisionModule struct {
	Service *decision.Service
	Handler *decisionHandler.Handler
}

type tenantClientLookup struct {
	tenantSvc *tenantService.Service
}

func (t *tenantClientLookup) IsConfidentialClient(ctx context.Context, clientID string) (bool, error) {
	client, _, err := t.tenantSvc.ResolveClient(ctx, clientID)
	if err != nil {
		return false, err
	}
	return client.IsConfidential(), nil
}

func main() {
	infra, err := buildInfra()
	if err != nil {
		panic(err)
	}

	rlBundle, err := buildRateLimitServices(infra.Log, infra.DBPool)
	if err != nil {
		infra.Log.Error("failed to initialize rate limit services", "error", err)
		os.Exit(1)
	}
	rateLimitMiddleware := rateLimitMW.New(
		rlBundle.limiter,
		infra.Log,
		rateLimitMW.WithDisabled(infra.Cfg.DemoMode || infra.Cfg.DisableRateLimiting),
	)

	appCtx, cancelApp := context.WithCancel(context.Background())
	defer cancelApp()
	tenantMod, err := buildTenantModule(infra)
	if err != nil {
		infra.Log.Error("failed to initialize tenant module", "error", err)
		os.Exit(1)
	}
	authMod, err := buildAuthModule(appCtx, infra, tenantMod.Service, rlBundle.authLockoutSvc, rlBundle.requestSvc)
	if err != nil {
		infra.Log.Error("failed to initialize auth module", "error", err)
		os.Exit(1)
	}
	clientRateLimitMiddleware, err := buildClientRateLimitMiddleware(infra.Log, tenantMod.Service, rlBundle.cfg, infra.DBPool, infra.Cfg.DemoMode || infra.Cfg.DisableRateLimiting)
	if err != nil {
		infra.Log.Error("failed to initialize client rate limit middleware", "error", err)
		os.Exit(1)
	}
	consentMod, err := buildConsentModule(infra)
	if err != nil {
		infra.Log.Error("failed to initialize consent module", "error", err)
		os.Exit(1)
	}
	registryMod, err := buildRegistryModule(infra, consentMod.Service)
	if err != nil {
		infra.Log.Error("failed to initialize registry module", "error", err)
		os.Exit(1)
	}
	vcMod, err := buildVCModule(infra, consentMod.Service, registryMod.Service)
	if err != nil {
		infra.Log.Error("failed to initialize vc module", "error", err)
		os.Exit(1)
	}
	decisionMod, err := buildDecisionModule(infra, registryMod.Service, vcMod.Store, consentMod.Service)
	if err != nil {
		infra.Log.Error("failed to initialize decision module", "error", err)
		os.Exit(1)
	}

	startCleanupWorker(appCtx, infra.Log, authMod.Cleanup)
	go func() {
		if err := rlBundle.allowlistStore.StartCleanup(appCtx, 5*time.Minute); err != nil && err != context.Canceled {
			infra.Log.Error("rate limit cleanup stopped", "error", err)
		}
	}()

	// Start Phase 2 workers if configured
	startPhase2Workers(infra)

	r := setupRouter(infra)
	registerRoutes(r, infra, authMod, consentMod, tenantMod, registryMod, vcMod, decisionMod, rateLimitMiddleware, clientRateLimitMiddleware)

	mainSrv := httpserver.New(infra.Cfg.Addr, r)
	startServer(mainSrv, infra.Log, "main API")

	var adminSrv *http.Server
	if infra.Cfg.Security.AdminAPIToken != "" {
		adminRouter := setupAdminRouter(infra.Log, authMod.AdminSvc, tenantMod.Handler, infra.Cfg, rateLimitMiddleware)
		adminSrv = httpserver.New(":8081", adminRouter)
		startServer(adminSrv, infra.Log, "admin")
	}

	waitForShutdown([]*http.Server{mainSrv, adminSrv}, infra, cancelApp)
}

// rateLimitBundle holds the rate limiting services needed by middleware and auth.
type rateLimitBundle struct {
	limiter        *rateLimitMW.Limiter
	authLockoutSvc *authlockout.Service
	requestSvc     *requestlimit.Service
	allowlistStore interface {
		requestlimit.AllowlistStore
		StartCleanup(ctx context.Context, interval time.Duration) error
	}
	cfg *rateLimitConfig.Config
}

func buildRateLimitServices(logger *slog.Logger, dbPool *database.Pool) (*rateLimitBundle, error) {
	cfg := rateLimitConfig.DefaultConfig()

	if dbPool == nil {
		return nil, fmt.Errorf("database connection required for rate limit stores")
	}

	// Create stores
	bucketStore := rwbucketStore.NewPostgres(dbPool.DB())
	allowlistStore := rwallowlistStore.NewPostgres(dbPool.DB())
	authLockoutSt := authlockoutStore.NewPostgres(dbPool.DB(), &cfg.AuthLockout)
	globalThrottleSt := globalthrottleStore.NewPostgres(dbPool.DB(), &cfg.Global)

	// Create focused services
	requestSvc, err := requestlimit.New(bucketStore, allowlistStore,
		requestlimit.WithLogger(logger),
		requestlimit.WithConfig(cfg),
	)
	if err != nil {
		logger.Error("failed to create request limit service", "error", err)
		return nil, err
	}

	authLockoutSvc, err := authlockout.New(authLockoutSt,
		authlockout.WithLogger(logger),
	)
	if err != nil {
		logger.Error("failed to create auth lockout service", "error", err)
		return nil, err
	}

	globalThrottleSvc, err := globalthrottle.New(globalThrottleSt,
		globalthrottle.WithLogger(logger),
	)
	if err != nil {
		logger.Error("failed to create global throttle service", "error", err)
		return nil, err
	}

	// Create limiter for middleware (composes requestlimit + globalthrottle)
	limiter := rateLimitMW.NewLimiter(requestSvc, globalThrottleSvc)

	return &rateLimitBundle{
		limiter:        limiter,
		authLockoutSvc: authLockoutSvc,
		requestSvc:     requestSvc,
		allowlistStore: allowlistStore,
		cfg:            cfg,
	}, nil
}

func buildClientRateLimitMiddleware(logger *slog.Logger, tenantSvc *tenantService.Service, cfg *rateLimitConfig.Config, dbPool *database.Pool, disabled bool) (*rateLimitMW.ClientMiddleware, error) {
	if cfg == nil {
		return nil, fmt.Errorf("rate limit config is required")
	}
	if dbPool == nil {
		return nil, fmt.Errorf("database connection required for client rate limits")
	}
	clientLookup := &tenantClientLookup{tenantSvc: tenantSvc}
	clientBucketStore := rwbucketStore.NewPostgres(dbPool.DB())
	clientLimiter, err := rateLimitClientLimit.New(
		clientBucketStore,
		clientLookup,
		rateLimitClientLimit.WithLogger(logger),
		rateLimitClientLimit.WithConfig(&cfg.ClientLimits),
	)
	if err != nil {
		return nil, err
	}
	return rateLimitMW.NewClientMiddleware(
		clientLimiter,
		logger,
		disabled,
	), nil
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
			"stores", "postgres",
			"issuer_base_url", cfg.Auth.JWTIssuerBaseURL,
		)
	}

	authMetrics := authmetrics.New()
	consentMetrics := consentmetrics.New()
	tenantMetrics := tenantmetrics.New()
	auditMet := auditmetrics.New()
	registryMet := registrymetrics.New()
	requestMetrics := request.NewMetrics()
	outboxMet := outboxmetrics.New()
	jwtService, jwtValidator := initializeJWTService(&cfg)
	deviceSvc := device.NewService(cfg.Auth.DeviceBindingEnabled)

	bundle := &infraBundle{
		Cfg:             &cfg,
		Log:             log,
		AuthMetrics:     authMetrics,
		ConsentMetrics:  consentMetrics,
		TenantMetrics:   tenantMetrics,
		AuditMetrics:    auditMet,
		RegistryMetrics: registryMet,
		RequestMetrics:  requestMetrics,
		JWTService:      jwtService,
		JWTValidator:    jwtValidator,
		DeviceService:   deviceSvc,
		OutboxMetrics:   outboxMet,
	}

	// Initialize Phase 2 infrastructure if configured
	if err := initPhase2Infra(bundle, &cfg, log); err != nil {
		return nil, err
	}

	return bundle, nil
}

// initPhase2Infra initializes database, Kafka, and outbox infrastructure.
func initPhase2Infra(bundle *infraBundle, cfg *config.Server, log *slog.Logger) error {
	// Initialize database pool if configured
	if cfg.Database.URL != "" {
		dbPool, err := database.New(database.Config{
			URL:             cfg.Database.URL,
			MaxOpenConns:    cfg.Database.MaxOpenConns,
			MaxIdleConns:    cfg.Database.MaxIdleConns,
			ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
		})
		if err != nil {
			return fmt.Errorf("initialize database: %w", err)
		}
		bundle.DBPool = dbPool
		log.Info("database connected", "url", cfg.Database.URL[:min(len(cfg.Database.URL), 50)]+"...")
	}

	// Initialize Kafka producer if configured
	if cfg.Kafka.Brokers != "" {
		producer, err := kafkaproducer.New(kafkaproducer.Config{
			Brokers:         cfg.Kafka.Brokers,
			Acks:            cfg.Kafka.Acks,
			Retries:         cfg.Kafka.Retries,
			DeliveryTimeout: cfg.Kafka.DeliveryTimeout,
		}, log)
		if err != nil {
			return fmt.Errorf("initialize kafka producer: %w", err)
		}
		bundle.KafkaProducer = producer
		bundle.KafkaHealthChecker = kafka.NewHealthChecker(cfg.Kafka.Brokers)
		log.Info("kafka producer initialized", "brokers", cfg.Kafka.Brokers)
	}

	// Initialize outbox worker if both database and Kafka are configured
	if bundle.DBPool != nil && bundle.KafkaProducer != nil {
		outboxStore := outboxpostgres.New(bundle.DBPool.DB())
		bundle.OutboxWorker = outboxworker.New(
			outboxStore,
			bundle.KafkaProducer,
			outboxworker.WithTopic(cfg.Kafka.AuditTopic),
			outboxworker.WithBatchSize(cfg.Outbox.BatchSize),
			outboxworker.WithPollInterval(cfg.Outbox.PollInterval),
			outboxworker.WithMetrics(bundle.OutboxMetrics),
			outboxworker.WithLogger(log),
		)
		log.Info("outbox worker initialized",
			"topic", cfg.Kafka.AuditTopic,
			"batch_size", cfg.Outbox.BatchSize,
			"poll_interval", cfg.Outbox.PollInterval,
		)

		// Initialize audit event consumer
		auditStore := auditpostgres.New(bundle.DBPool.DB())
		handler := auditconsumer.NewHandler(auditStore, log)
		consumer, err := kafkaconsumer.New(kafkaconsumer.Config{
			Brokers:         cfg.Kafka.Brokers,
			GroupID:         cfg.Kafka.ConsumerGroup,
			AutoOffsetReset: "earliest",
		}, handler, log)
		if err != nil {
			return fmt.Errorf("initialize kafka consumer: %w", err)
		}
		if err := consumer.Subscribe([]string{cfg.Kafka.AuditTopic}); err != nil {
			return fmt.Errorf("subscribe to audit topic: %w", err)
		}
		bundle.KafkaConsumer = consumer
		log.Info("kafka consumer initialized",
			"group", cfg.Kafka.ConsumerGroup,
			"topic", cfg.Kafka.AuditTopic,
		)
	}

	return nil
}

func buildAuthModule(ctx context.Context, infra *infraBundle, tenantService *tenantService.Service, authLockoutSvc *authlockout.Service, requestSvc *requestlimit.Service) (*authModule, error) {
	if infra.DBPool == nil {
		return nil, fmt.Errorf("database connection required for auth module")
	}

	users := userStore.NewPostgres(infra.DBPool.DB())
	sessions := sessionStore.NewPostgres(infra.DBPool.DB())
	codes := authCodeStore.NewPostgres(infra.DBPool.DB())
	refreshTokens := refreshTokenStore.NewPostgres(infra.DBPool.DB())
	auditStore := auditpostgres.New(infra.DBPool.DB())

	authCfg := &authService.Config{
		SessionTTL:             infra.Cfg.Auth.SessionTTL,
		TokenTTL:               infra.Cfg.Auth.TokenTTL,
		AllowedRedirectSchemes: infra.Cfg.Auth.AllowedRedirectSchemes,
		DeviceBindingEnabled:   infra.Cfg.Auth.DeviceBindingEnabled,
	}
	trl := revocationStore.NewPostgresTRL(infra.DBPool.DB())

	// Wrap tenant service with circuit breaker for resilience
	resilientClientResolver := authAdapters.NewResilientClientResolver(
		tenantService,
		infra.Log,
		authAdapters.WithFailureThreshold(5),
		authAdapters.WithCacheTTL(5*time.Minute),
	)

	authSvc, err := authService.New(
		users,
		sessions,
		codes,
		refreshTokens,
		infra.JWTService,
		resilientClientResolver,
		authCfg,
		authService.WithMetrics(infra.AuthMetrics),
		authService.WithLogger(infra.Log),
		authService.WithTRL(trl),
		authService.WithAuditPublisher(auditpublisher.NewPublisher(
			auditStore,
			auditpublisher.WithMetrics(infra.AuditMetrics),
			auditpublisher.WithPublisherLogger(infra.Log),
		)),
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
		rateLimitAdapter = authAdapters.New(authLockoutSvc, requestSvc)
	}

	return &authModule{
		Service:    authSvc,
		Handler:    authHandler.New(authSvc, rateLimitAdapter, infra.AuthMetrics, infra.Log, infra.Cfg.Auth.DeviceCookieName, infra.Cfg.Auth.DeviceCookieMaxAge),
		AdminSvc:   admin.NewService(users, sessions, auditStore),
		Cleanup:    cleanupSvc,
		AuditStore: auditStore,
	}, nil
}

func buildConsentModule(infra *infraBundle) (*consentModule, error) {
	if infra.DBPool == nil {
		return nil, fmt.Errorf("database connection required for consent module")
	}
	auditStore := auditpostgres.New(infra.DBPool.DB())

	consentSvc := consentService.New(
		consentStore.NewPostgres(infra.DBPool.DB()),
		auditpublisher.NewPublisher(
			auditStore,
			auditpublisher.WithMetrics(infra.AuditMetrics),
			auditpublisher.WithPublisherLogger(infra.Log),
		),
		infra.Log,
		consentService.WithConsentTTL(infra.Cfg.Consent.ConsentTTL),
		consentService.WithGrantWindow(infra.Cfg.Consent.ConsentGrantWindow),
		consentService.WithReGrantCooldown(infra.Cfg.Consent.ReGrantCooldown),
		consentService.WithMetrics(infra.ConsentMetrics),
	)

	return &consentModule{
		Service: consentSvc,
		Handler: consentHandler.New(consentSvc, infra.Log, infra.ConsentMetrics),
	}, nil
}

func buildTenantModule(infra *infraBundle) (*tenantModule, error) {
	if infra.DBPool == nil {
		return nil, fmt.Errorf("database connection required for tenant module")
	}
	tenants := tenantstore.NewPostgres(infra.DBPool.DB())
	clients := clientstore.NewPostgres(infra.DBPool.DB())
	userCounter := userStore.NewPostgres(infra.DBPool.DB())
	service, err := tenantService.New(
		tenants,
		clients,
		userCounter,
		tenantService.WithMetrics(infra.TenantMetrics),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant service: %w", err)
	}

	return &tenantModule{
		Service: service,
		Handler: tenantHandler.New(service, infra.Log),
	}, nil
}

func buildRegistryModule(infra *infraBundle, consentSvc *consentService.Service) (*registryModule, error) {
	if infra.DBPool == nil {
		return nil, fmt.Errorf("database connection required for registry module")
	}
	// Create provider registry
	registry := providers.NewProviderRegistry()

	// Register citizen provider (tracing handled via OpenTelemetry SDK)
	citizenProv := citizenProvider.New(
		"citizen-registry",
		infra.Cfg.Registry.CitizenRegistryURL,
		infra.Cfg.Registry.CitizenAPIKey,
		infra.Cfg.Registry.RegistryTimeout,
	)
	if err := registry.Register(citizenProv); err != nil {
		infra.Log.Error("failed to register citizen provider", "error", err)
	}

	// Register sanctions provider
	sanctionsProv := sanctionsProvider.New(
		"sanctions-registry",
		infra.Cfg.Registry.SanctionsRegistryURL,
		infra.Cfg.Registry.SanctionsAPIKey,
		infra.Cfg.Registry.RegistryTimeout,
	)
	if err := registry.Register(sanctionsProv); err != nil {
		infra.Log.Error("failed to register sanctions provider", "error", err)
	}

	// Create orchestrator
	orch := orchestrator.New(orchestrator.OrchestratorConfig{
		Registry:        registry,
		DefaultStrategy: orchestrator.StrategyFallback,
		DefaultTimeout:  infra.Cfg.Registry.RegistryTimeout,
	})

	// Create cache store with metrics
	cache := registryStore.NewPostgresCache(
		infra.DBPool.DB(),
		infra.Cfg.Registry.CacheTTL,
		infra.RegistryMetrics,
	)

	// Create consent adapter (needed by both service and handler)
	consentAdapter := registryAdapters.NewConsentAdapter(consentSvc)

	// Create registry service with orchestrator and consent port
	// Tracing is handled automatically via OpenTelemetry SDK
	svc := registryService.New(
		orch,
		cache,
		consentAdapter,
		infra.Cfg.Security.RegulatedMode,
		registryService.WithLogger(infra.Log),
	)

	// Create audit publisher for handler
	auditStore := auditpostgres.New(infra.DBPool.DB())
	auditPort := auditpublisher.NewPublisher(
		auditStore,
		auditpublisher.WithMetrics(infra.AuditMetrics),
		auditpublisher.WithPublisherLogger(infra.Log),
	)

	handler := registryHandler.New(svc, auditPort, infra.Log)

	return &registryModule{
		Service: svc,
		Handler: handler,
	}, nil
}

func buildVCModule(infra *infraBundle, consentSvc *consentService.Service, registrySvc *registryService.Service) (*vcModule, error) {
	if infra.DBPool == nil {
		return nil, fmt.Errorf("database connection required for VC module")
	}
	store := vcStore.NewPostgres(infra.DBPool.DB())
	consentAdapter := vcAdapters.NewConsentAdapter(consentSvc)
	registryAdapter := vcAdapters.NewRegistryAdapter(registrySvc)

	auditStore := auditpostgres.New(infra.DBPool.DB())
	auditPort := auditpublisher.NewPublisher(
		auditStore,
		auditpublisher.WithMetrics(infra.AuditMetrics),
		auditpublisher.WithPublisherLogger(infra.Log),
	)

	svc := vcService.NewService(
		store,
		registryAdapter,
		consentAdapter,
		infra.Cfg.Security.RegulatedMode,
		vcService.WithAuditor(auditPort),
		vcService.WithLogger(infra.Log),
	)

	return &vcModule{
		Service: svc,
		Handler: vcHandler.New(svc, infra.Log),
		Store:   store,
	}, nil
}

func buildDecisionModule(infra *infraBundle, registrySvc *registryService.Service, vcSt vcStore.Store, consentSvc *consentService.Service) (*decisionModule, error) {
	if infra.DBPool == nil {
		return nil, fmt.Errorf("database connection required for decision module")
	}
	// Create adapters
	registryAdapter := decisionAdapters.NewRegistryAdapter(registrySvc)
	vcAdapter := decisionAdapters.NewVCAdapter(vcSt)
	consentAdapter := decisionAdapters.NewConsentAdapter(consentSvc)

	// Create audit publisher
	auditStore := auditpostgres.New(infra.DBPool.DB())
	auditPort := auditpublisher.NewPublisher(
		auditStore,
		auditpublisher.WithMetrics(infra.AuditMetrics),
		auditpublisher.WithPublisherLogger(infra.Log),
	)

	// Create metrics
	metrics := decisionmetrics.New()

	// Create service
	svc := decision.New(
		registryAdapter,
		vcAdapter,
		consentAdapter,
		auditPort,
		decision.WithMetrics(metrics),
		decision.WithLogger(infra.Log),
	)

	return &decisionModule{
		Service: svc,
		Handler: decisionHandler.New(svc, infra.Log, metrics),
	}, nil
}

func startCleanupWorker(ctx context.Context, log *slog.Logger, cleanupSvc *cleanupWorker.CleanupService) {
	go func() {
		if err := cleanupSvc.Start(ctx); err != nil && err != context.Canceled {
			log.Error("auth cleanup service stopped", "error", err)
		}
	}()
}

// startPhase2Workers starts the outbox worker and Kafka consumer if configured.
func startPhase2Workers(infra *infraBundle) {
	if infra.OutboxWorker != nil {
		infra.OutboxWorker.Start()
		infra.Log.Info("outbox worker started")
	}

	if infra.KafkaConsumer != nil {
		infra.KafkaConsumer.Start()
		infra.Log.Info("kafka consumer started")
	}
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
	r.Use(metadata.NewMiddleware(nil).Handler)
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
	r.Use(request.BodyLimit(validation.MaxBodySize))
	r.Use(request.LatencyMiddleware(infra.RequestMetrics))

	// Add Prometheus metrics endpoint (no auth required)
	r.Handle("/metrics", promhttp.Handler())

	// Health check endpoints (no auth required)
	healthHandler := health.New(infra.Cfg.Environment)

	// Register Phase 2 health checks
	if infra.DBPool != nil {
		healthHandler.RegisterCheck("database", func() error {
			return infra.DBPool.Health(context.Background())
		})
	}
	if infra.KafkaHealthChecker != nil {
		healthHandler.RegisterCheck("kafka", func() error {
			return infra.KafkaHealthChecker.Check(context.Background())
		})
	}

	healthHandler.Register(r)

	return r
}

// registerRoutes wires HTTP handlers to the shared router
func registerRoutes(r *chi.Mux, infra *infraBundle, authMod *authModule, consentMod *consentModule, tenantMod *tenantModule, registryMod *registryModule, vcMod *vcModule, decisionMod *decisionModule, rateLimitMiddleware *rateLimitMW.Middleware, clientRateLimitMiddleware *rateLimitMW.ClientMiddleware) {
	if infra.Cfg.DemoMode {
		r.Get("/demo/info", func(w http.ResponseWriter, _ *http.Request) {
			resp := map[string]any{
				"env":             "demo",
				"users":           []string{"alice", "bob", "charlie"},
				"jwt_issuer_base": infra.Cfg.Auth.JWTIssuerBaseURL,
				"data_store":      "postgres",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
	}

	// Auth public endpoints - ClassAuth (10 req/min)
	r.Group(func(r chi.Router) {
		r.Use(rateLimitMiddleware.RateLimit(rateLimitModels.ClassAuth))
		if clientRateLimitMiddleware != nil {
			r.Use(clientRateLimitMiddleware.RateLimitClient())
		}
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
		r.Post("/auth/logout-all", authMod.Handler.HandleLogoutAll)
		r.Post("/auth/consent", consentMod.Handler.HandleGrantConsent)
		r.Post("/auth/consent/revoke", consentMod.Handler.HandleRevokeConsent)
		r.Post("/auth/consent/revoke-all", consentMod.Handler.HandleRevokeAllConsents)
		r.Delete("/auth/consent", consentMod.Handler.HandleDeleteAllConsents)
		// Registry endpoints
		registryMod.Handler.Register(r)
		// Verifiable credential endpoints
		vcMod.Handler.Register(r)
		// Decision endpoints
		decisionMod.Handler.Register(r)
	})

	// Admin endpoints - ClassWrite (50 req/min)
	if infra.Cfg.Security.AdminAPIToken != "" {
		r.Group(func(r chi.Router) {
			r.Use(rateLimitMiddleware.RateLimitAuthenticated(rateLimitModels.ClassWrite))
			r.Use(adminmw.RequireAdminToken(infra.Cfg.Security.AdminAPIToken, infra.Log))
			authMod.Handler.RegisterAdmin(r)
			r.Post("/admin/consent/users/{user_id}/revoke-all", consentMod.Handler.HandleAdminRevokeAllConsents)
			tenantMod.Handler.Register(r)
		})
	}
}

// setupAdminRouter creates a router for the admin server
func setupAdminRouter(log *slog.Logger, adminSvc *admin.Service, tenantHandler *tenantHandler.Handler, cfg *config.Server, rateLimitMw *rateLimitMW.Middleware) *chi.Mux {
	r := chi.NewRouter()

	// Common middleware for all routes
	r.Use(requesttime.Middleware)
	r.Use(request.Recovery(log))
	r.Use(request.RequestID)
	r.Use(request.Logger(log))
	r.Use(request.Timeout(30 * time.Second))
	r.Use(request.ContentTypeJSON)
	r.Use(request.BodyLimit(validation.MaxBodySize))

	// Health check and metrics
	r.Handle("/metrics", promhttp.Handler())
	healthHandler := health.New(cfg.Environment)
	healthHandler.Register(r)

	// All admin routes require authentication and rate limiting
	adminHandler := admin.New(adminSvc, log)
	r.Group(func(r chi.Router) {
		r.Use(rateLimitMw.RateLimit(rateLimitModels.ClassAdmin)) // Rate limit before auth to prevent brute-force
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

// waitForShutdown waits for an interrupt signal and gracefully shuts down all servers and workers
func waitForShutdown(servers []*http.Server, infra *infraBundle, cancel context.CancelFunc) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	infra.Log.Info("shutting down gracefully")
	if cancel != nil {
		cancel()
	}

	ctx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop Phase 2 workers first (drain outbox, flush Kafka)
	stopPhase2Workers(ctx, infra)

	// Shutdown all HTTP servers
	for _, srv := range servers {
		if srv != nil {
			if err := srv.Shutdown(ctx); err != nil {
				infra.Log.Error("server shutdown failed", "addr", srv.Addr, "error", err)
			}
		}
	}

	// Close Phase 2 infrastructure
	closePhase2Infra(infra)

	infra.Log.Info("shutdown complete")
}

// stopPhase2Workers gracefully stops the outbox worker and Kafka consumer.
func stopPhase2Workers(ctx context.Context, infra *infraBundle) {
	if infra.OutboxWorker != nil {
		if err := infra.OutboxWorker.Stop(ctx); err != nil {
			infra.Log.Error("outbox worker shutdown failed", "error", err)
		} else {
			infra.Log.Info("outbox worker stopped")
		}
	}

	if infra.KafkaConsumer != nil {
		if err := infra.KafkaConsumer.Stop(ctx); err != nil {
			infra.Log.Error("kafka consumer shutdown failed", "error", err)
		} else {
			infra.Log.Info("kafka consumer stopped")
		}
	}
}

// closePhase2Infra closes database and Kafka connections.
func closePhase2Infra(infra *infraBundle) {
	if infra.KafkaProducer != nil {
		if err := infra.KafkaProducer.Close(); err != nil {
			infra.Log.Error("kafka producer close failed", "error", err)
		} else {
			infra.Log.Info("kafka producer closed")
		}
	}

	if infra.DBPool != nil {
		if err := infra.DBPool.Close(); err != nil {
			infra.Log.Error("database close failed", "error", err)
		} else {
			infra.Log.Info("database closed")
		}
	}
}
