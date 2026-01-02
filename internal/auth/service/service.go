package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"credo/internal/auth/device"
	"credo/internal/auth/metrics"
	"credo/internal/auth/models"
	"credo/internal/auth/store/revocation"
	jwttoken "credo/internal/jwt_token"
	tenant "credo/internal/tenant/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	platformsync "credo/pkg/platform/sync"
	"credo/pkg/requestcontext"
)

// Shard contention metrics for monitoring lock behavior
var (
	authShardLockWaitDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "credo_auth_shard_lock_wait_seconds",
		Help:    "Time spent waiting to acquire auth shard lock",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	})
	authShardLockAcquisitions = promauto.NewCounter(prometheus.CounterOpts{
		Name: "credo_auth_shard_lock_acquisitions_total",
		Help: "Total number of auth shard lock acquisitions",
	})
)

// TokenRevocationList manages revoked access tokens by JTI.
// Production systems should use a persistent, shared store (PostgreSQL or Redis).
type TokenRevocationList interface {
	RevokeToken(ctx context.Context, jti string, ttl time.Duration) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
	RevokeSessionTokens(ctx context.Context, sessionID string, jtis []string, ttl time.Duration) error
}

// UserStore defines the persistence interface for user data.
// Error Contract: All Find methods return store.ErrNotFound when the entity doesn't exist.
type UserStore interface {
	Save(ctx context.Context, user *models.User) error
	FindByID(ctx context.Context, userID id.UserID) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindOrCreateByTenantAndEmail(ctx context.Context, tenantID id.TenantID, email string, user *models.User) (*models.User, error)
	Delete(ctx context.Context, userID id.UserID) error
}

// SessionStore defines the persistence interface for session data.
// Error Contract:
//   - All Find methods return sentinel.ErrNotFound when the entity doesn't exist.
//   - Execute() returns sentinel.ErrNotFound if session doesn't exist, or passes through
//     any error returned by the validate callback (typically domain errors).
type SessionStore interface {
	Create(ctx context.Context, session *models.Session) error
	FindByID(ctx context.Context, sessionID id.SessionID) (*models.Session, error)
	ListByUser(ctx context.Context, userID id.UserID) ([]*models.Session, error)
	UpdateSession(ctx context.Context, session *models.Session) error
	DeleteSessionsByUser(ctx context.Context, userID id.UserID) error
	RevokeSession(ctx context.Context, sessionID id.SessionID) error
	RevokeSessionIfActive(ctx context.Context, sessionID id.SessionID, now time.Time) error

	// Execute atomically validates and mutates a session under lock.
	// The validate callback should return domain errors for validation failures.
	// The mutate callback applies changes to the session.
	// Returns the mutated session on success.
	Execute(ctx context.Context, sessionID id.SessionID, validate func(*models.Session) error, mutate func(*models.Session)) (*models.Session, error)
}

// AuthCodeStore defines persistence operations for authorization codes and their lifecycle.
// Error Contract:
//   - FindByCode returns sentinel.ErrNotFound when code doesn't exist.
//   - Execute returns sentinel.ErrNotFound if code doesn't exist, or passes through
//     any error returned by the validate callback (typically domain errors).
//     On validation failure, the record is still returned (for replay attack detection).
type AuthCodeStore interface {
	Create(ctx context.Context, authCode *models.AuthorizationCodeRecord) error
	FindByCode(ctx context.Context, code string) (*models.AuthorizationCodeRecord, error)
	MarkUsed(ctx context.Context, code string) error
	DeleteExpiredCodes(ctx context.Context, now time.Time) (int, error)

	// Execute atomically validates and mutates an auth code under lock.
	// Returns (record, nil) on success, (record, error) on validation failure,
	// or (nil, sentinel.ErrNotFound) if code doesn't exist.
	Execute(ctx context.Context, code string, validate func(*models.AuthorizationCodeRecord) error, mutate func(*models.AuthorizationCodeRecord)) (*models.AuthorizationCodeRecord, error)
}

// RefreshTokenStore defines persistence operations for refresh tokens, including rotation.
// Error Contract:
//   - Find returns sentinel.ErrNotFound when token doesn't exist.
//   - Execute returns sentinel.ErrNotFound if token doesn't exist, or passes through
//     any error returned by the validate callback (typically domain errors).
//     On validation failure, the record is still returned (for replay attack detection).
type RefreshTokenStore interface {
	Create(ctx context.Context, token *models.RefreshTokenRecord) error
	FindBySessionID(ctx context.Context, sessionID id.SessionID, now time.Time) (*models.RefreshTokenRecord, error)
	Find(ctx context.Context, tokenString string) (*models.RefreshTokenRecord, error)
	DeleteBySessionID(ctx context.Context, sessionID id.SessionID) error

	// Execute atomically validates and mutates a refresh token under lock.
	// Returns (record, nil) on success, (record, error) on validation failure,
	// or (nil, sentinel.ErrNotFound) if token doesn't exist.
	Execute(ctx context.Context, token string, validate func(*models.RefreshTokenRecord) error, mutate func(*models.RefreshTokenRecord)) (*models.RefreshTokenRecord, error)
}

// TokenGenerator issues signed access/ID tokens and generates refresh tokens.
type TokenGenerator interface {
	GenerateAccessToken(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID, clientID string, tenantID string, scopes []string) (string, error)
	GenerateAccessTokenWithJTI(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID, clientID string, tenantID string, scopes []string) (string, string, error)
	GenerateIDToken(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID, clientID string, tenantID string) (string, error)
	CreateRefreshToken() (string, error)
	// ParseTokenSkipClaimsValidation parses a JWT with signature verification but skips claims validation (e.g., expiration)
	// This is used for token revocation where we need to verify the signature but accept expired tokens
	ParseTokenSkipClaimsValidation(token string) (*jwttoken.AccessTokenClaims, error)
}

// AuditPublisher emits auth-related audit events.
type AuditPublisher interface {
	Emit(ctx context.Context, base audit.Event) error
}

// ClientResolver resolves client metadata and tenant ownership for a client ID.
type ClientResolver interface {
	// ResolveClient maps client_id -> client and tenant as a single choke point.
	// If the client or tenant is inactive, returns an invalid_client error.
	ResolveClient(ctx context.Context, clientID string) (*tenant.Client, *tenant.Tenant, error)
}

// Service orchestrates auth workflows across stores, tokens, audits, and metrics.
type Service struct {
	users          UserStore
	sessions       SessionStore
	codes          AuthCodeStore
	refreshTokens  RefreshTokenStore
	tx             *shardedAuthTx
	deviceService  *device.Service
	trl            TokenRevocationList
	logger         *slog.Logger
	auditPublisher AuditPublisher
	jwt            TokenGenerator
	clientResolver ClientResolver
	metrics        *metrics.Metrics
	*Config
}

const (
	defaultSessionTTL      = 24 * time.Hour
	defaultTokenTTL        = 15 * time.Minute
	defaultRefreshTokenTTL = 30 * 24 * time.Hour
)

// TokenFlow represents the type of token operation being performed.
type TokenFlow string

const (
	TokenFlowCode    TokenFlow = "code"
	TokenFlowRefresh TokenFlow = "refresh"
)

// TRLFailureModeWarn logs TRL failures but continues (default).
const TRLFailureModeWarn = "warn"

// TRLFailureModeFail returns an error if TRL write fails.
const TRLFailureModeFail = "fail"

// Config controls auth timeouts, redirect scheme policy, and TRL behavior.
type Config struct {
	SessionTTL             time.Duration
	TokenTTL               time.Duration
	RefreshTokenTTL        time.Duration
	AllowedRedirectSchemes []string
	DeviceBindingEnabled   bool
	// TRLFailureMode controls behavior when token revocation list write fails.
	// "warn" (default): log the error and continue
	// "fail": return an error, failing the operation
	TRLFailureMode string
}

// applyDefaults sets default values for any unset config fields.
func (c *Config) applyDefaults() {
	if c.SessionTTL <= 0 {
		c.SessionTTL = defaultSessionTTL
	}
	if c.TokenTTL <= 0 {
		c.TokenTTL = defaultTokenTTL
	}
	if c.RefreshTokenTTL <= 0 {
		c.RefreshTokenTTL = defaultRefreshTokenTTL
	}
	if len(c.AllowedRedirectSchemes) == 0 {
		c.AllowedRedirectSchemes = []string{"https"}
	}
	if c.TRLFailureMode == "" {
		c.TRLFailureMode = TRLFailureModeWarn
	}
}

type tokenArtifacts struct {
	accessToken    string
	accessTokenJTI string
	idToken        string
	refreshToken   string
	refreshRecord  *models.RefreshTokenRecord
}

// Option configures Service during initialization.
type Option func(*Service)

// txAuthStores groups the stores used inside a transaction.
type txAuthStores struct {
	Users         UserStore
	Codes         AuthCodeStore
	Sessions      SessionStore
	RefreshTokens RefreshTokenStore
}

// defaultTxTimeout is the maximum duration for a transaction before it's aborted.
const defaultTxTimeout = 5 * time.Second

// shardedAuthTx provides fine-grained locking using sharded mutexes.
// Uses platform ShardedMutex for lock distribution, with auth-specific timeout handling.
type shardedAuthTx struct {
	mu      *platformsync.ShardedMutex
	stores  txAuthStores
	timeout time.Duration
}

// RunInTx acquires a shard lock based on context and executes the transaction.
// Falls back to shard 0 if no session key is in context.
// Enforces a timeout to prevent runaway operations.
func (t *shardedAuthTx) RunInTx(ctx context.Context, fn func(stores txAuthStores) error) error {
	// Check if context is already cancelled
	if err := ctx.Err(); err != nil {
		return dErrors.Wrap(err, dErrors.CodeTimeout, "transaction aborted: context cancelled")
	}

	// Apply timeout if not already set
	timeout := t.timeout
	if timeout == 0 {
		timeout = defaultTxTimeout
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Get session key for shard selection
	key := t.shardKey(ctx)

	// Record lock acquisition timing for contention monitoring
	lockStart := time.Now()
	t.mu.Lock(key)
	authShardLockWaitDuration.Observe(time.Since(lockStart).Seconds())
	authShardLockAcquisitions.Inc()
	defer t.mu.Unlock(key)

	// Check again after acquiring lock
	if err := ctx.Err(); err != nil {
		return dErrors.Wrap(err, dErrors.CodeTimeout, "transaction aborted: context cancelled")
	}

	return fn(t.stores)
}

// shardKey extracts the session ID from context for consistent sharding.
func (t *shardedAuthTx) shardKey(ctx context.Context) string {
	if sessionID, ok := ctx.Value(txSessionKeyCtx).(string); ok {
		return sessionID
	}
	return ""
}

// txSessionKey is the context key for session-based sharding.
type txSessionKey struct{}

var txSessionKeyCtx = txSessionKey{}

// WithLogger sets the logger used by auth operations.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		s.logger = logger
	}
}

// WithAuditPublisher sets the audit publisher used to emit auth events.
func WithAuditPublisher(publisher AuditPublisher) Option {
	return func(s *Service) {
		s.auditPublisher = publisher
	}
}

// WithMetrics sets the metrics recorder for auth operations.
func WithMetrics(m *metrics.Metrics) Option {
	return func(s *Service) {
		s.metrics = m
	}
}

// WithAuthStoreTx overrides the default transaction wrapper for auth stores.
func WithAuthStoreTx(tx *shardedAuthTx) Option {
	return func(s *Service) {
		s.tx = tx
	}
}

// WithDeviceBindingEnabled toggles device binding logic for session issuance.
func WithDeviceBindingEnabled(enabled bool) Option {
	return func(s *Service) {
		s.DeviceBindingEnabled = enabled
	}
}

// WithTRL sets the token revocation list implementation.
func WithTRL(trl TokenRevocationList) Option {
	return func(s *Service) {
		s.trl = trl
	}
}

// validateRequiredDeps checks that all required dependencies are provided.
func validateRequiredDeps(users UserStore, sessions SessionStore, codes AuthCodeStore, refreshTokens RefreshTokenStore, jwt TokenGenerator, clientResolver ClientResolver) error {
	if users == nil || sessions == nil || codes == nil || refreshTokens == nil {
		return fmt.Errorf("users, sessions, codes, and refreshTokens stores are required")
	}
	if jwt == nil {
		return fmt.Errorf("token generator (jwt) is required")
	}
	if clientResolver == nil {
		return fmt.Errorf("client resolver is required")
	}
	return nil
}

// New creates an auth service with required dependencies.
// Required: stores (users, sessions, codes, refreshTokens), jwt generator, and client resolver.
// Optional: logger, metrics, auditPublisher, TRL (via functional options).
func New(
	users UserStore,
	sessions SessionStore,
	codes AuthCodeStore,
	refreshTokens RefreshTokenStore,
	jwt TokenGenerator,
	clientResolver ClientResolver,
	cfg *Config,
	opts ...Option,
) (*Service, error) {
	if err := validateRequiredDeps(users, sessions, codes, refreshTokens, jwt, clientResolver); err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &Config{}
	}
	cfg.applyDefaults()

	svc := &Service{
		users:          users,
		sessions:       sessions,
		codes:          codes,
		refreshTokens:  refreshTokens,
		jwt:            jwt,
		clientResolver: clientResolver,
		tx: &shardedAuthTx{
			mu: platformsync.NewShardedMutex(),
			stores: txAuthStores{
				Users:         users,
				Codes:         codes,
				Sessions:      sessions,
				RefreshTokens: refreshTokens,
			},
		},
		Config: cfg,
	}

	for _, opt := range opts {
		opt(svc)
	}

	if svc.deviceService == nil {
		svc.deviceService = device.NewService(svc.DeviceBindingEnabled)
	}

	if svc.trl == nil {
		svc.trl = revocation.NewInMemoryTRL()
	}

	return svc, nil
}

func (s *Service) isRedirectSchemeAllowed(uri *url.URL) bool {
	for _, scheme := range s.AllowedRedirectSchemes {
		if strings.EqualFold(uri.Scheme, scheme) {
			return true
		}
	}
	return false
}

func (s *Service) generateTokenArtifacts(ctx context.Context, session *models.Session) (*tokenArtifacts, error) {
	// Generate tokens before mutating persistence state so failures do not leave partial writes.
	accessToken, accessTokenJTI, err := s.jwt.GenerateAccessTokenWithJTI(
		ctx,
		uuid.UUID(session.UserID),
		uuid.UUID(session.ID),
		session.ClientID.String(),
		session.TenantID.String(),
		session.RequestedScope,
	)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to generate access token")
	}

	idToken, err := s.jwt.GenerateIDToken(ctx, uuid.UUID(session.UserID), uuid.UUID(session.ID), session.ClientID.String(), session.TenantID.String())
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to generate ID token")
	}

	refreshToken, err := s.jwt.CreateRefreshToken()
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create refresh token")
	}

	now := requestcontext.Now(ctx)
	tokenRecord, err := models.NewRefreshToken(
		refreshToken,
		session.ID,
		now,
		now.Add(s.RefreshTokenTTL),
		now,
	)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create refresh token record")
	}

	return &tokenArtifacts{
		accessToken:    accessToken,
		accessTokenJTI: accessTokenJTI,
		idToken:        idToken,
		refreshToken:   refreshToken,
		refreshRecord:  tokenRecord,
	}, nil
}

// buildTokenResult constructs the API response from token artifacts and session scope.
func (s *Service) buildTokenResult(artifacts *tokenArtifacts, scope []string) *models.TokenResult {
	return &models.TokenResult{
		AccessToken:  artifacts.accessToken,
		IDToken:      artifacts.idToken,
		RefreshToken: artifacts.refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.TokenTTL.Seconds()),
		Scope:        strings.Join(scope, " "),
	}
}
