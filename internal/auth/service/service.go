package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

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
)

// TokenRevocationList manages revoked access tokens by JTI.
// Production systems should use Redis for distributed revocation.
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
// Error Contract: All Find methods return store.ErrNotFound when the entity doesn't exist.
type SessionStore interface {
	Create(ctx context.Context, session *models.Session) error
	FindByID(ctx context.Context, sessionID id.SessionID) (*models.Session, error)
	ListByUser(ctx context.Context, userID id.UserID) ([]*models.Session, error)
	UpdateSession(ctx context.Context, session *models.Session) error
	DeleteSessionsByUser(ctx context.Context, userID id.UserID) error
	RevokeSession(ctx context.Context, sessionID id.SessionID) error
	RevokeSessionIfActive(ctx context.Context, sessionID id.SessionID, now time.Time) error
	AdvanceLastSeen(ctx context.Context, sessionID id.SessionID, clientID string, at time.Time, accessTokenJTI string, activate bool, deviceID string, deviceFingerprintHash string) (*models.Session, error)
	AdvanceLastRefreshed(ctx context.Context, sessionID id.SessionID, clientID string, at time.Time, accessTokenJTI string, deviceID string, deviceFingerprintHash string) (*models.Session, error)
}

type AuthCodeStore interface {
	Create(ctx context.Context, authCode *models.AuthorizationCodeRecord) error
	FindByCode(ctx context.Context, code string) (*models.AuthorizationCodeRecord, error)
	MarkUsed(ctx context.Context, code string) error
	ConsumeAuthCode(ctx context.Context, code string, redirectURI string, now time.Time) (*models.AuthorizationCodeRecord, error)
	DeleteExpiredCodes(ctx context.Context) (int, error)
}

type RefreshTokenStore interface {
	Create(ctx context.Context, token *models.RefreshTokenRecord) error
	FindBySessionID(ctx context.Context, sessionID id.SessionID) (*models.RefreshTokenRecord, error)
	Find(ctx context.Context, tokenString string) (*models.RefreshTokenRecord, error)
	ConsumeRefreshToken(ctx context.Context, token string, now time.Time) (*models.RefreshTokenRecord, error)
	DeleteBySessionID(ctx context.Context, sessionID id.SessionID) error
}

type TokenGenerator interface {
	GenerateAccessToken(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID, clientID string, tenantID string, scopes []string) (string, error)
	GenerateAccessTokenWithJTI(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID, clientID string, tenantID string, scopes []string) (string, string, error)
	GenerateIDToken(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID, clientID string, tenantID string) (string, error)
	CreateRefreshToken() (string, error)
	// ParseTokenSkipClaimsValidation parses a JWT with signature verification but skips claims validation (e.g., expiration)
	// This is used for token revocation where we need to verify the signature but accept expired tokens
	ParseTokenSkipClaimsValidation(token string) (*jwttoken.AccessTokenClaims, error)
}

type AuditPublisher interface {
	Emit(ctx context.Context, base audit.Event) error
}

type ClientResolver interface {
	// ResolveClient maps client_id -> client and tenant as a single choke point.
	// If the client or tenant is inactive, returns an invalid_client error.
	ResolveClient(ctx context.Context, clientID string) (*tenant.Client, *tenant.Tenant, error)
}

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

type Config struct {
	SessionTTL             time.Duration
	TokenTTL               time.Duration
	RefreshTokenTTL        time.Duration
	AllowedRedirectSchemes []string
	DeviceBindingEnabled   bool
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
}

type tokenArtifacts struct {
	accessToken    string
	accessTokenJTI string
	idToken        string
	refreshToken   string
	refreshRecord  *models.RefreshTokenRecord
}

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
	t.mu.Lock(key)
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

func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		s.logger = logger
	}
}

func WithAuditPublisher(publisher AuditPublisher) Option {
	return func(s *Service) {
		s.auditPublisher = publisher
	}
}

func WithMetrics(m *metrics.Metrics) Option {
	return func(s *Service) {
		s.metrics = m
	}
}

func WithAuthStoreTx(tx *shardedAuthTx) Option {
	return func(s *Service) {
		s.tx = tx
	}
}

func WithDeviceBindingEnabled(enabled bool) Option {
	return func(s *Service) {
		s.DeviceBindingEnabled = enabled
	}
}

func WithTRL(trl TokenRevocationList) Option {
	return func(s *Service) {
		s.trl = trl
	}
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
	if users == nil || sessions == nil || codes == nil || refreshTokens == nil {
		return nil, fmt.Errorf("users, sessions, codes, and refreshTokens stores are required")
	}
	if jwt == nil {
		return nil, fmt.Errorf("token generator (jwt) is required")
	}
	if clientResolver == nil {
		return nil, fmt.Errorf("client resolver is required")
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

	now := time.Now()
	tokenRecord, err := models.NewRefreshToken(
		refreshToken,
		session.ID,
		now,
		now.Add(s.RefreshTokenTTL),
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
