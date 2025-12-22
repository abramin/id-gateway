package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"credo/internal/auth/device"
	"credo/internal/auth/models"
	"credo/internal/auth/store/revocation"
	sessionStore "credo/internal/auth/store/session"
	jwttoken "credo/internal/jwt_token"
	tenant "credo/internal/tenant/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/attrs"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/metrics"
	request "credo/pkg/platform/middleware/request"
	"credo/pkg/platform/sentinel"
)

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
	ResolveClient(ctx context.Context, clientID string) (*tenant.Client, *tenant.Tenant, error)
}

type Service struct {
	users          UserStore
	sessions       SessionStore
	codes          AuthCodeStore
	refreshTokens  RefreshTokenStore
	tx             AuthStoreTx
	deviceService  *device.Service
	trl            revocation.TokenRevocationList
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

type tokenArtifacts struct {
	accessToken    string
	accessTokenJTI string
	idToken        string
	refreshToken   string
	refreshRecord  *models.RefreshTokenRecord
}

type Option func(*Service)

// TxAuthStores groups the stores used inside a transaction.
type TxAuthStores struct {
	Users         UserStore
	Codes         AuthCodeStore
	Sessions      SessionStore
	RefreshTokens RefreshTokenStore
}

// shardedAuthTx provides fine-grained locking using sharded mutexes.
// Instead of a single global lock, operations are distributed across N shards
// based on a hash of the resource key, reducing contention under concurrent load.
const numAuthShards = 32

// defaultTxTimeout is the maximum duration for a transaction before it's aborted.
const defaultTxTimeout = 5 * time.Second

type shardedAuthTx struct {
	shards  [numAuthShards]sync.Mutex
	stores  TxAuthStores
	timeout time.Duration
}

// RunInTx acquires a shard lock based on context and executes the transaction.
// Falls back to shard 0 if no session key is in context.
// Enforces a timeout to prevent runaway operations.
func (t *shardedAuthTx) RunInTx(ctx context.Context, fn func(stores TxAuthStores) error) error {
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

	shard := t.selectShard(ctx)
	t.shards[shard].Lock()
	defer t.shards[shard].Unlock()

	// Check again after acquiring lock
	if err := ctx.Err(); err != nil {
		return dErrors.Wrap(err, dErrors.CodeTimeout, "transaction aborted: context cancelled")
	}

	return fn(t.stores)
}

// selectShard picks a shard based on session ID from context, or defaults to shard 0.
func (t *shardedAuthTx) selectShard(ctx context.Context) int {
	// Try to get session ID from context for consistent sharding
	if sessionID, ok := ctx.Value(txSessionKeyCtx).(string); ok && sessionID != "" {
		return int(hashString(sessionID) % numAuthShards)
	}
	return 0
}

// hashString provides a simple hash for shard selection.
func hashString(s string) uint32 {
	var h uint32
	for i := 0; i < len(s); i++ {
		h = h*31 + uint32(s[i])
	}
	return h
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

func WithJWTService(jwtService TokenGenerator) Option {
	return func(s *Service) {
		s.jwt = jwtService
	}
}

func WithAuthStoreTx(tx AuthStoreTx) Option {
	return func(s *Service) {
		s.tx = tx
	}
}

func WithDeviceBindingEnabled(enabled bool) Option {
	return func(s *Service) {
		s.DeviceBindingEnabled = enabled
	}
}

func WithTRL(trl revocation.TokenRevocationList) Option {
	return func(s *Service) {
		s.trl = trl
	}
}

func WithClientResolver(resolver ClientResolver) Option {
	return func(s *Service) {
		s.clientResolver = resolver
	}
}

func New(
	users UserStore,
	sessions SessionStore,
	codes AuthCodeStore,
	refreshTokens RefreshTokenStore,
	cfg *Config,
	opts ...Option,
) (*Service, error) {
	if users == nil || sessions == nil || codes == nil || refreshTokens == nil {
		return nil, fmt.Errorf("users, sessions, codes, and refreshTokens stores are required")
	}
	if cfg == nil {
		cfg = &Config{}
	}
	// Defaults for required config
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = defaultTokenTTL
	}
	if cfg.RefreshTokenTTL <= 0 {
		cfg.RefreshTokenTTL = defaultRefreshTokenTTL
	}
	if len(cfg.AllowedRedirectSchemes) == 0 {
		cfg.AllowedRedirectSchemes = []string{"https"}
	}

	svc := &Service{
		users:         users,
		sessions:      sessions,
		codes:         codes,
		refreshTokens: refreshTokens,
		tx: &shardedAuthTx{
			stores: TxAuthStores{
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

	if svc.jwt == nil {
		return nil, fmt.Errorf("token generator (jwt) is required")
	}

	if svc.deviceService == nil {
		svc.deviceService = device.NewService(svc.DeviceBindingEnabled)
	}

	if svc.trl == nil {
		svc.trl = revocation.NewInMemoryTRL()
	}

	return svc, nil
}

func (s *Service) logAudit(ctx context.Context, event string, attributes ...any) {
	// Add request_id from context if available
	if requestID := request.GetRequestID(ctx); requestID != "" {
		attributes = append(attributes, "request_id", requestID)
	}
	args := append(attributes, "event", event, "log_type", "audit")
	if s.logger != nil {
		s.logger.InfoContext(ctx, event, args...)
	}
	if s.auditPublisher == nil {
		return
	}
	userIDStr := attrs.ExtractString(attributes, "user_id")
	userID, _ := id.ParseUserID(userIDStr) // Best-effort for audit - ignore parse errors
	// TODO: log errors from audit publisher?
	_ = s.auditPublisher.Emit(ctx, audit.Event{
		UserID:  userID,
		Subject: userIDStr,
		Action:  event,
	})
}

func (s *Service) authFailure(ctx context.Context, reason string, isError bool, attributes ...any) {
	s.logAuthFailure(ctx, reason, isError, attributes...)
	if s.metrics != nil {
		s.metrics.IncrementAuthFailures()
	}
}

func (s *Service) logAuthFailure(ctx context.Context, reason string, isError bool, attributes ...any) {
	// Add request_id from context if available
	if requestID := request.GetRequestID(ctx); requestID != "" {
		attributes = append(attributes, "request_id", requestID)
	}
	args := append(attributes, "event", audit.EventAuthFailed, "reason", reason, "log_type", "standard")
	if s.logger == nil {
		return
	}
	if isError {
		s.logger.ErrorContext(ctx, string(audit.EventAuthFailed), args...)
		return
	}
	s.logger.WarnContext(ctx, string(audit.EventAuthFailed), args...)
}

// incrementUserCreated increments the users created metric if metrics are enabled
func (s *Service) incrementUserCreated() {
	if s.metrics != nil {
		s.metrics.IncrementUsersCreated()
	}
}

// incrementActiveSession increments the active sessions metric if metrics are enabled
func (s *Service) incrementActiveSession() {
	if s.metrics != nil {
		s.metrics.IncrementActiveSessions(1)
	}
}

// incrementTokenRequests increments the token requests metric if metrics are enabled
func (s *Service) incrementTokenRequests() {
	if s.metrics != nil {
		s.metrics.IncrementTokenRequests()
	}
}

func (s *Service) isRedirectSchemeAllowed(uri *url.URL) bool {
	for _, scheme := range s.AllowedRedirectSchemes {
		if strings.EqualFold(uri.Scheme, scheme) {
			return true
		}
	}
	return false
}

// tokenErrorMapping defines how a sentinel error maps to a domain error.
type tokenErrorMapping struct {
	sentinel   error
	code       dErrors.Code
	codeMsg    string // message for TokenFlowCode (empty = use err.Error())
	refreshMsg string // message for TokenFlowRefresh (empty = use err.Error())
	logReason  string
}

// tokenErrorMappings defines error translations in priority order.
// First match wins; more specific errors should come first.
// Note: Domain-errors from validation are passed through directly (see handleTokenError).
var tokenErrorMappings = []tokenErrorMapping{
	{sentinel.ErrNotFound, dErrors.CodeInvalidGrant, "invalid authorization code", "invalid refresh token", "not_found"},
	{sentinel.ErrExpired, dErrors.CodeInvalidGrant, "authorization code expired", "refresh token expired", "expired"},
	{sentinel.ErrAlreadyUsed, dErrors.CodeInvalidGrant, "authorization code already used", "invalid refresh token", "already_used"},
	{sessionStore.ErrSessionRevoked, dErrors.CodeInvalidGrant, "session has been revoked", "session has been revoked", "session_revoked"},
	{sentinel.ErrInvalidState, dErrors.CodeInvalidGrant, "session not active", "session not active", "invalid_state"},
}

// handleTokenError translates dependency errors into domain errors.
// Uses tokenErrorMappings to determine error code and user-facing message based on flow type.
func (s *Service) handleTokenError(ctx context.Context, err error, clientID string, recordID *string, flow TokenFlow) error {
	if err == nil {
		return nil
	}

	attrs := []any{"client_id", clientID}
	if recordID != nil {
		attrs = append(attrs, "record_id", *recordID)
	}

	// Pass through existing domain errors
	var de *dErrors.Error
	if errors.As(err, &de) {
		s.authFailure(ctx, string(de.Code), false, attrs...)
		return err
	}

	// Check mappings in order
	for _, m := range tokenErrorMappings {
		if errors.Is(err, m.sentinel) {
			msg := m.codeMsg
			if flow == TokenFlowRefresh {
				msg = m.refreshMsg
			}
			if msg == "" {
				msg = err.Error()
			}
			s.authFailure(ctx, m.logReason, false, attrs...)
			return dErrors.Wrap(err, m.code, msg)
		}
	}

	// Default: internal error
	s.authFailure(ctx, "internal_error", true, attrs...)
	return dErrors.Wrap(err, dErrors.CodeInternal, "token handling failed")
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
