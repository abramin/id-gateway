package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"credo/internal/audit"
	"credo/internal/auth/device"
	"credo/internal/auth/models"
	"credo/internal/auth/store/revocation"
	"credo/internal/platform/metrics"
	"credo/internal/platform/middleware"
	"credo/pkg/attrs"
	dErrors "credo/pkg/domain-errors"
)

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
	metrics        *metrics.Metrics
	*Config
}

const (
	StatusPendingConsent       = "pending_consent"
	StatusActive               = "active"
	StatusRevoked              = "revoked"
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	defaultSessionTTL          = 24 * time.Hour
	defaultTokenTTL            = 15 * time.Minute
	defaultRefreshTokenTTL     = 30 * 24 * time.Hour
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

// AuthStoreTx provides a transactional boundary for auth-related store mutations.
// Implementations may wrap a database transaction or, in-memory, a coarse lock.
type AuthStoreTx interface {
	RunInTx(ctx context.Context, fn func(stores TxAuthStores) error) error
}

// TxAuthStores groups the stores used inside a transaction.
type TxAuthStores struct {
	Codes         AuthCodeStore
	Sessions      SessionStore
	RefreshTokens RefreshTokenStore
}

type mutexAuthTx struct {
	mu     *sync.Mutex
	stores TxAuthStores
}

func (t *mutexAuthTx) RunInTx(ctx context.Context, fn func(stores TxAuthStores) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return fn(t.stores)
}

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

func (s *Service) generateTokenArtifacts(session *models.Session) (*tokenArtifacts, error) {
	// Generate tokens before mutating persistence state so failures do not leave partial writes.
	accessToken, accessTokenJTI, err := s.jwt.GenerateAccessTokenWithJTI(session.UserID, session.ID, session.ClientID, session.RequestedScope)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to generate access token")
	}

	idToken, err := s.jwt.GenerateIDToken(session.UserID, session.ID, session.ClientID)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to generate ID token")
	}

	refreshToken, err := s.jwt.CreateRefreshToken()
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create refresh token")
	}

	now := time.Now()
	tokenRecord := &models.RefreshTokenRecord{
		Token:           refreshToken,
		SessionID:       session.ID,
		CreatedAt:       now,
		LastRefreshedAt: nil,
		ExpiresAt:       now.Add(s.RefreshTokenTTL), // 30 days
		Used:            false,
	}

	return &tokenArtifacts{
		accessToken:    accessToken,
		accessTokenJTI: accessTokenJTI,
		idToken:        idToken,
		refreshToken:   refreshToken,
		refreshRecord:  tokenRecord,
	}, nil
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
		tx:            &mutexAuthTx{mu: &sync.Mutex{}, stores: TxAuthStores{Codes: codes, Sessions: sessions, RefreshTokens: refreshTokens}},
		Config:        cfg,
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
	if requestID := middleware.GetRequestID(ctx); requestID != "" {
		attributes = append(attributes, "request_id", requestID)
	}
	args := append(attributes, "event", event, "log_type", "audit")
	if s.logger != nil {
		s.logger.InfoContext(ctx, event, args...)
	}
	if s.auditPublisher == nil {
		return
	}
	userID := attrs.ExtractString(attributes, "user_id")
	_ = s.auditPublisher.Emit(ctx, audit.Event{
		UserID:  userID,
		Subject: userID,
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
	if requestID := middleware.GetRequestID(ctx); requestID != "" {
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
