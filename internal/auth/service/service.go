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

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"credo/internal/audit"
	"credo/internal/auth/device"
	"credo/internal/auth/models"
	"credo/internal/auth/store/revocation"
	sessionStore "credo/internal/auth/store/session"
	userStore "credo/internal/auth/store/user"
	jwttoken "credo/internal/jwt_token"
	"credo/internal/platform/metrics"
	"credo/internal/platform/middleware"
	"credo/pkg/attrs"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/email"
)

// UserStore defines the persistence interface for user data.
// Error Contract: All Find methods return store.ErrNotFound when the entity doesn't exist.
type UserStore interface {
	Save(ctx context.Context, user *models.User) error
	FindByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindOrCreateByEmail(ctx context.Context, email string, user *models.User) (*models.User, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// SessionStore defines the persistence interface for session data.
// Error Contract: All Find methods return store.ErrNotFound when the entity doesn't exist.
type SessionStore interface {
	Create(ctx context.Context, session *models.Session) error
	FindByID(ctx context.Context, id uuid.UUID) (*models.Session, error)
	UpdateSession(ctx context.Context, session *models.Session) error
	DeleteSessionsByUser(ctx context.Context, userID uuid.UUID) error
	RevokeSession(ctx context.Context, id uuid.UUID) error
}

type AuthCodeStore interface {
	Create(ctx context.Context, authCode *models.AuthorizationCodeRecord) error
	FindByCode(ctx context.Context, code string) (*models.AuthorizationCodeRecord, error)
	MarkUsed(ctx context.Context, code string) error
	Delete(ctx context.Context, code string) error
	DeleteExpiredCodes(ctx context.Context) (int, error)
}

type RefreshTokenStore interface {
	Create(ctx context.Context, token *models.RefreshTokenRecord) error
	FindBySessionID(ctx context.Context, id uuid.UUID) (*models.RefreshTokenRecord, error)
	Find(ctx context.Context, tokenString string) (*models.RefreshTokenRecord, error)
	Consume(ctx context.Context, token string, timestamp time.Time) error
	DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) error
}

type TokenGenerator interface {
	GenerateAccessToken(userID uuid.UUID, sessionID uuid.UUID, clientID string) (string, error)
	GenerateIDToken(userID uuid.UUID, sessionID uuid.UUID, clientID string) (string, error)
	CreateRefreshToken() (string, error)
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

type AuditPublisher interface {
	Emit(ctx context.Context, base audit.Event) error
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

func (s *Service) Authorize(ctx context.Context, req *models.AuthorizationRequest) (*models.AuthorizationResult, error) {
	parsedURI, err := url.Parse(req.RedirectURI)
	if err != nil {
		return nil, dErrors.New(dErrors.CodeBadRequest, "invalid redirect_uri")
	}
	if !s.isRedirectSchemeAllowed(parsedURI) {
		return nil, dErrors.New(dErrors.CodeBadRequest, fmt.Sprintf("redirect_uri scheme '%s' not allowed", parsedURI.Scheme))
	}

	firstName, lastName := email.DeriveNameFromEmail(req.Email)
	newUser := &models.User{
		ID:        uuid.New(),
		Email:     req.Email,
		FirstName: firstName,
		LastName:  lastName,
		Verified:  false,
	}
	user, err := s.users.FindOrCreateByEmail(ctx, req.Email, newUser)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find or create user")
	}
	if user.ID == newUser.ID {
		s.logAudit(ctx, string(audit.EventUserCreated),
			"user_id", user.ID.String(),
			"client_id", req.ClientID,
		)
		s.incrementUserCreated()
	}

	now := time.Now()
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{models.ScopeOpenID.String()}
	}

	// Generate OAuth 2.0 authorization code
	authCode := &models.AuthorizationCodeRecord{
		Code:        "authz_" + uuid.New().String(),
		SessionID:   uuid.New(),
		RedirectURI: req.RedirectURI,
		ExpiresAt:   now.Add(10 * time.Minute),
		Used:        false,
		CreatedAt:   now,
	}

	if err := s.codes.Create(ctx, authCode); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to save authorization code")
	}

	userAgent := middleware.GetUserAgent(ctx)
	deviceDisplayName := device.ParseUserAgent(userAgent)

	deviceID := ""
	deviceIDToSet := ""
	if s.DeviceBindingEnabled {
		deviceID = middleware.GetDeviceID(ctx)
		if deviceID == "" {
			deviceID = s.deviceService.GenerateDeviceID()
			deviceIDToSet = deviceID
		}
	}

	deviceFingerprint := s.deviceService.ComputeFingerprint(userAgent)

	newSession := &models.Session{
		ID:                    authCode.SessionID,
		UserID:                user.ID,
		ClientID:              req.ClientID,
		RequestedScope:        scopes,
		DeviceID:              deviceID,
		DeviceFingerprintHash: deviceFingerprint,
		DeviceDisplayName:     deviceDisplayName,
		ApproximateLocation:   "",
		Status:                StatusPendingConsent,
		CreatedAt:             now,
		ExpiresAt:             now.Add(s.SessionTTL),
		LastSeenAt:            now,
	}

	err = s.sessions.Create(ctx, newSession)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to save session")
	}
	s.logAudit(ctx, string(audit.EventSessionCreated),
		"user_id", user.ID.String(),
		"session_id", newSession.ID.String(),
		"client_id", req.ClientID,
	)
	s.incrementActiveSession()

	query := parsedURI.Query()
	query.Set("code", authCode.Code) // OAuth 2.0: return authorization code, not session_id
	if req.State != "" {
		query.Set("state", req.State)
	}
	parsedURI.RawQuery = query.Encode()
	redirectURI := parsedURI.String()
	res := &models.AuthorizationResult{
		Code:        authCode.Code,
		RedirectURI: redirectURI,
		DeviceID:    deviceIDToSet,
	}

	return res, nil
}

func (s *Service) UserInfo(ctx context.Context, sessionID string) (*models.UserInfoResult, error) {
	if sessionID == "" {
		s.authFailure(ctx, "missing_session_id", false)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "missing or invalid session")
	}

	parsedSessionID, err := uuid.Parse(sessionID)
	if err != nil {
		s.authFailure(ctx, "invalid_session_id_format", false,
			"session_id", sessionID,
			"error", err,
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid session ID")
	}

	session, err := s.sessions.FindByID(ctx, parsedSessionID)
	if err != nil {
		if errors.Is(err, sessionStore.ErrNotFound) {
			s.authFailure(ctx, "session_not_found", false,
				"session_id", parsedSessionID.String(),
			)
			return nil, dErrors.New(dErrors.CodeUnauthorized, "session not found")
		}
		s.authFailure(ctx, "session_lookup_failed", true,
			"session_id", parsedSessionID.String(),
			"error", err,
		)
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find session")
	}

	if session.Status != StatusActive {
		s.authFailure(ctx, "session_not_active", false,
			"session_id", parsedSessionID.String(),
			"status", session.Status,
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "session not active")
	}

	user, err := s.users.FindByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, userStore.ErrNotFound) {
			s.authFailure(ctx, "user_not_found", false,
				"session_id", parsedSessionID.String(),
				"user_id", session.UserID.String(),
			)
			return nil, dErrors.New(dErrors.CodeUnauthorized, "user not found")
		}
		s.authFailure(ctx, "user_lookup_failed", true,
			"session_id", parsedSessionID.String(),
			"user_id", session.UserID.String(),
			"error", err,
		)
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find user")
	}

	userInfo := &models.UserInfoResult{
		Sub:           user.ID.String(),
		Email:         user.Email,
		EmailVerified: user.Verified,
		GivenName:     user.FirstName,
		FamilyName:    user.LastName,
		Name:          user.FirstName + " " + user.LastName,
	}
	s.logAudit(ctx, string(audit.EventUserInfoAccessed),
		"user_id", user.ID.String(),
		"session_id", session.ID.String(),
	)

	return userInfo, nil
}

func (s *Service) Token(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	if err := s.validateTokenRequest(req); err != nil {
		return nil, err
	}

	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return s.exchangeAuthorizationCode(ctx, req)
	case GrantTypeRefreshToken:
		return s.refreshWithRefreshToken(ctx, req)
	default:
		return nil, dErrors.New(dErrors.CodeBadRequest, "unsupported grant_type")
	}
}

type tokenArtifacts struct {
	accessToken   string
	idToken       string
	refreshToken  string
	refreshRecord *models.RefreshTokenRecord
}

func (s *Service) validateTokenRequest(req *models.TokenRequest) error {
	if req == nil {
		return dErrors.New(dErrors.CodeBadRequest, "invalid request")
	}
	if strings.TrimSpace(req.GrantType) == "" {
		return dErrors.New(dErrors.CodeValidation, "grant_type is required")
	}
	if strings.TrimSpace(req.ClientID) == "" {
		return dErrors.New(dErrors.CodeValidation, "client_id is required")
	}

	switch req.GrantType {
	case "authorization_code":
		if strings.TrimSpace(req.Code) == "" {
			return dErrors.New(dErrors.CodeValidation, "code is required")
		}
		if strings.TrimSpace(req.RedirectURI) == "" {
			return dErrors.New(dErrors.CodeValidation, "redirect_uri is required")
		}
	case "refresh_token":
		if strings.TrimSpace(req.RefreshToken) == "" {
			return dErrors.New(dErrors.CodeValidation, "refresh_token is required")
		}
	default:
		// OAuth 2.0: unsupported_grant_type
		return dErrors.New(dErrors.CodeBadRequest, "unsupported grant_type")
	}

	return nil
}

func (s *Service) exchangeAuthorizationCode(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	codeRecord, err := s.findAuthorizationCode(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := s.validateAuthorizationCode(ctx, req, codeRecord); err != nil {
		return nil, err
	}

	session, err := s.findSessionForCode(ctx, req, codeRecord)
	if err != nil {
		return nil, err
	}
	if err := s.validateSessionForTokenExchange(ctx, req, session); err != nil {
		return nil, err
	}

	mutableSession := *session
	s.applyDeviceBinding(ctx, &mutableSession)
	// Used for session management UI / risk signals.
	mutableSession.LastSeenAt = time.Now()

	// Transition from pending_consent to active on first successful exchange.
	if mutableSession.Status == StatusPendingConsent {
		mutableSession.Status = StatusActive
	}

	artifacts, err := s.generateTokenArtifacts(&mutableSession)
	if err != nil {
		return nil, err
	}
	if err := s.persistTokenExchange(ctx, &mutableSession, codeRecord, artifacts.refreshRecord); err != nil {
		return nil, err
	}

	s.logAudit(ctx,
		string(audit.EventTokenIssued),
		"session_id", mutableSession.ID.String(),
		"user_id", mutableSession.UserID.String(),
		"client_id", mutableSession.ClientID,
	)
	s.incrementTokenRequests()

	return &models.TokenResult{
		AccessToken:  artifacts.accessToken,
		IDToken:      artifacts.idToken,
		RefreshToken: artifacts.refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.TokenTTL, // Access token TTL
	}, nil
}

func (s *Service) refreshWithRefreshToken(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	refreshRecord, err := s.refreshTokens.Find(ctx, req.RefreshToken)
	if err != nil {
		if dErrors.Is(err, dErrors.CodeNotFound) {
			s.authFailure(ctx, "refresh_token_not_found", false,
				"client_id", req.ClientID,
			)
			return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid refresh token")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find refresh token")
	}

	// TODO:
	// “Reused refresh token → revoke entire session family”: no —
	// reuse returns 401 but does not revoke the session (or its refresh tokens).
	if refreshRecord.Used {
		s.authFailure(ctx, "refresh_token_reused", false,
			"client_id", req.ClientID,
			"session_id", refreshRecord.SessionID.String(),
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid refresh token")
	}

	if time.Now().After(refreshRecord.ExpiresAt) {
		s.authFailure(ctx, "refresh_token_expired", false,
			"client_id", req.ClientID,
			"session_id", refreshRecord.SessionID.String(),
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "refresh token expired")
	}

	session, err := s.sessions.FindByID(ctx, refreshRecord.SessionID)
	if err != nil {
		if dErrors.Is(err, dErrors.CodeNotFound) {
			s.authFailure(ctx, "session_not_found_for_refresh_token", false,
				"client_id", req.ClientID,
				"session_id", refreshRecord.SessionID.String(),
			)
			return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid refresh token")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find session")
	}

	if session.Status == StatusRevoked {
		s.authFailure(ctx, "session_revoked", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "session has been revoked")
	}

	if req.ClientID != session.ClientID {
		s.authFailure(ctx, "client_id_mismatch", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"expected_client_id", session.ClientID,
			"provided_client_id", req.ClientID,
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "client_id mismatch")
	}

	if time.Now().After(session.ExpiresAt) {
		s.authFailure(ctx, "session_expired", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "session expired")
	}

	mutableSession := *session
	s.applyDeviceBinding(ctx, &mutableSession)
	// Used for session management UI / risk signals.
	mutableSession.LastSeenAt = time.Now()

	artifacts, err := s.generateTokenArtifacts(&mutableSession)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	mutableSession.LastRefreshedAt = &now
	writeErr := s.tx.RunInTx(ctx, func(stores TxAuthStores) error {
		if err := stores.Sessions.UpdateSession(ctx, &mutableSession); err != nil {
			return err
		}
		if err := stores.RefreshTokens.Consume(ctx, req.RefreshToken, now); err != nil {
			return err
		}
		if err := stores.RefreshTokens.Create(ctx, artifacts.refreshRecord); err != nil {
			return err
		}
		return nil
	})
	if writeErr != nil {
		return nil, dErrors.Wrap(writeErr, dErrors.CodeInternal, "failed to persist token refresh")
	}

	s.logAudit(ctx,
		string(audit.EventTokenRefreshed),
		"session_id", mutableSession.ID.String(),
		"user_id", mutableSession.UserID.String(),
		"client_id", mutableSession.ClientID,
	)
	s.incrementTokenRequests()

	return &models.TokenResult{
		AccessToken:  artifacts.accessToken,
		IDToken:      artifacts.idToken,
		RefreshToken: artifacts.refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.TokenTTL,
	}, nil
}

func (s *Service) findAuthorizationCode(ctx context.Context, req *models.TokenRequest) (*models.AuthorizationCodeRecord, error) {
	codeRecord, err := s.codes.FindByCode(ctx, req.Code)
	if err != nil {
		if errors.Is(err, sessionStore.ErrNotFound) {
			s.authFailure(ctx, "code_not_found", false,
				"client_id", req.ClientID,
			)
			return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid authorization code")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find code")
	}
	return codeRecord, nil
}

func (s *Service) validateAuthorizationCode(ctx context.Context, req *models.TokenRequest, codeRecord *models.AuthorizationCodeRecord) error {
	if time.Now().After(codeRecord.ExpiresAt) {
		s.authFailure(ctx, "authorization_code_expired", false,
			"client_id", req.ClientID,
			"code", req.Code,
		)
		return dErrors.New(dErrors.CodeUnauthorized, "authorization code expired")
	}

	if codeRecord.Used {
		// Security: Code reuse indicates replay attack - revoke the session.
		if err := s.sessions.RevokeSession(ctx, codeRecord.SessionID); err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to revoke compromised session")
		}
		s.authFailure(ctx, "authorization_code_reused", false,
			"client_id", req.ClientID,
			"session_id", codeRecord.SessionID.String(),
		)
		return dErrors.New(dErrors.CodeUnauthorized, "authorization code already used")
	}

	if codeRecord.RedirectURI != req.RedirectURI {
		s.authFailure(ctx, "redirect_uri_mismatch", false,
			"client_id", req.ClientID,
		)
		return dErrors.New(dErrors.CodeBadRequest, "redirect_uri mismatch")
	}

	return nil
}

func (s *Service) findSessionForCode(ctx context.Context, req *models.TokenRequest, codeRecord *models.AuthorizationCodeRecord) (*models.Session, error) {
	session, err := s.sessions.FindByID(ctx, codeRecord.SessionID)
	if err != nil {
		if errors.Is(err, sessionStore.ErrNotFound) {
			s.authFailure(ctx, "session_not_found", false,
				"client_id", req.ClientID,
			)
			return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid authorization code")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find session")
	}
	return session, nil
}

func (s *Service) validateSessionForTokenExchange(ctx context.Context, req *models.TokenRequest, session *models.Session) error {
	if req.ClientID != session.ClientID {
		s.authFailure(ctx, "client_id_mismatch", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"expected_client_id", session.ClientID,
			"provided_client_id", req.ClientID,
		)
		return dErrors.New(dErrors.CodeBadRequest, "client_id mismatch")
	}

	if session.Status == "revoked" {
		s.authFailure(ctx, "session_revoked", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		return dErrors.New(dErrors.CodeUnauthorized, "session has been revoked")
	}

	// Accept both pending_consent and active (for idempotency if code is exchanged twice).
	if session.Status != StatusPendingConsent && session.Status != StatusActive {
		s.authFailure(ctx, "invalid_session_status", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
			"status", session.Status,
		)
		return dErrors.New(dErrors.CodeUnauthorized, "session in invalid state")
	}

	if time.Now().After(session.ExpiresAt) {
		s.authFailure(ctx, "session_expired", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		return dErrors.New(dErrors.CodeUnauthorized, "session expired")
	}

	return nil
}

func (s *Service) applyDeviceBinding(ctx context.Context, session *models.Session) {
	// Phase 1: soft launch — log signals, do not enforce.
	if !s.DeviceBindingEnabled {
		return
	}

	cookieDeviceID := middleware.GetDeviceID(ctx)
	if session.DeviceID == "" && cookieDeviceID != "" {
		session.DeviceID = cookieDeviceID
		if s.logger != nil {
			s.logger.InfoContext(ctx, "device_id_attached",
				"session_id", session.ID.String(),
				"user_id", session.UserID.String(),
			)
		}
	}
	if session.DeviceID != "" && cookieDeviceID == "" {
		if s.logger != nil {
			s.logger.WarnContext(ctx, "device_id_missing",
				"session_id", session.ID.String(),
				"user_id", session.UserID.String(),
			)
		}
	} else if session.DeviceID != "" && cookieDeviceID != "" && session.DeviceID != cookieDeviceID {
		if s.logger != nil {
			s.logger.WarnContext(ctx, "device_id_mismatch",
				"session_id", session.ID.String(),
				"user_id", session.UserID.String(),
			)
		}
	}

	userAgent := middleware.GetUserAgent(ctx)
	currentFingerprint := s.deviceService.ComputeFingerprint(userAgent)
	_, driftDetected := s.deviceService.CompareFingerprints(session.DeviceFingerprintHash, currentFingerprint)
	if session.DeviceFingerprintHash == "" && currentFingerprint != "" {
		session.DeviceFingerprintHash = currentFingerprint
	} else if driftDetected {
		if s.logger != nil {
			s.logger.InfoContext(ctx, "fingerprint_drift_detected",
				"session_id", session.ID.String(),
				"user_id", session.UserID.String(),
			)
		}
		session.DeviceFingerprintHash = currentFingerprint
	}
}

func (s *Service) generateTokenArtifacts(session *models.Session) (*tokenArtifacts, error) {
	// Generate tokens before mutating persistence state so failures do not leave partial writes.
	accessToken, err := s.jwt.GenerateAccessToken(session.UserID, session.ID, session.ClientID)
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
		accessToken:   accessToken,
		idToken:       idToken,
		refreshToken:  refreshToken,
		refreshRecord: tokenRecord,
	}, nil
}

func (s *Service) persistTokenExchange(
	ctx context.Context,
	session *models.Session,
	codeRecord *models.AuthorizationCodeRecord,
	refreshRecord *models.RefreshTokenRecord,
) error {
	writeErr := s.tx.RunInTx(ctx, func(stores TxAuthStores) error {
		if err := stores.Sessions.UpdateSession(ctx, session); err != nil {
			return err
		}
		if err := stores.RefreshTokens.Create(ctx, refreshRecord); err != nil {
			return err
		}
		if err := stores.Codes.MarkUsed(ctx, codeRecord.Code); err != nil {
			return err
		}
		return nil
	})
	if writeErr != nil {
		return dErrors.Wrap(writeErr, dErrors.CodeInternal, "failed to persist token exchange")
	}
	return nil
}

func (s *Service) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	_, err := s.users.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, userStore.ErrNotFound) {
			return dErrors.New(dErrors.CodeNotFound, "user not found")
		}
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to lookup user")
	}

	if err := s.sessions.DeleteSessionsByUser(ctx, userID); err != nil {
		if !errors.Is(err, sessionStore.ErrNotFound) {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to delete user sessions")
		}
	}
	s.logAudit(ctx, string(audit.EventSessionsRevoked),
		"user_id", userID.String(),
	)

	if err := s.users.Delete(ctx, userID); err != nil {
		if errors.Is(err, userStore.ErrNotFound) {
			return dErrors.New(dErrors.CodeNotFound, "user not found")
		}
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to delete user")
	}

	s.logAudit(ctx, string(audit.EventUserDeleted),
		"user_id", userID.String(),
	)

	return nil
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

// RevokeToken revokes an access token or refresh token, effectively logging out the user.
// Implements FR-3: Token Revocation (Logout) from PRD-016.
func (s *Service) RevokeToken(ctx context.Context, token string, tokenTypeHint string) error {
	// Determine token type and extract session
	var session *models.Session
	var jti string
	var err error

	// Try to parse as JWT (access token)
	if tokenTypeHint == "access_token" || tokenTypeHint == "" {
		jti, session, err = s.extractSessionFromAccessToken(ctx, token)
		if err == nil {
			// Found valid access token, proceed with revocation
			return s.revokeSession(ctx, session, jti)
		}
	}

	// Try as refresh token (opaque)
	if tokenTypeHint == "refresh_token" || tokenTypeHint == "" {
		session, err = s.findSessionByRefreshToken(ctx, token)
		if err == nil {
			// Found session via refresh token, revoke it
			// For refresh tokens, we don't have a specific JTI, so we revoke all session tokens
			return s.revokeSession(ctx, session, "")
		}
	}

	// Token not found - idempotent success (RFC 7009 Section 2.2)
	s.logAudit(ctx, "token_revocation_noop", "reason", "token_not_found")
	return nil
}

// extractSessionFromAccessToken parses a JWT access token and returns the JTI and session.
func (s *Service) extractSessionFromAccessToken(ctx context.Context, token string) (string, *models.Session, error) {
	// Parse JWT without full validation to extract claims
	// We only need to extract session_id and jti, token might be expired
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	claims := &jwttoken.Claims{}
	_, _, err := parser.ParseUnverified(token, claims)
	if err != nil {
		return "", nil, fmt.Errorf("invalid jwt format: %w", err)
	}

	// Get session
	sessionID, err := uuid.Parse(claims.SessionID)
	if err != nil {
		return "", nil, fmt.Errorf("invalid session_id in token: %w", err)
	}

	session, err := s.sessions.FindByID(ctx, sessionID)
	if err != nil {
		return "", nil, fmt.Errorf("session not found: %w", err)
	}

	return claims.ID, session, nil
}

// findSessionByRefreshToken finds a session by its refresh token.
func (s *Service) findSessionByRefreshToken(ctx context.Context, token string) (*models.Session, error) {
	refreshToken, err := s.refreshTokens.Find(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("refresh token not found: %w", err)
	}

	session, err := s.sessions.FindByID(ctx, refreshToken.SessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	return session, nil
}

// revokeSession marks a session as revoked and adds tokens to the revocation list.
func (s *Service) revokeSession(ctx context.Context, session *models.Session, jti string) error {
	// Already revoked - idempotent success
	if session.Status == StatusRevoked {
		s.logAudit(ctx, "token_revocation_noop",
			"session_id", session.ID.String(),
			"reason", "already_revoked")
		return nil
	}

	// Revoke the session
	if err := s.sessions.RevokeSession(ctx, session.ID); err != nil {
		s.logger.Error("failed to revoke session", "error", err, "session_id", session.ID)
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	// Add access token JTI to revocation list if provided
	if jti != "" {
		if err := s.trl.RevokeToken(ctx, jti, s.TokenTTL); err != nil {
			s.logger.Error("failed to add token to revocation list", "error", err, "jti", jti)
			// Don't fail the revocation if TRL update fails - session is already revoked
		}
	}

	// Delete refresh tokens for this session
	if err := s.refreshTokens.DeleteBySessionID(ctx, session.ID); err != nil {
		s.logger.Error("failed to delete refresh tokens", "error", err, "session_id", session.ID)
		// Don't fail - session is already revoked
	}

	// Emit audit event
	s.logAudit(ctx, "token_revoked",
		"user_id", session.UserID.String(),
		"session_id", session.ID.String(),
		"client_id", session.ClientID)

	return nil
}

// IsTokenRevoked checks if a token JTI is in the revocation list.
// Used by middleware to validate tokens on every request.
func (s *Service) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	return s.trl.IsRevoked(ctx, jti)
}
