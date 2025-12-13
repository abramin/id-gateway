package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"credo/internal/audit"
	"credo/internal/auth/device"
	"credo/internal/auth/models"
	sessionStore "credo/internal/auth/store/session"
	userStore "credo/internal/auth/store/user"
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
	UpdateLastRefreshed(ctx context.Context, token string, timestamp *time.Time) error
	DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) error
}

type TokenGenerator interface {
	GenerateAccessToken(userID uuid.UUID, sessionID uuid.UUID, clientID string) (string, error)
	GenerateIDToken(userID uuid.UUID, sessionID uuid.UUID, clientID string) (string, error)
	CreateRefreshToken() (string, error)
}

type Service struct {
	users                  UserStore
	sessions               SessionStore
	codes                  AuthCodeStore
	refreshTokens          RefreshTokenStore
	sessionTTL             time.Duration
	tokenTTL               time.Duration
	deviceBindingEnabled   bool
	deviceService          *device.Service
	logger                 *slog.Logger
	auditPublisher         AuditPublisher
	jwt                    TokenGenerator
	metrics                *metrics.Metrics
	allowedRedirectSchemes []string
}

const (
	StatusPendingConsent = "pending_consent"
	StatusActive         = "active"
	defaultSessionTTL    = 24 * time.Hour
	defaultTokenTTL      = 15 * time.Minute
)

type Config struct {
	SessionTTL             time.Duration
	TokenTTL               time.Duration
	AllowedRedirectSchemes []string
	DeviceBindingEnabled   bool
}

type AuditPublisher interface {
	Emit(ctx context.Context, base audit.Event) error
}

type Option func(*Service)

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

func WithDeviceBindingEnabled(enabled bool) Option {
	return func(s *Service) {
		s.deviceBindingEnabled = enabled
	}
}

func New(
	users UserStore,
	sessions SessionStore,
	codes AuthCodeStore,
	refreshTokens RefreshTokenStore,
	cfg Config,
	opts ...Option,
) (*Service, error) {
	if users == nil || sessions == nil || codes == nil || refreshTokens == nil {
		return nil, fmt.Errorf("users, sessions, codes, and refreshTokens stores are required")
	}
	// Defaults for required config
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = defaultTokenTTL
	}
	if len(cfg.AllowedRedirectSchemes) == 0 {
		cfg.AllowedRedirectSchemes = []string{"https"}
	}

	svc := &Service{
		users:                  users,
		sessions:               sessions,
		codes:                  codes,
		refreshTokens:          refreshTokens,
		sessionTTL:             cfg.SessionTTL,
		tokenTTL:               cfg.TokenTTL,
		deviceBindingEnabled:   cfg.DeviceBindingEnabled,
		allowedRedirectSchemes: cfg.AllowedRedirectSchemes,
	}

	for _, opt := range opts {
		opt(svc)
	}

	if svc.jwt == nil {
		return nil, fmt.Errorf("token generator (jwt) is required")
	}

	if svc.deviceService == nil {
		svc.deviceService = device.NewService(svc.deviceBindingEnabled)
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
	if s.deviceBindingEnabled {
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
		ExpiresAt:             now.Add(s.sessionTTL),
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
	// Validate grant_type (OAuth 2.0 requirement)
	// Note: This is a client implementation error, not a security attack
	if req.GrantType != "authorization_code" {
		return nil, dErrors.New(dErrors.CodeBadRequest, "unsupported grant_type")
	}

	// Step 1: Retrieve authorization code
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

	// Step 2: Validate authorization code constraints
	if time.Now().After(codeRecord.ExpiresAt) {
		s.authFailure(ctx, "authorization_code_expired", false,
			"client_id", req.ClientID,
			"code", req.Code,
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "authorization code expired")
	}

	if codeRecord.Used {
		// Security: Code reuse indicates replay attack - revoke the session
		err = s.sessions.RevokeSession(ctx, codeRecord.SessionID)
		if err != nil {
			return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to revoke compromised session")
		}
		s.authFailure(ctx, "authorization_code_reused", false,
			"client_id", req.ClientID,
			"session_id", codeRecord.SessionID.String(),
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "authorization code already used")
	}

	if codeRecord.RedirectURI != req.RedirectURI {
		s.authFailure(ctx, "redirect_uri_mismatch", false,
			"client_id", req.ClientID,
		)
		return nil, dErrors.New(dErrors.CodeBadRequest, "redirect_uri mismatch")
	}

	// Step 3: Retrieve session
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

	// Step 4: Validate session and client_id match
	if req.ClientID != session.ClientID {
		s.authFailure(ctx, "client_id_mismatch", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"expected_client_id", session.ClientID,
			"provided_client_id", req.ClientID,
		)
		return nil, dErrors.New(dErrors.CodeBadRequest, "client_id mismatch")
	}

	// Step 5: Validate session status and expiry
	if session.Status == "revoked" {
		s.authFailure(ctx, "session_revoked", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "session has been revoked")
	}

	// Accept both pending_consent and active (for idempotency if code is exchanged twice)
	if session.Status != StatusPendingConsent && session.Status != StatusActive {
		s.authFailure(ctx, "invalid_session_status", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
			"status", session.Status,
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "session in invalid state")
	}

	if time.Now().After(session.ExpiresAt) {
		s.authFailure(ctx, "session_expired", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "session expired")
	}

	// Device binding (Phase 1: soft launch — log results, do not enforce).
	if s.deviceBindingEnabled {
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

	// Session activity marker (used for session management UI / risk signals).
	session.LastSeenAt = time.Now()

	// Step 6: Mark code as used (prevent replay attacks)
	if err := s.codes.MarkUsed(ctx, codeRecord.Code); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to mark code as used")
	}

	// Step 7: Activate session (transition from pending_consent to active)
	// Note: In-memory store holds pointers, so this updates the stored session
	// TODO: Add proper UpdateSession method to SessionStore interface for explicit updates
	if session.Status == StatusPendingConsent {
		session.Status = StatusActive
	}

	// Step 8: Generate tokens
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

	tokenRecord := &models.RefreshTokenRecord{
		Token:           refreshToken,
		SessionID:       session.ID,
		CreatedAt:       time.Now(),
		LastRefreshedAt: nil,
		ExpiresAt:       time.Now().Add(30 * 24 * time.Hour), // 30 days
		Used:            false,
	}

	if err := s.refreshTokens.Create(ctx, tokenRecord); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create refresh token record")
	}

	s.logAudit(ctx,
		string(audit.EventTokenIssued),
		"session_id", session.ID.String(),
		"user_id", session.UserID.String(),
		"client_id", session.ClientID,
	)
	s.incrementTokenRequests()

	return &models.TokenResult{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.tokenTTL, // Access token TTL
	}, nil
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
	for _, scheme := range s.allowedRedirectSchemes {
		if strings.EqualFold(uri.Scheme, scheme) {
			return true
		}
	}
	return false
}
