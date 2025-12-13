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
)

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

// WithSessionTTL configures the time-to-live duration for sessions.
// If not set or set to zero/negative, defaults to 24 hours.
func WithSessionTTL(ttl time.Duration) Option {
	return func(s *Service) {
		if ttl > 0 {
			s.sessionTTL = ttl
		}
	}
}

func WithAllowedRedirectSchemes(schemes []string) Option {
	return func(s *Service) {
		if len(schemes) > 0 {
			s.allowedRedirectSchemes = schemes
		}
	}
}

func WithTokenTTL(ttl time.Duration) Option {
	return func(s *Service) {
		if ttl > 0 {
			s.tokenTTL = ttl
		}
	}
}

func NewService(users UserStore, sessions SessionStore, codes AuthCodeStore, refreshTokens RefreshTokenStore, opts ...Option) *Service {
	svc := &Service{
		users:         users,
		sessions:      sessions,
		codes:         codes,
		refreshTokens: refreshTokens,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
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

	userAgent := ctx.Value(models.ContextKeyUserAgent).(string)
	deviceDisplayName := device.ParseUserAgent(userAgent)

	newSession := &models.Session{
		ID:             authCode.SessionID,
		UserID:         user.ID,
		ClientID:       req.ClientID,
		RequestedScope: scopes,
		DeviceFingerprintHash: device.ComputeDeviceFingerprint(
			userAgent,
			ctx.Value(models.ContextKeyIPAddress).(string),
		),
		DeviceDisplayName:   deviceDisplayName,
		ApproximateLocation: "", // TODO: implement approximate location
		Status:              StatusPendingConsent,
		CreatedAt:           now,
		ExpiresAt:           now.Add(s.sessionTTL),
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
	}

	return res, nil
}

func (s *Service) UserInfo(ctx context.Context, sessionID string) (*models.UserInfoResult, error) {
	if sessionID == "" {
		s.logAuthFailure(ctx, "missing_session_id", false)
		s.incrementAuthFailure()
		return nil, dErrors.New(dErrors.CodeUnauthorized, "missing or invalid session")
	}

	parsedSessionID, err := uuid.Parse(sessionID)
	if err != nil {
		s.logAuthFailure(ctx, "invalid_session_id_format", false,
			"session_id", sessionID,
			"error", err,
		)
		s.incrementAuthFailure()
		return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid session ID")
	}

	session, err := s.sessions.FindByID(ctx, parsedSessionID)
	if err != nil {
		if errors.Is(err, sessionStore.ErrNotFound) {
			s.logAuthFailure(ctx, "session_not_found", false,
				"session_id", parsedSessionID.String(),
			)
			s.incrementAuthFailure()
			return nil, dErrors.New(dErrors.CodeUnauthorized, "session not found")
		}
		s.logAuthFailure(ctx, "session_lookup_failed", true,
			"session_id", parsedSessionID.String(),
			"error", err,
		)
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find session")
	}

	if session.Status != StatusActive {
		s.logAuthFailure(ctx, "session_not_active", false,
			"session_id", parsedSessionID.String(),
			"status", session.Status,
		)
		s.incrementAuthFailure()
		return nil, dErrors.New(dErrors.CodeUnauthorized, "session not active")
	}

	user, err := s.users.FindByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, userStore.ErrNotFound) {
			s.logAuthFailure(ctx, "user_not_found", false,
				"session_id", parsedSessionID.String(),
				"user_id", session.UserID.String(),
			)
			s.incrementAuthFailure()
			return nil, dErrors.New(dErrors.CodeUnauthorized, "user not found")
		}
		s.logAuthFailure(ctx, "user_lookup_failed", true,
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
	if s.jwt == nil {
		return nil, dErrors.New(dErrors.CodeInternal, "token generator not configured")
	}

	if req.GrantType != "authorization_code" {
		s.logAuthFailure(ctx, "invalid_grant_type", false,
			"client_id", req.ClientID,
			"grant_type", req.GrantType,
		)
		s.incrementAuthFailure()
		return nil, dErrors.New(dErrors.CodeUnauthorized, "unsupported grant_type")
	}

	// Step 1: Retrieve and validate auth code
	codeRecord, err := s.codes.FindByCode(ctx, req.Code)
	if err != nil {
		if errors.Is(err, sessionStore.ErrNotFound) {
			s.logAuthFailure(ctx, "code_not_found", false,
				"client_id", req.ClientID,
			)
			s.incrementAuthFailure()
			return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid authorization code")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find code")
	}
	// Step 3: Retrieve and validate session
	session, err := s.sessions.FindByID(ctx, codeRecord.SessionID)
	if err != nil {
		if errors.Is(err, sessionStore.ErrNotFound) {
			s.logAuthFailure(ctx, "session not found", false,
				"client_id", session.ClientID,
			)
			s.incrementAuthFailure()
			return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid authorization code")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find session")
	}

	// 3. Validate code not expired (OAuth 2.0 spec: codes expire quickly)
	if time.Now().After(codeRecord.ExpiresAt) {
		s.logAuthFailure(ctx, "authorization_code_expired", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		s.incrementAuthFailure()
		return nil, dErrors.New(dErrors.CodeUnauthorized, "authorization code expired")
	}

	if codeRecord.RedirectURI != req.RedirectURI {
		s.logAuthFailure(ctx, "redirect_uri mismatch", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		s.incrementAuthFailure()
		return nil, dErrors.New(dErrors.CodeUnauthorized, "redirect_uri mismatch")
	}
	//4. Validate code not already used (prevent replay attacks)
	// Step 2: Validate code constraints
	if codeRecord.Used {
		// Security: Mark session as compromised and revoke
		err = s.sessions.RevokeSession(ctx, codeRecord.SessionID)
		if err != nil {
			return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to revoke compromised session")
		}
		s.logAuthFailure(ctx, "authorization_code_reused", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		s.incrementAuthFailure()
		return nil, dErrors.New(dErrors.CodeUnauthorized, "authorization code already used")
	}

	// 6. Validate client_id matches
	if req.ClientID != session.ClientID {
		s.logAuthFailure(ctx, "client_id_mismatch", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		s.incrementAuthFailure()
		return nil, dErrors.New(dErrors.CodeUnauthorized, "client_id mismatch")
	}

	if session.Status != "active" {
		return nil, dErrors.New(dErrors.CodeUnauthorized, "session revoked or expired")
	}
	if time.Now().After(session.ExpiresAt) {
		s.logAuthFailure(ctx, "session_expired", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		s.incrementAuthFailure()
		return nil, dErrors.New(dErrors.CodeUnauthorized, "session expired")
	}

	// Step 4: Mark code as used (prevent replay)
	if err := s.codes.MarkUsed(ctx, codeRecord.Code); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to mark code as used")
	}

	// Step 5: Generate tokens
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

// incrementAuthFailure increments the auth failures metric if metrics are enabled
func (s *Service) incrementAuthFailure() {
	if s.metrics != nil {
		s.metrics.IncrementAuthFailures()
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
