package service

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/google/uuid"

	"credo/internal/audit"
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
	Save(ctx context.Context, session *models.Session) error
	FindByID(ctx context.Context, id uuid.UUID) (*models.Session, error)
	FindByCode(ctx context.Context, code string) (*models.Session, error)
	DeleteSessionsByUser(ctx context.Context, userID uuid.UUID) error
}

type TokenGenerator interface {
	GenerateAccessToken(userID uuid.UUID, sessionID uuid.UUID, clientID string) (string, error)
	GenerateIDToken(userID uuid.UUID, sessionID uuid.UUID, clientID string) (string, error)
}

type Service struct {
	users          UserStore
	sessions       SessionStore
	sessionTTL     time.Duration
	logger         *slog.Logger
	auditPublisher AuditPublisher
	jwt            TokenGenerator
	metrics        *metrics.Metrics
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

func NewService(users UserStore, sessions SessionStore, opts ...Option) *Service {
	svc := &Service{
		users:      users,
		sessions:   sessions,
		sessionTTL: defaultSessionTTL,
	}
	for _, opt := range opts {
		opt(svc)
	}
	if svc.logger == nil {
		svc.logger = slog.Default()
	}
	// Validate and apply default if needed
	if svc.sessionTTL <= 0 {
		svc.sessionTTL = defaultSessionTTL
	}
	return svc
}

func (s *Service) Authorize(ctx context.Context, req *models.AuthorizationRequest) (*models.AuthorizationResult, error) {
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
		return nil, dErrors.Wrap(dErrors.CodeInternal, "failed to find or create user", err)
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
	authCode := "authz_" + uuid.New().String()

	newSession := &models.Session{
		ID:             uuid.New(),
		UserID:         user.ID,
		Code:           authCode,
		CodeExpiresAt:  now.Add(10 * time.Minute), // OAuth 2.0 spec: short-lived codes
		CodeUsed:       false,
		ClientID:       req.ClientID,
		RedirectURI:    req.RedirectURI,
		RequestedScope: scopes,
		Status:         StatusPendingConsent,
		CreatedAt:      now,
		ExpiresAt:      now.Add(s.sessionTTL),
	}

	err = s.sessions.Save(ctx, newSession)
	if err != nil {
		return nil, dErrors.Wrap(dErrors.CodeInternal, "failed to save session", err)
	}
	s.logAudit(ctx, string(audit.EventSessionCreated),
		"user_id", user.ID.String(),
		"session_id", newSession.ID.String(),
		"client_id", req.ClientID,
	)
	s.incrementActiveSession()

	redirectURI := req.RedirectURI
	if redirectURI != "" {
		u, parseErr := url.Parse(redirectURI)
		if parseErr != nil {
			return nil, dErrors.New(dErrors.CodeValidation, "invalid redirect_uri")
		}
		query := u.Query()
		query.Set("code", authCode) // OAuth 2.0: return authorization code, not session_id
		if req.State != "" {
			query.Set("state", req.State)
		}
		u.RawQuery = query.Encode()
		redirectURI = u.String()
	}
	res := &models.AuthorizationResult{
		Code:        authCode,
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
		if errors.Is(err, userStore.ErrNotFound) {
			s.logAuthFailure(ctx, "session_not_found", false,
				"session_id", parsedSessionID.String(),
			)
			s.incrementAuthFailure()
			return nil, dErrors.New(dErrors.CodeNotFound, "session not found")
		}
		s.logAuthFailure(ctx, "session_lookup_failed", true,
			"session_id", parsedSessionID.String(),
			"error", err,
		)
		return nil, dErrors.Wrap(dErrors.CodeInternal, "failed to find session", err)
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
		return nil, dErrors.Wrap(dErrors.CodeInternal, "failed to find user", err)
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
		s.logAuthFailure(ctx, "token_generator_missing", true)
		return nil, dErrors.New(dErrors.CodeInternal, "token generator not configured")
	}

	// 1. Validate grant_type
	if req.GrantType != "authorization_code" {
		s.logAuthFailure(ctx, "invalid_grant_type", false,
			"client_id", req.ClientID,
		)
		return nil, dErrors.New(dErrors.CodeInvalidInput, "unsupported grant_type")
	}

	// 2. Find session by authorization code
	session, err := s.sessions.FindByCode(ctx, req.Code)
	if err != nil {
		if errors.Is(err, sessionStore.ErrNotFound) {
			s.logAuthFailure(ctx, "session_not_found", false,
				"client_id", req.ClientID,
			)
			s.incrementAuthFailure()
			return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid authorization code")
		}
		s.logAuthFailure(ctx, "session_lookup_failed", true,
			"client_id", req.ClientID,
			"error", err,
		)
		return nil, dErrors.Wrap(dErrors.CodeInternal, "failed to find session", err)
	}

	// 3. Validate code not expired (OAuth 2.0 spec: codes expire quickly)
	if time.Now().After(session.CodeExpiresAt) {
		s.logAuthFailure(ctx, "authorization_code_expired", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		s.incrementAuthFailure()
		return nil, dErrors.New(dErrors.CodeUnauthorized, "authorization code expired")
	}

	// 4. Validate code not already used (prevent replay attacks)
	if session.CodeUsed {
		s.logAuthFailure(ctx, "authorization_code_reused", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		s.incrementAuthFailure()
		return nil, dErrors.New(dErrors.CodeUnauthorized, "authorization code already used")
	}

	// 5. Validate redirect_uri matches (OAuth 2.0 security requirement)
	if req.RedirectURI != session.RedirectURI {
		s.logAuthFailure(ctx, "redirect_uri_mismatch", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		return nil, dErrors.New(dErrors.CodeInvalidInput, "redirect_uri mismatch")
	}

	// 6. Validate client_id matches
	if req.ClientID != session.ClientID {
		s.logAuthFailure(ctx, "client_id_mismatch", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		return nil, dErrors.New(dErrors.CodeInvalidInput, "client_id mismatch")
	}

	// 7. Mark code as used and update session status
	session.CodeUsed = true
	session.Status = StatusActive
	err = s.sessions.Save(ctx, session)
	if err != nil {
		s.logAuthFailure(ctx, "session_update_failed", true,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
			"error", err,
		)
		return nil, dErrors.Wrap(dErrors.CodeInternal, "failed to update session", err)
	}

	// 8. Generate tokens
	accessToken, err := s.jwt.GenerateAccessToken(session.UserID, session.ID, session.ClientID)
	if err != nil {
		return nil, dErrors.Wrap(dErrors.CodeInternal, "failed to generate access token", err)
	}

	idToken, err := s.jwt.GenerateIDToken(session.UserID, session.ID, session.ClientID)
	if err != nil {
		return nil, dErrors.Wrap(dErrors.CodeInternal, "failed to generate ID token", err)
	}

	s.logAudit(ctx, string(audit.EventTokenIssued),
		"user_id", session.UserID.String(),
		"session_id", session.ID.String(),
		"client_id", session.ClientID,
	)
	s.incrementTokenRequests()

	return &models.TokenResult{
		AccessToken: accessToken,
		IDToken:     idToken,
		ExpiresIn:   s.sessionTTL,
		TokenType:   "Bearer",
	}, nil
}

func (s *Service) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, userStore.ErrNotFound) {
			return dErrors.New(dErrors.CodeNotFound, "user not found")
		}
		return dErrors.Wrap(dErrors.CodeInternal, "failed to lookup user", err)
	}

	if err := s.sessions.DeleteSessionsByUser(ctx, userID); err != nil {
		if !errors.Is(err, sessionStore.ErrNotFound) {
			return dErrors.Wrap(dErrors.CodeInternal, "failed to delete user sessions", err)
		}
	}
	s.logAudit(ctx, string(audit.EventSessionsRevoked),
		"user_id", userID.String(),
	)

	if err := s.users.Delete(ctx, userID); err != nil {
		if errors.Is(err, userStore.ErrNotFound) {
			return dErrors.New(dErrors.CodeNotFound, "user not found")
		}
		return dErrors.Wrap(dErrors.CodeInternal, "failed to delete user", err)
	}

	s.logAudit(ctx, string(audit.EventUserDeleted),
		"user_id", userID.String(),
		"email", user.Email,
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
