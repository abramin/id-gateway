package service

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"

	"id-gateway/internal/auth/models"
	"id-gateway/internal/auth/store"
	"id-gateway/pkg/email"
	httpErrors "id-gateway/pkg/http-errors"
)

type UserStore interface {
	Save(ctx context.Context, user *models.User) error
	FindByID(ctx context.Context, id string) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
}

type SessionStore interface {
	Save(ctx context.Context, session *models.Session) error
	FindByID(ctx context.Context, id string) (*models.Session, error)
}

type Service struct {
	users      UserStore
	sessions   SessionStore
	sessionTTL time.Duration
}

const StatusPendingConsent = "pending_consent"

func NewService(users UserStore, sessions SessionStore, sessionTTL time.Duration) *Service {
	if sessionTTL <= 0 {
		sessionTTL = 15 * time.Minute
	}
	return &Service{
		users:      users,
		sessions:   sessions,
		sessionTTL: sessionTTL,
	}
}

func (s *Service) Authorize(ctx context.Context, req *models.AuthorizationRequest) (*models.AuthorizationResult, error) {
	user, err := s.users.FindByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			firstName, lastName := email.DeriveNameFromEmail(req.Email)
			newUser := &models.User{
				ID:        uuid.New(),
				Email:     req.Email,
				FirstName: firstName,
				LastName:  lastName,
				Verified:  false,
			}
			err = s.users.Save(ctx, newUser)
			if err != nil {
				return nil, httpErrors.New(httpErrors.CodeInternal, "failed to save user")
			}
			user = newUser
		} else {
			return nil, httpErrors.New(httpErrors.CodeInternal, "failed to find user")
		}
	}

	now := time.Now()
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid"}
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
		return nil, httpErrors.New(httpErrors.CodeInternal, "failed to save session")
	}

	redirectURI := req.RedirectURI
	if redirectURI != "" {
		u, parseErr := url.Parse(redirectURI)
		if parseErr != nil {
			return nil, httpErrors.New(httpErrors.CodeInvalidInput, "invalid redirect_uri")
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

func (s *Service) Consent(ctx context.Context, req *models.ConsentRequest) (*models.ConsentResult, error) {
	_ = ctx
	return nil, nil
}

func (s *Service) Token(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	// 1. Validate grant_type
	if req.GrantType != "authorization_code" {
		return nil, httpErrors.New(httpErrors.CodeInvalidInput, "unsupported grant_type")
	}

	// 2. Find session by authorization code
	session, err := s.sessions.FindByCode(ctx, req.Code)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, httpErrors.New(httpErrors.CodeUnauthorized, "invalid authorization code")
		}
		return nil, httpErrors.New(httpErrors.CodeInternal, "failed to find session")
	}

	// 3. Validate code not expired (OAuth 2.0 spec: codes expire quickly)
	if time.Now().After(session.CodeExpiresAt) {
		return nil, httpErrors.New(httpErrors.CodeUnauthorized, "authorization code expired")
	}

	// 4. Validate code not already used (prevent replay attacks)
	if session.CodeUsed {
		return nil, httpErrors.New(httpErrors.CodeUnauthorized, "authorization code already used")
	}

	// 5. Validate redirect_uri matches (OAuth 2.0 security requirement)
	if req.RedirectURI != session.RedirectURI {
		return nil, httpErrors.New(httpErrors.CodeInvalidInput, "redirect_uri mismatch")
	}

	// 6. Validate client_id matches
	if req.ClientID != session.ClientID {
		return nil, httpErrors.New(httpErrors.CodeInvalidInput, "client_id mismatch")
	}

	// 7. Mark code as used and update session status
	session.CodeUsed = true
	session.Status = "active"
	err = s.sessions.Save(ctx, session)
	if err != nil {
		return nil, httpErrors.New(httpErrors.CodeInternal, "failed to update session")
	}

	// 8. Generate tokens
	accessToken := "at_" + session.ID.String()
	idToken := "idt_" + session.ID.String()

	return &models.TokenResult{
		AccessToken: accessToken,
		IDToken:     idToken,
		ExpiresIn:   3600, // 1 hour
	}, nil
}
