package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"id-gateway/internal/auth/models"
	"id-gateway/pkg/email"
)

type UserStore interface {
	Save(ctx context.Context, user *models.User) error
	FindByID(ctx context.Context, id string) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
}

type SessionStore interface {
	Save(ctx context.Context, session models.Session) error
	FindByID(ctx context.Context, id string) (models.Session, error)
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
		if errors.Is(err, models.ErrUserNotFound) {
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
				return nil, err
			}
			user = newUser
		} else {
			return nil, err
		}
	}

	now := time.Now()
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	newSession := models.Session{
		ID:             uuid.New(),
		UserID:         user.ID,
		RequestedScope: scopes,
		Status:         StatusPendingConsent,
		CreatedAt:      now,
		ExpiresAt:      now.Add(s.sessionTTL),
	}

	err = s.sessions.Save(ctx, newSession)
	if err != nil {
		return nil, err
	}

	redirectURI := req.RedirectURI + "?session_id=" + newSession.ID.String()
	if req.State != "" {
		redirectURI += "&state=" + req.State
	}
	res := &models.AuthorizationResult{
		SessionID:   newSession.ID,
		RedirectURI: redirectURI,
	}

	return res, nil
}

func (s *Service) Consent(ctx context.Context, req *models.ConsentRequest) (*models.ConsentResult, error) {
	_ = ctx
	return nil, nil
}

func (s *Service) Token(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	_ = ctx
	return nil, nil
}
