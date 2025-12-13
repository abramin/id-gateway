package cleanup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

type AuthorizationCodeStore interface {
	DeleteExpiredCodes(ctx context.Context) (int, error)
}

type RefreshTokenStore interface {
	DeleteExpiredTokens(ctx context.Context) (int, error)
	DeleteUsedTokens(ctx context.Context) (int, error)
}

type SessionStore interface {
	DeleteExpiredSessions(ctx context.Context) (int, error)
}

type CleanupResult struct {
	DeletedAuthorizationCodes int
	DeletedRefreshTokens      int
	DeletedUsedRefreshTokens  int
	DeletedSessions           int
}

type CleanupService struct {
	sessionStore      SessionStore
	codeStore         AuthorizationCodeStore
	refreshTokenStore RefreshTokenStore
	interval          time.Duration
	logger            *slog.Logger
}

type CleanupOption func(*CleanupService)

func WithCleanupInterval(interval time.Duration) CleanupOption {
	return func(s *CleanupService) {
		if interval > 0 {
			s.interval = interval
		}
	}
}

func WithCleanupLogger(logger *slog.Logger) CleanupOption {
	return func(s *CleanupService) {
		if logger != nil {
			s.logger = logger
		}
	}
}

func New(
	sessionStore SessionStore,
	codeStore AuthorizationCodeStore,
	refreshTokenStore RefreshTokenStore,
	opts ...CleanupOption,
) (*CleanupService, error) {
	if sessionStore == nil || codeStore == nil || refreshTokenStore == nil {
		return nil, fmt.Errorf("sessionStore, codeStore, and refreshTokenStore are required")
	}
	svc := &CleanupService{
		sessionStore:      sessionStore,
		codeStore:         codeStore,
		refreshTokenStore: refreshTokenStore,
		interval:          5 * time.Minute,
		logger:            slog.Default(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(svc)
		}
	}
	return svc, nil
}

// Start runs cleanup periodically until ctx is cancelled.
func (s *CleanupService) Start(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if _, err := s.RunOnce(ctx); err != nil {
				s.logger.ErrorContext(ctx, "auth cleanup failed", "error", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// RunOnce performs one cleanup sweep.
func (s *CleanupService) RunOnce(ctx context.Context) (CleanupResult, error) {
	var res CleanupResult
	var errs []error

	deletedCodes, err := s.codeStore.DeleteExpiredCodes(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("delete expired authorization codes: %w", err))
	} else {
		res.DeletedAuthorizationCodes = deletedCodes
	}

	deletedExpiredRefresh, err := s.refreshTokenStore.DeleteExpiredTokens(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("delete expired refresh tokens: %w", err))
	} else {
		res.DeletedRefreshTokens = deletedExpiredRefresh
	}

	deletedUsedRefresh, err := s.refreshTokenStore.DeleteUsedTokens(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("delete used refresh tokens: %w", err))
	} else {
		res.DeletedUsedRefreshTokens = deletedUsedRefresh
	}

	deletedSessions, err := s.sessionStore.DeleteExpiredSessions(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("delete expired sessions: %w", err))
	} else {
		res.DeletedSessions = deletedSessions
	}

	if len(errs) > 0 {
		return res, errors.Join(errs...)
	}
	return res, nil
}
