package cleanup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// AuthorizationCodeStore exposes cleanup for expired authorization codes.
type AuthorizationCodeStore interface {
	DeleteExpiredCodes(ctx context.Context, now time.Time) (int, error)
}

// RefreshTokenStore exposes cleanup for refresh tokens and rotation artifacts.
type RefreshTokenStore interface {
	DeleteExpiredTokens(ctx context.Context, now time.Time) (int, error)
	DeleteUsedTokens(ctx context.Context) (int, error)
}

// SessionStore exposes cleanup for expired sessions.
type SessionStore interface {
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error)
}

// CleanupResult summarizes the deletions performed by a cleanup run.
type CleanupResult struct {
	DeletedAuthorizationCodes int
	DeletedRefreshTokens      int
	DeletedUsedRefreshTokens  int
	DeletedSessions           int
}

// CleanupService periodically removes expired auth artifacts.
type CleanupService struct {
	sessionStore      SessionStore
	codeStore         AuthorizationCodeStore
	refreshTokenStore RefreshTokenStore
	interval          time.Duration
	logger            *slog.Logger
}

// CleanupOption configures CleanupService.
type CleanupOption func(*CleanupService)

// WithCleanupInterval overrides the cleanup interval when greater than zero.
func WithCleanupInterval(interval time.Duration) CleanupOption {
	return func(s *CleanupService) {
		if interval > 0 {
			s.interval = interval
		}
	}
}

// WithCleanupLogger overrides the logger used for cleanup errors.
func WithCleanupLogger(logger *slog.Logger) CleanupOption {
	return func(s *CleanupService) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// New constructs a CleanupService with required stores and options applied.
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

// RunOnce performs a single cleanup operation.
// It removes expired authorization codes, expired refresh tokens, used refresh tokens, and expired sessions.
// It returns a CleanupResult summarizing the deletions performed.
// If any errors occur during cleanup, they are aggregated and returned.
func (s *CleanupService) RunOnce(ctx context.Context) (CleanupResult, error) {
	now := time.Now()
	var res CleanupResult
	var errs []error

	deletedCodes, err := s.codeStore.DeleteExpiredCodes(ctx, now)
	if err != nil {
		errs = append(errs, fmt.Errorf("delete expired authorization codes: %w", err))
	} else {
		res.DeletedAuthorizationCodes = deletedCodes
	}

	deletedExpiredRefresh, err := s.refreshTokenStore.DeleteExpiredTokens(ctx, now)
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

	deletedSessions, err := s.sessionStore.DeleteExpiredSessions(ctx, now)
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
