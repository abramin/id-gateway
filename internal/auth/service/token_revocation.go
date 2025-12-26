package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"credo/internal/auth/models"
	sessionStore "credo/internal/auth/store/session"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/middleware/requesttime"
)

const (
	TokenHintRefreshToken = "refresh_token"
	TokenHintAccessToken  = "access_token"
)

type tokenResolution struct {
	Session *models.Session
	JTI     string // Only set for access tokens
}

func (s *Service) RevokeToken(ctx context.Context, token string, tokenTypeHint string) error {
	token = strings.TrimSpace(token)
	tokenTypeHint = strings.TrimSpace(tokenTypeHint)

	if err := validateRevokeInput(token, tokenTypeHint); err != nil {
		return err
	}

	resolution, err := s.resolveTokenToSession(ctx, token, tokenTypeHint)
	if err != nil {
		s.logAudit(ctx, "token_revocation_noop", "reason", "token_not_found")
		return nil
	}

	return s.revokeAndAudit(ctx, resolution)
}

func validateRevokeInput(token, tokenTypeHint string) error {
	if token == "" {
		return dErrors.New(dErrors.CodeValidation, "token is required")
	}
	if tokenTypeHint != "" && tokenTypeHint != TokenHintAccessToken && tokenTypeHint != TokenHintRefreshToken {
		return dErrors.New(dErrors.CodeValidation, "token_type_hint must be 'access_token' or 'refresh_token'")
	}
	return nil
}

func (s *Service) resolveTokenToSession(ctx context.Context, token, tokenTypeHint string) (*tokenResolution, error) {
	// Try access token first (if hint allows)
	if tokenTypeHint == TokenHintAccessToken || tokenTypeHint == "" {
		jti, session, err := s.extractSessionFromAccessToken(ctx, token)
		if err == nil {
			return &tokenResolution{Session: session, JTI: jti}, nil
		}
	}

	// Try refresh token (if hint allows)
	if tokenTypeHint == TokenHintRefreshToken || tokenTypeHint == "" {
		session, err := s.findSessionByRefreshToken(ctx, token)
		if err == nil {
			return &tokenResolution{Session: session, JTI: ""}, nil
		}
	}

	return nil, fmt.Errorf("token not found")
}

func (s *Service) revokeAndAudit(ctx context.Context, resolution *tokenResolution) error {
	session := resolution.Session

	outcome, err := s.revokeSessionInternal(ctx, session, resolution.JTI)
	if err != nil {
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to revoke session")
	}

	if outcome == revokeSessionOutcomeAlreadyRevoked {
		s.logAudit(ctx, "token_revocation_noop",
			"session_id", session.ID.String(),
			"reason", "already_revoked")
		return nil
	}

	s.logAudit(ctx, "token_revoked",
		"user_id", session.UserID.String(),
		"session_id", session.ID.String(),
		"client_id", session.ClientID)
	return nil
}

func (s *Service) extractSessionFromAccessToken(ctx context.Context, token string) (string, *models.Session, error) {
	claims, err := s.jwt.ParseTokenSkipClaimsValidation(token)
	if err != nil {
		return "", nil, err
	}

	// Get session
	sessionID, err := uuid.Parse(claims.SessionID)
	if err != nil {
		return "", nil, fmt.Errorf("invalid session_id in token: %w", err)
	}

	session, err := s.sessions.FindByID(ctx, id.SessionID(sessionID))
	if err != nil {
		return "", nil, fmt.Errorf("session not found: %w", err)
	}

	return claims.ID, session, nil
}

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

type revokeSessionOutcome int

const (
	revokeSessionOutcomeRevoked revokeSessionOutcome = iota
	revokeSessionOutcomeAlreadyRevoked
)

func (s *Service) revokeSessionInternal(ctx context.Context, session *models.Session, jti string) (revokeSessionOutcome, error) {
	if err := s.sessions.RevokeSessionIfActive(ctx, session.ID, requesttime.Now(ctx)); err != nil {
		if errors.Is(err, sessionStore.ErrSessionRevoked) {
			return revokeSessionOutcomeAlreadyRevoked, nil
		}
		s.logger.Error("failed to revoke session", "error", err, "session_id", session.ID)
		return revokeSessionOutcomeRevoked, fmt.Errorf("failed to revoke session: %w", err)
	}

	jtiToRevoke := jti
	if jtiToRevoke == "" {
		jtiToRevoke = session.LastAccessTokenJTI
	}
	if jtiToRevoke != "" {
		if err := s.trl.RevokeToken(ctx, jtiToRevoke, s.TokenTTL); err != nil {
			s.logger.Error("failed to add token to revocation list", "error", err, "jti", jtiToRevoke)
			// Don't fail the revocation if TRL update fails - session is already revoked
		}
	}

	if err := s.refreshTokens.DeleteBySessionID(ctx, session.ID); err != nil {
		s.logger.Error("failed to delete refresh tokens", "error", err, "session_id", session.ID)
		// Don't fail - session is already revoked
	}
	return revokeSessionOutcomeRevoked, nil
}

func (s *Service) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	return s.trl.IsRevoked(ctx, jti)
}
