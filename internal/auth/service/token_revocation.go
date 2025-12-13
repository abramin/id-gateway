package service

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"credo/internal/auth/models"
	jwttoken "credo/internal/jwt_token"
)

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
