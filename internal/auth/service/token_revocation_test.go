package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"credo/internal/auth/models"
	sessionStore "credo/internal/auth/store/session"
	jwttoken "credo/internal/jwt_token"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// TestRevokeToken tests the RevokeToken endpoint (PRD-016 FR-3)
func (s *ServiceSuite) TestRevokeToken() {
	sessionID := uuid.New()
	userID := uuid.New()
	clientID := "client-123"
	jti := "access-token-jti-123"

	validSession := &models.Session{
		ID:                 sessionID,
		UserID:             userID,
		ClientID:           clientID,
		Status:             string(models.SessionStatusActive),
		LastAccessTokenJTI: jti,
		CreatedAt:          time.Now().Add(-1 * time.Hour),
		ExpiresAt:          time.Now().Add(23 * time.Hour),
	}

	s.T().Run("revoke access token - happy path", func(t *testing.T) {
		ctx := context.Background()
		accessToken := "mock-access-token"
		tokenJTI := "token-jti-123"

		sess := *validSession
		sess.LastAccessTokenJTI = tokenJTI

		// Mock JWT parsing to return valid claims
		claims := &jwttoken.Claims{
			UserID:    userID.String(),
			SessionID: sessionID.String(),
			RegisteredClaims: jwt.RegisteredClaims{
				ID: tokenJTI,
			},
		}
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(accessToken).Return(claims, nil)

		// Expect session lookup
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)

		// Expect session revocation
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessionID, gomock.Any()).Return(nil)

		// Expect TRL update
		s.mockTRL.EXPECT().RevokeToken(gomock.Any(), tokenJTI, s.service.TokenTTL).Return(nil)

		// Expect refresh token deletion
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessionID).Return(nil)

		// Expect audit event
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		err := s.service.RevokeToken(ctx, accessToken, TokenHintAccessToken)
		assert.NoError(t, err)
	})

	s.T().Run("revoke refresh token - happy path", func(t *testing.T) {
		ctx := context.Background()
		refreshToken := "ref_valid-refresh-token"

		refreshRecord := &models.RefreshTokenRecord{
			Token:     refreshToken,
			SessionID: sessionID,
			Used:      false,
			ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		}

		sess := *validSession

		// Expect refresh token lookup
		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshToken).Return(refreshRecord, nil)

		// Expect session lookup
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)

		// Expect session revocation
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessionID, gomock.Any()).Return(nil)

		// Expect TRL update with LastAccessTokenJTI
		s.mockTRL.EXPECT().RevokeToken(gomock.Any(), jti, s.service.TokenTTL).Return(nil)

		// Expect refresh token deletion
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessionID).Return(nil)

		// Expect audit event
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		err := s.service.RevokeToken(ctx, refreshToken, TokenHintRefreshToken)
		assert.NoError(t, err)
	})

	s.T().Run("already revoked - idempotent success", func(t *testing.T) {
		ctx := context.Background()
		accessToken := "mock-access-token"
		tokenJTI := "token-jti-456"

		sess := *validSession
		sess.LastAccessTokenJTI = tokenJTI
		sess.Status = "revoked"

		claims := &jwttoken.Claims{
			UserID:    userID.String(),
			SessionID: sessionID.String(),
			RegisteredClaims: jwt.RegisteredClaims{
				ID: tokenJTI,
			},
		}
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(accessToken).Return(claims, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessionID, gomock.Any()).
			Return(sessionStore.ErrSessionRevoked)

		// Expect audit event for already revoked
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		err := s.service.RevokeToken(ctx, accessToken, TokenHintAccessToken)
		assert.NoError(t, err) // Should be idempotent
	})

	s.T().Run("token not found - idempotent success", func(t *testing.T) {
		ctx := context.Background()
		fakeToken := "fake-token-that-does-not-exist"

		// Service will try to parse as JWT first - mock failure
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(fakeToken).Return(nil, errors.New("invalid token"))

		// Then it will try as refresh token - mock failure
		s.mockRefreshStore.EXPECT().Find(gomock.Any(), fakeToken).Return(nil, errors.New("not found"))

		// Expect audit event for token not found
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		err := s.service.RevokeToken(ctx, fakeToken, "")
		assert.NoError(t, err) // RFC 7009 Section 2.2 - idempotent
	})

	s.T().Run("expired access token - can still revoke", func(t *testing.T) {
		ctx := context.Background()
		expiredToken := "expired-jwt-token"
		expiredJTI := "expired-jti-123"

		sess := *validSession
		sess.LastAccessTokenJTI = expiredJTI

		// Mock parsing returns expired token claims
		claims := &jwttoken.Claims{
			UserID:    userID.String(),
			SessionID: sessionID.String(),
			RegisteredClaims: jwt.RegisteredClaims{
				ID: expiredJTI,
			},
		}
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(expiredToken).Return(claims, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessionID, gomock.Any()).Return(nil)
		s.mockTRL.EXPECT().RevokeToken(gomock.Any(), expiredJTI, s.service.TokenTTL).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessionID).Return(nil)

		// Expect audit event
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		err := s.service.RevokeToken(ctx, expiredToken, TokenHintAccessToken)
		assert.NoError(t, err)
	})

	s.T().Run("hint inference - access token without hint", func(t *testing.T) {
		ctx := context.Background()
		accessToken := "mock-access-token"
		tokenJTI := "token-jti-789"

		sess := *validSession
		sess.LastAccessTokenJTI = tokenJTI

		claims := &jwttoken.Claims{
			UserID:    userID.String(),
			SessionID: sessionID.String(),
			RegisteredClaims: jwt.RegisteredClaims{
				ID: tokenJTI,
			},
		}
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(accessToken).Return(claims, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessionID, gomock.Any()).Return(nil)
		s.mockTRL.EXPECT().RevokeToken(gomock.Any(), tokenJTI, s.service.TokenTTL).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessionID).Return(nil)

		// Expect audit event
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		err := s.service.RevokeToken(ctx, accessToken, "") // No hint
		assert.NoError(t, err)
	})

	s.T().Run("TRL failure - session still revoked", func(t *testing.T) {
		ctx := context.Background()
		accessToken := "mock-access-token"
		tokenJTI := "token-jti-abc"

		sess := *validSession
		sess.LastAccessTokenJTI = tokenJTI

		claims := &jwttoken.Claims{
			UserID:    userID.String(),
			SessionID: sessionID.String(),
			RegisteredClaims: jwt.RegisteredClaims{
				ID: tokenJTI,
			},
		}
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(accessToken).Return(claims, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessionID, gomock.Any()).Return(nil)
		s.mockTRL.EXPECT().RevokeToken(gomock.Any(), tokenJTI, s.service.TokenTTL).
			Return(errors.New("redis error"))
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessionID).Return(nil)

		// Expect audit event
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		err := s.service.RevokeToken(ctx, accessToken, TokenHintAccessToken)
		assert.NoError(t, err) // Should succeed even if TRL fails
	})

	s.T().Run("refresh token deletion failure - session still revoked", func(t *testing.T) {
		ctx := context.Background()
		accessToken := "mock-access-token"
		tokenJTI := "token-jti-def"

		sess := *validSession
		sess.LastAccessTokenJTI = tokenJTI

		claims := &jwttoken.Claims{
			UserID:    userID.String(),
			SessionID: sessionID.String(),
			RegisteredClaims: jwt.RegisteredClaims{
				ID: tokenJTI,
			},
		}
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(accessToken).Return(claims, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessionID, gomock.Any()).Return(nil)
		s.mockTRL.EXPECT().RevokeToken(gomock.Any(), tokenJTI, s.service.TokenTTL).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessionID).
			Return(errors.New("db error"))

		// Expect audit event
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		err := s.service.RevokeToken(ctx, accessToken, TokenHintAccessToken)
		assert.NoError(t, err) // Should succeed even if refresh deletion fails
	})
}

// TestExtractSessionFromAccessToken tests JWT signature verification
func (s *ServiceSuite) TestExtractSessionFromAccessToken() {
	sessionID := uuid.New()
	userID := uuid.New()
	clientID := "client-123"

	validSession := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		ClientID:  clientID,
		Status:    string(models.SessionStatusActive),
		CreatedAt: time.Now().Add(-1 * time.Hour),
		ExpiresAt: time.Now().Add(23 * time.Hour),
	}

	s.T().Run("valid signature - success", func(t *testing.T) {
		ctx := context.Background()
		accessToken := "valid-jwt-token"
		tokenJTI := "jti-123"

		claims := &jwttoken.Claims{
			UserID:    userID.String(),
			SessionID: sessionID.String(),
			RegisteredClaims: jwt.RegisteredClaims{
				ID: tokenJTI,
			},
		}
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(accessToken).Return(claims, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(validSession, nil)

		jti, session, err := s.service.extractSessionFromAccessToken(ctx, accessToken)
		assert.NoError(t, err)
		assert.Equal(t, tokenJTI, jti)
		assert.Equal(t, sessionID, session.ID)
	})

	s.T().Run("invalid signature - rejected", func(t *testing.T) {
		ctx := context.Background()
		invalidToken := "invalid-signature-token"

		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(invalidToken).
			Return(nil, errors.New("invalid jwt signature or format: signature is invalid"))

		jti, session, err := s.service.extractSessionFromAccessToken(ctx, invalidToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid jwt signature")
		assert.Empty(t, jti)
		assert.Nil(t, session)
	})

	s.T().Run("algorithm confusion attack - rejected", func(t *testing.T) {
		ctx := context.Background()
		maliciousToken := "token-with-wrong-algorithm"

		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(maliciousToken).
			Return(nil, errors.New("unexpected signing method: HS512"))

		jti, session, err := s.service.extractSessionFromAccessToken(ctx, maliciousToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected signing method")
		assert.Empty(t, jti)
		assert.Nil(t, session)
	})

	s.T().Run("malformed token - rejected", func(t *testing.T) {
		ctx := context.Background()
		malformedToken := "not.a.valid.jwt.token.at.all"

		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(malformedToken).
			Return(nil, errors.New("invalid jwt signature or format: token contains an invalid number of segments"))

		jti, session, err := s.service.extractSessionFromAccessToken(ctx, malformedToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid jwt signature")
		assert.Empty(t, jti)
		assert.Nil(t, session)
	})

	s.T().Run("expired token - signature still verified", func(t *testing.T) {
		ctx := context.Background()
		expiredToken := "expired-but-valid-signature-token"
		expiredJTI := "expired-jti"

		// Expired tokens should still parse successfully
		claims := &jwttoken.Claims{
			UserID:    userID.String(),
			SessionID: sessionID.String(),
			RegisteredClaims: jwt.RegisteredClaims{
				ID: expiredJTI,
			},
		}
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(expiredToken).Return(claims, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(validSession, nil)

		extractedJTI, session, err := s.service.extractSessionFromAccessToken(ctx, expiredToken)
		assert.NoError(t, err) // Expiration should be ignored, signature verified
		assert.Equal(t, expiredJTI, extractedJTI)
		assert.Equal(t, sessionID, session.ID)
	})

	s.T().Run("invalid session_id in claims - rejected", func(t *testing.T) {
		ctx := context.Background()
		accessToken := "token-with-invalid-session-id"

		claims := &jwttoken.Claims{
			UserID:    userID.String(),
			SessionID: "not-a-valid-uuid",
			RegisteredClaims: jwt.RegisteredClaims{
				ID: "jti-123",
			},
		}
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(accessToken).Return(claims, nil)

		jti, session, err := s.service.extractSessionFromAccessToken(ctx, accessToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid session_id")
		assert.Empty(t, jti)
		assert.Nil(t, session)
	})

	s.T().Run("session not found - rejected", func(t *testing.T) {
		ctx := context.Background()
		accessToken := "token-for-nonexistent-session"
		tokenJTI := "jti-456"

		claims := &jwttoken.Claims{
			UserID:    userID.String(),
			SessionID: sessionID.String(),
			RegisteredClaims: jwt.RegisteredClaims{
				ID: tokenJTI,
			},
		}
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(accessToken).Return(claims, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).
			Return(nil, errors.New("session not found"))

		jti, session, err := s.service.extractSessionFromAccessToken(ctx, accessToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "session not found")
		assert.Empty(t, jti)
		assert.Nil(t, session)
	})
}

// TestIsTokenRevoked tests TRL checking
func (s *ServiceSuite) TestIsTokenRevoked() {
	s.T().Run("token revoked", func(t *testing.T) {
		ctx := context.Background()
		jti := "revoked-jti"

		s.mockTRL.EXPECT().IsRevoked(gomock.Any(), jti).Return(true, nil)

		revoked, err := s.service.IsTokenRevoked(ctx, jti)
		assert.NoError(t, err)
		assert.True(t, revoked)
	})

	s.T().Run("token not revoked", func(t *testing.T) {
		ctx := context.Background()
		jti := "active-jti"

		s.mockTRL.EXPECT().IsRevoked(gomock.Any(), jti).Return(false, nil)

		revoked, err := s.service.IsTokenRevoked(ctx, jti)
		assert.NoError(t, err)
		assert.False(t, revoked)
	})

	s.T().Run("TRL error", func(t *testing.T) {
		ctx := context.Background()
		jti := "some-jti"

		s.mockTRL.EXPECT().IsRevoked(gomock.Any(), jti).
			Return(false, errors.New("redis connection error"))

		revoked, err := s.service.IsTokenRevoked(ctx, jti)
		assert.Error(t, err)
		assert.False(t, revoked)
	})
}
