package service

import (
	"context"
	"errors"
	"time"

	"credo/internal/auth/models"
	jwttoken "credo/internal/jwt_token"
	id "credo/pkg/domain"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/mock/gomock"
)

// TestRevokeToken tests the RevokeToken endpoint (PRD-016 FR-3)
//
// AGENTS.MD JUSTIFICATION (per testing.md doctrine):
// These unit tests verify behaviors NOT covered by Gherkin:
// - hint inference: Tests internal token type detection without hint
// - TRL failure: Tests partial failure handling (session revoked despite TRL error)
// - refresh deletion failure: Tests partial failure handling
func (s *ServiceSuite) TestTokenRevocation_PartialFailureHandling() {
	sessionID := id.SessionID(uuid.New())
	userID := id.UserID(uuid.New())
	clientUUID := id.ClientID(uuid.New())
	jti := "access-token-jti-123"

	validSession := &models.Session{
		ID:                 sessionID,
		UserID:             userID,
		ClientID:           clientUUID,
		Status:             models.SessionStatusActive,
		LastAccessTokenJTI: jti,
		CreatedAt:          time.Now().Add(-1 * time.Hour),
		ExpiresAt:          time.Now().Add(23 * time.Hour),
	}

	s.Run("hint inference - access token without hint", func() {
		ctx := context.Background()
		accessToken := "mock-access-token"
		tokenJTI := "token-jti-789"

		sess := *validSession
		sess.LastAccessTokenJTI = tokenJTI

		claims := &jwttoken.AccessTokenClaims{
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
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		err := s.service.RevokeToken(ctx, accessToken, "") // No hint
		s.Require().NoError(err)
	})

	s.Run("TRL failure - session still revoked", func() {
		ctx := context.Background()
		accessToken := "mock-access-token"
		tokenJTI := "token-jti-abc"

		sess := *validSession
		sess.LastAccessTokenJTI = tokenJTI

		claims := &jwttoken.AccessTokenClaims{
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
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		err := s.service.RevokeToken(ctx, accessToken, TokenHintAccessToken)
		s.Require().NoError(err) // Should succeed even if TRL fails
	})

	s.Run("refresh token deletion failure - session still revoked", func() {
		ctx := context.Background()
		accessToken := "mock-access-token"
		tokenJTI := "token-jti-def"

		sess := *validSession
		sess.LastAccessTokenJTI = tokenJTI

		claims := &jwttoken.AccessTokenClaims{
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
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		err := s.service.RevokeToken(ctx, accessToken, TokenHintAccessToken)
		s.Require().NoError(err) // Should succeed even if refresh deletion fails
	})
}

// TestAccessTokenVerification tests JWT signature verification
func (s *ServiceSuite) TestAccessTokenVerification() {
	sessionID := id.SessionID(uuid.New())
	userID := id.UserID(uuid.New())
	clientUUID := id.ClientID(uuid.New())

	validSession := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		ClientID:  clientUUID,
		Status:    models.SessionStatusActive,
		CreatedAt: time.Now().Add(-1 * time.Hour),
		ExpiresAt: time.Now().Add(23 * time.Hour),
	}

	s.Run("valid signature - success", func() {
		ctx := context.Background()
		accessToken := "valid-jwt-token"
		tokenJTI := "jti-123"

		claims := &jwttoken.AccessTokenClaims{
			UserID:    userID.String(),
			SessionID: sessionID.String(),
			RegisteredClaims: jwt.RegisteredClaims{
				ID: tokenJTI,
			},
		}
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(accessToken).Return(claims, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(validSession, nil)

		jti, session, err := s.service.extractSessionFromAccessToken(ctx, accessToken)
		s.Require().NoError(err)
		s.Equal(tokenJTI, jti)
		s.Equal(sessionID, session.ID)
	})

	s.Run("invalid signature - rejected", func() {
		ctx := context.Background()
		invalidToken := "invalid-signature-token"

		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(invalidToken).
			Return(nil, errors.New("invalid jwt signature or format: signature is invalid"))

		jti, session, err := s.service.extractSessionFromAccessToken(ctx, invalidToken)
		s.Require().Error(err)
		s.Contains(err.Error(), "invalid jwt signature")
		s.Empty(jti)
		s.Nil(session)
	})

	s.Run("algorithm confusion attack - rejected", func() {
		ctx := context.Background()
		maliciousToken := "token-with-wrong-algorithm"

		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(maliciousToken).
			Return(nil, errors.New("unexpected signing method: HS512"))

		jti, session, err := s.service.extractSessionFromAccessToken(ctx, maliciousToken)
		s.Require().Error(err)
		s.Contains(err.Error(), "unexpected signing method")
		s.Empty(jti)
		s.Nil(session)
	})

	s.Run("malformed token - rejected", func() {
		ctx := context.Background()
		malformedToken := "not.a.valid.jwt.token.at.all"

		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(malformedToken).
			Return(nil, errors.New("invalid jwt signature or format: token contains an invalid number of segments"))

		jti, session, err := s.service.extractSessionFromAccessToken(ctx, malformedToken)
		s.Require().Error(err)
		s.Contains(err.Error(), "invalid jwt signature")
		s.Empty(jti)
		s.Nil(session)
	})

	s.Run("expired token - signature still verified", func() {
		ctx := context.Background()
		expiredToken := "expired-but-valid-signature-token"
		expiredJTI := "expired-jti"

		// Expired tokens should still parse successfully
		claims := &jwttoken.AccessTokenClaims{
			UserID:    userID.String(),
			SessionID: sessionID.String(),
			RegisteredClaims: jwt.RegisteredClaims{
				ID: expiredJTI,
			},
		}
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(expiredToken).Return(claims, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(validSession, nil)

		extractedJTI, session, err := s.service.extractSessionFromAccessToken(ctx, expiredToken)
		s.Require().NoError(err) // Expiration should be ignored, signature verified
		s.Equal(expiredJTI, extractedJTI)
		s.Equal(sessionID, session.ID)
	})

	s.Run("invalid session_id in claims - rejected", func() {
		ctx := context.Background()
		accessToken := "token-with-invalid-session-id"

		claims := &jwttoken.AccessTokenClaims{
			UserID:    userID.String(),
			SessionID: "not-a-valid-uuid",
			RegisteredClaims: jwt.RegisteredClaims{
				ID: "jti-123",
			},
		}
		s.mockJWT.EXPECT().ParseTokenSkipClaimsValidation(accessToken).Return(claims, nil)

		jti, session, err := s.service.extractSessionFromAccessToken(ctx, accessToken)
		s.Require().Error(err)
		s.Contains(err.Error(), "invalid session_id")
		s.Empty(jti)
		s.Nil(session)
	})

	s.Run("session not found - rejected", func() {
		ctx := context.Background()
		accessToken := "token-for-nonexistent-session"
		tokenJTI := "jti-456"

		claims := &jwttoken.AccessTokenClaims{
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
		s.Require().Error(err)
		s.Contains(err.Error(), "session not found")
		s.Empty(jti)
		s.Nil(session)
	})
}

// TestTokenRevocationLookup tests TRL checking
func (s *ServiceSuite) TestTokenRevocationLookup() {
	s.Run("token revoked", func() {
		ctx := context.Background()
		jti := "revoked-jti"

		s.mockTRL.EXPECT().IsRevoked(gomock.Any(), jti).Return(true, nil)

		revoked, err := s.service.IsTokenRevoked(ctx, jti)
		s.Require().NoError(err)
		s.True(revoked)
	})

	s.Run("token not revoked", func() {
		ctx := context.Background()
		jti := "active-jti"

		s.mockTRL.EXPECT().IsRevoked(gomock.Any(), jti).Return(false, nil)

		revoked, err := s.service.IsTokenRevoked(ctx, jti)
		s.Require().NoError(err)
		s.False(revoked)
	})

	s.Run("TRL error", func() {
		ctx := context.Background()
		jti := "some-jti"

		s.mockTRL.EXPECT().IsRevoked(gomock.Any(), jti).
			Return(false, errors.New("redis connection error"))

		revoked, err := s.service.IsTokenRevoked(ctx, jti)
		s.Require().Error(err)
		s.False(revoked)
	})
}
