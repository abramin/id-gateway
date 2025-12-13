package jwttoken

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	dErrors "credo/pkg/domain-errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents the JWT claims for our access tokens
type Claims struct {
	UserID    string   `json:"user_id"`
	SessionID string   `json:"session_id"`
	ClientID  string   `json:"client_id"`
	Env       string   `json:"env,omitempty"`
	Scope     []string `json:"scope"`
	jwt.RegisteredClaims
}

// IDTokenClaims represents OIDC-compliant ID token claims.
// It keeps the standard subject while carrying session and client references.
type IDTokenClaims struct {
	SessionID string `json:"sid,omitempty"`
	ClientID  string `json:"azp,omitempty"`
	Env       string `json:"env,omitempty"`
	jwt.RegisteredClaims
}

// JWTService handles JWT creation and validation
type JWTService struct {
	signingKey []byte
	issuer     string
	audience   string
	tokenTTL   time.Duration
	env        string
}

func NewJWTService(signingKey string, issuer string, audience string, tokenTTL time.Duration) *JWTService {
	return &JWTService{
		signingKey: []byte(signingKey),
		issuer:     issuer,
		audience:   audience,
		tokenTTL:   tokenTTL,
	}
}

func (s *JWTService) GenerateAccessTokenWithJTI(
	userID uuid.UUID,
	sessionID uuid.UUID,
	clientID string,
	scopes []string,
) (string, string, error) {
	newToken, err := s.GenerateAccessToken(userID, sessionID, clientID, scopes)
	if err != nil {
		return "", "", err
	}
	// Extract the JTI from the token
	parsed, err := jwt.ParseWithClaims(newToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return s.signingKey, nil
	})
	if err != nil {
		return "", "", err
	}
	claims, ok := parsed.Claims.(*Claims)
	if !ok {
		return "", "", errors.New("invalid token claims")
	}
	return newToken, claims.ID, nil
}

func (s *JWTService) GenerateAccessToken(
	userID uuid.UUID,
	sessionID uuid.UUID,
	clientID string,
	scopes []string,
) (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	jti := hex.EncodeToString(b)

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID:    userID.String(),
		SessionID: sessionID.String(),
		ClientID:  clientID,
		Env:       s.env,
		Scope:     scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    s.issuer,
			Audience:  []string{s.audience},
			ID:        jti,
		},
	})

	signedToken, err := newToken.SignedString(s.signingKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func (s *JWTService) ParseTokenSkipClaimsValidation(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("empty token")
	}

	claims := new(Claims)

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing algorithm: %s", t.Method.Alg())
		}
		return s.signingKey, nil
	},
		jwt.WithoutClaimsValidation(),
	)
	if err != nil {
		return nil, fmt.Errorf("jwt parse failed: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid jwt signature")
	}

	return claims, nil
}

func (s *JWTService) GenerateIDToken(
	userID uuid.UUID,
	sessionID uuid.UUID,
	clientID string) (string, error) {
	now := time.Now()
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, IDTokenClaims{
		SessionID: sessionID.String(),
		ClientID:  clientID,
		Env:       s.env,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(), // OIDC sub
			ExpiresAt: jwt.NewNumericDate(now.Add(s.tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.issuer,
			Audience:  []string{s.audience},
			ID:        uuid.NewString(),
		},
	})

	signedToken, err := newToken.SignedString(s.signingKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

// SetEnv annotates issued tokens with an environment string (e.g., \"demo\").
func (s *JWTService) SetEnv(env string) {
	s.env = env
}

func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	var err error
	parsed, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenUnverifiable
		}
		return s.signingKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, dErrors.New(dErrors.CodeUnauthorized, "token has expired")
		}
		return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid token")
	}

	if !parsed.Valid {
		return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid token")
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok {
		return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid token claims")
	}

	return claims, nil
}

func (s *JWTService) ValidateIDToken(tokenString string) (*IDTokenClaims, error) {
	parsed, err := jwt.ParseWithClaims(tokenString, &IDTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenUnverifiable
		}
		return s.signingKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, dErrors.New(dErrors.CodeUnauthorized, "token has expired")
		}
		return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid token")
	}

	if !parsed.Valid {
		return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid token")
	}

	claims, ok := parsed.Claims.(*IDTokenClaims)
	if !ok {
		return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid token claims")
	}

	return claims, nil
}

func (s *JWTService) CreateRefreshToken() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", dErrors.Wrap(err, dErrors.CodeInternal, "failed to generate refresh token")
	}

	base64Token := base64.RawURLEncoding.EncodeToString(randomBytes)
	return base64Token, nil
}
