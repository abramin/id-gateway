package jwttoken

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"credo/internal/facts"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AccessTokenClaims represents the JWT claims for our access tokens
type AccessTokenClaims struct {
	UserID    string   `json:"user_id"`
	SessionID string   `json:"session_id"`
	ClientID  string   `json:"client_id"`
	TenantID  string   `json:"tenant_id,omitempty"`
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
	tenantID string,
	scopes []string,
) (string, string, error) {
	newToken, err := s.GenerateAccessToken(userID, sessionID, clientID, tenantID, scopes)
	if err != nil {
		return "", "", err
	}
	// Extract the JTI from the token
	parsed, err := jwt.ParseWithClaims(newToken, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.signingKey, nil
	})
	if err != nil {
		return "", "", err
	}
	claims, ok := parsed.Claims.(*AccessTokenClaims)
	if !ok {
		return "", "", errors.New("invalid token claims")
	}
	return newToken, claims.ID, nil
}

func (s *JWTService) GenerateAccessToken(
	userID uuid.UUID,
	sessionID uuid.UUID,
	clientID string,
	tenantID string,
	scopes []string,
) (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	jti := hex.EncodeToString(b)

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, AccessTokenClaims{
		UserID:    userID.String(),
		SessionID: sessionID.String(),
		ClientID:  clientID,
		TenantID:  tenantID,
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

func (s *JWTService) ParseTokenSkipClaimsValidation(tokenString string) (*AccessTokenClaims, error) {
	if tokenString == "" {
		return nil, errors.New("empty token")
	}

	claims := new(AccessTokenClaims)

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing algorithm: %s", t.Method.Alg())
		}
		return s.signingKey, nil
	},
		jwt.WithoutClaimsValidation(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return nil, fmt.Errorf("invalid jwt signature: %w", err)
		}
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

func (s *JWTService) ValidateToken(tokenString string) (*AccessTokenClaims, error) {
	var err error
	parsed, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenUnverifiable
		}
		return s.signingKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("token has expired: %w", facts.ErrExpired)
		}
		return nil, fmt.Errorf("invalid token: %w", facts.ErrInvalidInput)
	}

	if !parsed.Valid {
		return nil, fmt.Errorf("invalid token: %w", facts.ErrInvalidInput)
	}

	claims, ok := parsed.Claims.(*AccessTokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims: %w", facts.ErrInvalidInput)
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
			return nil, fmt.Errorf("token has expired: %w", facts.ErrExpired)
		}
		return nil, fmt.Errorf("invalid token: %w", facts.ErrInvalidInput)
	}

	if !parsed.Valid {
		return nil, fmt.Errorf("invalid token: %w", facts.ErrInvalidInput)
	}

	claims, ok := parsed.Claims.(*IDTokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims: %w", facts.ErrInvalidInput)
	}

	return claims, nil
}

func (s *JWTService) CreateRefreshToken() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	base64Token := base64.RawURLEncoding.EncodeToString(randomBytes)
	return base64Token, nil
}
