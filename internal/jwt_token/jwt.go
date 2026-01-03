package jwttoken

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/requestcontext"

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
	signingKey    []byte
	issuerBaseURL string // Base URL for per-tenant issuers (RFC 8414)
	audience      string
	tokenTTL      time.Duration
	env           string
}

func NewJWTService(signingKey string, issuerBaseURL string, audience string, tokenTTL time.Duration) *JWTService {
	return &JWTService{
		signingKey:    []byte(signingKey),
		issuerBaseURL: issuerBaseURL,
		audience:      audience,
		tokenTTL:      tokenTTL,
	}
}

// BuildIssuer constructs a per-tenant issuer URL following RFC 8414 format.
// Format: {baseURL}/tenants/{tenantID}
func (s *JWTService) BuildIssuer(tenantID id.TenantID) string {
	if tenantID.IsNil() {
		return s.issuerBaseURL
	}
	return fmt.Sprintf("%s/tenants/%s", s.issuerBaseURL, tenantID.String())
}

// ExtractTenantFromIssuer parses a tenant ID from a per-tenant issuer URL.
// Returns the tenant ID if the issuer matches the expected format, or an error otherwise.
func (s *JWTService) ExtractTenantFromIssuer(issuer string) (string, error) {
	prefix := s.issuerBaseURL + "/tenants/"
	if len(issuer) > len(prefix) && issuer[:len(prefix)] == prefix {
		return issuer[len(prefix):], nil
	}
	// Fallback: if issuer equals base URL exactly (no tenant), return empty
	if issuer == s.issuerBaseURL {
		return "", nil
	}
	return "", dErrors.New(dErrors.CodeInvalidInput, "invalid issuer format")
}

func (s *JWTService) GenerateAccessTokenWithJTI(
	ctx context.Context,
	userID id.UserID,
	sessionID id.SessionID,
	clientID id.ClientID,
	tenantID id.TenantID,
	scopes []string,
) (string, string, error) {
	newToken, err := s.GenerateAccessToken(ctx, userID, sessionID, clientID, tenantID, scopes)
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
		return "", "", dErrors.New(dErrors.CodeInvalidInput, "invalid token claims")
	}
	return newToken, claims.ID, nil
}

func (s *JWTService) GenerateAccessToken(
	ctx context.Context,
	userID id.UserID,
	sessionID id.SessionID,
	clientID id.ClientID,
	tenantID id.TenantID,
	scopes []string,
) (string, error) {
	if len(scopes) == 0 {
		return "", dErrors.New(dErrors.CodeInvalidInput, "scopes cannot be empty")
	}

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	jti := hex.EncodeToString(b)
	now := requestcontext.Now(ctx)

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, AccessTokenClaims{
		UserID:    userID.String(),
		SessionID: sessionID.String(),
		ClientID:  clientID.String(),
		TenantID:  tenantID.String(),
		Env:       s.env,
		Scope:     scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.BuildIssuer(tenantID),
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

// ParseTokenSkipClaimsValidation parses a token WITHOUT validating expiration or standard claims.
//
// SECURITY WARNING: This method should ONLY be used in specific scenarios:
//   - Token refresh flows where the old token may be expired
//   - Token revocation where we need to extract JTI from expired tokens
//
// This method STILL validates:
//   - Signature (token must be signed with our key)
//   - Algorithm (must be HS256)
//
// Callers MUST perform additional business validation:
//   - Check refresh token validity in database
//   - Verify session is still active
//   - Apply rate limiting to prevent abuse
func (s *JWTService) ParseTokenSkipClaimsValidation(tokenString string) (*AccessTokenClaims, error) {
	if tokenString == "" {
		return nil, dErrors.New(dErrors.CodeInvalidInput, "empty token")
	}

	claims := new(AccessTokenClaims)

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, dErrors.New(dErrors.CodeInvalidInput, "unexpected signing algorithm")
		}
		return s.signingKey, nil
	},
		jwt.WithoutClaimsValidation(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return nil, dErrors.New(dErrors.CodeInvalidInput, "invalid jwt signature")
		}
		return nil, dErrors.New(dErrors.CodeInvalidInput, "jwt parse failed")
	}

	if !token.Valid {
		return nil, dErrors.New(dErrors.CodeInvalidInput, "invalid jwt signature")
	}

	return claims, nil
}

func (s *JWTService) GenerateIDToken(
	ctx context.Context,
	userID id.UserID,
	sessionID id.SessionID,
	clientID id.ClientID,
	tenantID id.TenantID) (string, error) {
	now := requestcontext.Now(ctx)
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, IDTokenClaims{
		SessionID: sessionID.String(),
		ClientID:  clientID.String(),
		Env:       s.env,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(), // OIDC sub
			ExpiresAt: jwt.NewNumericDate(now.Add(s.tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.BuildIssuer(tenantID),
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
	parsed, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, jwt.ErrTokenUnverifiable
		}
		return s.signingKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, dErrors.New(dErrors.CodeInvalidGrant, "token expired")
		}
		return nil, dErrors.New(dErrors.CodeInvalidInput, "invalid token")
	}

	if !parsed.Valid {
		return nil, dErrors.New(dErrors.CodeInvalidInput, "invalid token")
	}

	claims, ok := parsed.Claims.(*AccessTokenClaims)
	if !ok {
		return nil, dErrors.New(dErrors.CodeInvalidInput, "invalid token claims")
	}

	// Explicit issuer validation: token issuer must match our configured base URL
	if !strings.HasPrefix(claims.Issuer, s.issuerBaseURL) {
		return nil, dErrors.New(dErrors.CodeInvalidInput, "invalid token issuer")
	}

	return claims, nil
}

func (s *JWTService) ValidateIDToken(tokenString string) (*IDTokenClaims, error) {
	parsed, err := jwt.ParseWithClaims(tokenString, &IDTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, jwt.ErrTokenUnverifiable
		}
		return s.signingKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, dErrors.New(dErrors.CodeInvalidGrant, "token expired")
		}
		return nil, dErrors.New(dErrors.CodeInvalidInput, "invalid token")
	}

	if !parsed.Valid {
		return nil, dErrors.New(dErrors.CodeInvalidInput, "invalid token")
	}

	claims, ok := parsed.Claims.(*IDTokenClaims)
	if !ok {
		return nil, dErrors.New(dErrors.CodeInvalidInput, "invalid token claims")
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
