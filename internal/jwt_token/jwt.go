package jwttoken

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents the JWT claims for our access tokens
type Claims struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	ClientID  string `json:"client_id"`
	jwt.RegisteredClaims
}

// JWTService handles JWT creation and validation
type JWTService struct {
	signingKey []byte
	issuer     string
	audience   string
}

// NewJWTService creates a new JWT service
// TODO: Implement this function
// - Store the signingKey, issuer, and audience in the struct
// - Return a pointer to the JWTService
func NewJWTService(signingKey string, issuer string, audience string) *JWTService {
	// TODO: Your implementation here
	panic("not implemented")
}

// GenerateAccessToken creates a new JWT access token for a user session
// TODO: Implement this function
// - Create a new Claims struct with:
//   - UserID, SessionID, ClientID from parameters
//   - ExpiresAt set to current time + expiresIn duration
//   - IssuedAt set to current time
//   - Issuer and Audience from the service
//
// - Create a new JWT token with HS256 signing method
// - Sign the token with the signing key
// - Return the signed token string
func (s *JWTService) GenerateAccessToken(userID uuid.UUID, sessionID uuid.UUID, clientID string, expiresIn time.Duration) (string, error) {
	// TODO: Your implementation here
	// Hint: Use jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Hint: Then call token.SignedString(s.signingKey)
	panic("not implemented")
}

// ValidateToken validates a JWT token and returns the claims
// TODO: Implement this function
// - Parse the token string with the Claims struct
// - Validate the signing method is HMAC
// - Verify the token with the signing key
// - Check if token is expired
// - Return the claims if valid, error otherwise
func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	// TODO: Your implementation here
	// Hint: Use jwt.ParseWithClaims(tokenString, &Claims{}, keyFunc)
	// Hint: The keyFunc should return your signing key
	// Hint: Check token.Valid before returning claims
	panic("not implemented")
}

// ExtractUserIDFromToken is a convenience method to get just the user ID
// TODO: Implement this function
// - Call ValidateToken to get claims
// - Parse the UserID string as UUID
// - Return the UUID
func (s *JWTService) ExtractUserIDFromToken(tokenString string) (uuid.UUID, error) {
	// TODO: Your implementation here
	panic("not implemented")
}

// ExtractSessionIDFromAuthHeader extracts and validates session ID from Authorization header
// TODO: Implement this function to maintain backward compatibility
// - Check for "Bearer " prefix
// - Extract the token
// - Call ValidateToken
// - Return the SessionID from claims
func (s *JWTService) ExtractSessionIDFromAuthHeader(authHeader string) (string, error) {
	// TODO: Your implementation here
	// This replaces the old placeholder function
	panic("not implemented")
}
