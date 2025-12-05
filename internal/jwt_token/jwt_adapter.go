package jwttoken

import (
	"id-gateway/internal/platform/middleware"
)

// ToMiddlewareClaims converts our JWT Claims to the middleware interface format
// TODO: Implement this function
// - Take a *Claims parameter
// - Return a *middleware.JWTClaims
// - Map the fields: UserID, SessionID, ClientID
func ToMiddlewareClaims(claims *Claims) *middleware.JWTClaims {
	// TODO: Your implementation here
	panic("not implemented")
}

// JWTServiceAdapter adapts JWTService to implement middleware.JWTValidator interface
type JWTServiceAdapter struct {
	service *JWTService
}

// NewJWTServiceAdapter creates an adapter for the middleware
// TODO: Implement this function
// - Store the JWTService in the adapter struct
// - Return pointer to the adapter
func NewJWTServiceAdapter(service *JWTService) *JWTServiceAdapter {
	// TODO: Your implementation here
	panic("not implemented")
}

// ValidateToken implements the middleware.JWTValidator interface
// TODO: Implement this function
// - Call a.service.ValidateToken(tokenString)
// - If error, return nil and the error
// - If success, convert Claims to middleware.JWTClaims using ToMiddlewareClaims
// - Return the converted claims
func (a *JWTServiceAdapter) ValidateToken(tokenString string) (*middleware.JWTClaims, error) {
	// TODO: Your implementation here
	panic("not implemented")
}
