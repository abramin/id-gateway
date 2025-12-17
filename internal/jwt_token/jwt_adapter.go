package jwttoken

import (
	"credo/internal/platform/middleware"
)

func ToMiddlewareClaims(claims *AccessTokenClaims) *middleware.JWTClaims {
	return &middleware.JWTClaims{
		UserID:    claims.UserID,
		SessionID: claims.SessionID,
		ClientID:  claims.ClientID,
		JTI:       claims.ID, // JWT ID for revocation tracking
	}
}

type JWTServiceAdapter struct {
	service *JWTService
}

func NewJWTServiceAdapter(service *JWTService) *JWTServiceAdapter {
	return &JWTServiceAdapter{service: service}
}

func (a *JWTServiceAdapter) ValidateToken(tokenString string) (*middleware.JWTClaims, error) {
	claims, err := a.service.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	return ToMiddlewareClaims(claims), nil
}
