package jwttoken

import (
	"credo/internal/platform/middleware"
)

func ToMiddlewareClaims(claims *Claims) *middleware.JWTClaims {
	return &middleware.JWTClaims{
		UserID:    claims.UserID,
		SessionID: claims.SessionID,
		ClientID:  claims.ClientID,
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
