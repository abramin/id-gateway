package config

import (
	"os"
	"time"
)

// Server captures HTTP server level configuration.
type Server struct {
	Addr          string
	RegulatedMode bool
	JWTSigningKey string
	TokenTTL      time.Duration
	ConsentTTL    time.Duration
}

// RegistryCacheTTL enforces retention for sensitive registry data.
var RegistryCacheTTL = 5 * time.Minute
var TokenTTL = 15 * time.Minute
var ConsentTTL = 365 * 24 * time.Hour // 1 year

// FromEnv builds a Server config from environment variables so main stays lean.
func FromEnv() Server {
	addr := os.Getenv("ID_GATEWAY_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	regulated := os.Getenv("REGULATED_MODE") == "true"
	tokenTTLStr := os.Getenv("TOKEN_TTL")
	if tokenTTLStr != "" {
		if duration, err := time.ParseDuration(tokenTTLStr); err == nil {
			TokenTTL = duration
		}
	}

	consentTTLStr := os.Getenv("CONSENT_TTL")
	if consentTTLStr != "" {
		if duration, err := time.ParseDuration(consentTTLStr); err == nil {
			ConsentTTL = duration
		}
	}

	jwtSigningKey := os.Getenv("JWT_SIGNING_KEY")
	if jwtSigningKey == "" {
		// Use a default for development - should be overridden in production
		jwtSigningKey = "dev-secret-key-change-in-production"
	}

	return Server{
		Addr:          addr,
		RegulatedMode: regulated,
		JWTSigningKey: jwtSigningKey,
		TokenTTL:      TokenTTL,
	}
}
