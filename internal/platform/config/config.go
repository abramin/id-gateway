package config

import (
	"os"
	"time"
)

// Server captures HTTP server level configuration.
type Server struct {
	Addr               string
	RegulatedMode      bool
	JWTSigningKey      string
	TokenTTL           time.Duration
	ConsentTTL         time.Duration
	ConsentGrantWindow time.Duration
	SessionTTL         time.Duration
}

// RegistryCacheTTL enforces retention for sensitive registry data.
var RegistryCacheTTL = 5 * time.Minute
var TokenTTL = 15 * time.Minute
var ConsentTTL = 365 * 24 * time.Hour // 1 year
var ConsentGrantWindow = 1 * time.Second
var SessionTTL = 24 * time.Hour

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

	consentGrantWindowStr := os.Getenv("CONSENT_GRANT_WINDOW")
	if consentGrantWindowStr != "" {
		if duration, err := time.ParseDuration(consentGrantWindowStr); err == nil {
			ConsentGrantWindow = duration
		}
	}

	SessionTTLStr := os.Getenv("SESSION_TTL")
	if SessionTTLStr != "" {
		if duration, err := time.ParseDuration(SessionTTLStr); err == nil {
			SessionTTL = duration
		}
	}

	jwtSigningKey := os.Getenv("JWT_SIGNING_KEY")
	if jwtSigningKey == "" {
		// Use a default for development - should be overridden in production
		jwtSigningKey = "dev-secret-key-change-in-production"
	}

	return Server{
		Addr:               addr,
		RegulatedMode:      regulated,
		JWTSigningKey:      jwtSigningKey,
		TokenTTL:           TokenTTL,
		ConsentTTL:         ConsentTTL,
		ConsentGrantWindow: ConsentGrantWindow,
		SessionTTL:         SessionTTL,
	}
}
