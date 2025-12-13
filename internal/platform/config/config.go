package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Server captures HTTP server level configuration.
type Server struct {
	Addr                   string
	RegulatedMode          bool
	DemoMode               bool
	Environment            string
	AllowedRedirectSchemes []string
	JWTSigningKey          string
	JWTIssuer              string
	TokenTTL               time.Duration
	ConsentTTL             time.Duration
	ConsentGrantWindow     time.Duration
	SessionTTL             time.Duration
	AdminAPIToken          string
	DeviceBindingEnabled   bool
	DeviceCookieName       string
	DeviceCookieMaxAge     int
}

// RegistryCacheTTL enforces retention for sensitive registry data.
var RegistryCacheTTL = 5 * time.Minute
var TokenTTL = 15 * time.Minute
var ConsentTTL = 365 * 24 * time.Hour // 1 year
var ConsentGrantWindow = 5 * time.Minute
var SessionTTL = 24 * time.Hour
var JWTIssuer = "credo"

// FromEnv builds a Server config from environment variables so main stays lean.
func FromEnv() (Server, error) {
	addr := os.Getenv("ID_GATEWAY_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	env := os.Getenv("CRENE_ENV")
	demoMode := env == "demo"
	if env == "" {
		env = "local"
	}
	regulated := os.Getenv("REGULATED_MODE") == "true"
	allowedRedirectSchemes := parseAllowedRedirectSchemes(os.Getenv("ALLOWED_REDIRECT_SCHEMES"), env)
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

	// TODO: revisit this as possible security issue
	adminAPIToken := os.Getenv("ADMIN_API_TOKEN")
	if adminAPIToken == "" {
		switch strings.ToLower(env) {
		case "local", "dev", "development", "testing", "test":
			adminAPIToken = "demo-admin-token"
		}
	}

	deviceBindingEnabled := os.Getenv("DEVICE_BINDING_ENABLED") == "true"
	deviceCookieName := os.Getenv("DEVICE_COOKIE_NAME")
	if deviceCookieName == "" {
		deviceCookieName = "__Secure-Device-ID"
	}
	deviceCookieMaxAge := 31536000 // 1 year
	if raw := os.Getenv("DEVICE_COOKIE_MAX_AGE"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			deviceCookieMaxAge = parsed
		}
	}

	jwtSigningKey := os.Getenv("JWT_SIGNING_KEY")
	if jwtSigningKey == "" {
		// Use a default for development - should be overridden in production
		jwtSigningKey = "dev-secret-key-change-in-production"
	}
	JWTIssuer = os.Getenv("JWT_ISSUER")
	if JWTIssuer == "" {
		JWTIssuer = "credo"
	}
	if demoMode {
		// Fail fast if any production-looking variables are present
		prodVars := []string{"DB_URL", "JWT_SIGNING_KEY", "REDIS_URL"}
		for _, key := range prodVars {
			if val := os.Getenv(key); val != "" {
				return Server{}, fmt.Errorf("refusing to start demo env with production variables: %s", key)
			}
		}
		for _, kv := range os.Environ() {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 && strings.Contains(strings.ToLower(parts[0]), "prod") {
				return Server{}, fmt.Errorf("refusing to start demo env with production variables: %s", parts[0])
			}
		}
		jwtSigningKey = "demo-signing-key-change-me-locally"
		JWTIssuer = "credo-demo"
		regulated = false
		if adminAPIToken == "" {
			adminAPIToken = "demo-admin-token"
		}
	}

	return Server{
		Addr:                   addr,
		RegulatedMode:          regulated,
		DemoMode:               demoMode,
		Environment:            env,
		JWTSigningKey:          jwtSigningKey,
		JWTIssuer:              JWTIssuer,
		AllowedRedirectSchemes: allowedRedirectSchemes,
		TokenTTL:               TokenTTL,
		ConsentTTL:             ConsentTTL,
		ConsentGrantWindow:     ConsentGrantWindow,
		SessionTTL:             SessionTTL,
		AdminAPIToken:          adminAPIToken,
		DeviceBindingEnabled:   deviceBindingEnabled,
		DeviceCookieName:       deviceCookieName,
		DeviceCookieMaxAge:     deviceCookieMaxAge,
	}, nil
}

func parseAllowedRedirectSchemes(raw, env string) []string {
	if raw != "" {
		parts := strings.Split(raw, ",")
		normalized := make([]string, 0, len(parts))
		for _, p := range parts {
			scheme := strings.ToLower(strings.TrimSpace(p))
			if scheme != "" {
				normalized = append(normalized, scheme)
			}
		}
		if len(normalized) > 0 {
			return normalized
		}
	}

	switch strings.ToLower(env) {
	case "local", "dev", "development", "demo", "testing", "test":
		return []string{"http", "https"}
	default:
		return []string{"https"}
	}
}
