package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Server holds core HTTP server configuration (shared across all modules)
type Server struct {
	Addr        string
	Environment string
	DemoMode    bool

	// Module configs
	Auth     AuthConfig
	Consent  ConsentConfig
	Registry RegistryConfig

	// Security
	Security SecurityConfig

	// RateLimiting
	DisableRateLimiting bool
}

// AuthConfig holds authentication and session configuration
type AuthConfig struct {
	JWTSigningKey                  string
	JWTIssuerBaseURL               string // Base URL for per-tenant issuers (RFC 8414)
	JWTAudience                    string
	TokenTTL                       time.Duration
	SessionTTL                     time.Duration
	TokenRevocationCleanupInterval time.Duration
	AuthCleanupInterval            time.Duration
	AllowedRedirectSchemes         []string
	DeviceBindingEnabled           bool
	DeviceCookieName               string
	DeviceCookieMaxAge             int
}

// ConsentConfig holds consent management configuration
type ConsentConfig struct {
	ConsentTTL         time.Duration
	ConsentGrantWindow time.Duration
	ReGrantCooldown    time.Duration
}

// RegistryConfig holds registry integration configuration
type RegistryConfig struct {
	CacheTTL           time.Duration
	CitizenRegistryURL string
	CitizenAPIKey      string
	RegistryTimeout    time.Duration
}

// SecurityConfig holds security and compliance settings
type SecurityConfig struct {
	RegulatedMode bool
	AdminAPIToken string
}

// Defaults
var (
	DefaultTokenTTL                       = 15 * time.Minute
	DefaultSessionTTL                     = 24 * time.Hour
	DefaultTokenRevocationCleanupInterval = 5 * time.Minute
	DefaultAuthCleanupInterval            = 5 * time.Minute
	DefaultConsentTTL                     = 365 * 24 * time.Hour
	DefaultConsentGrantWindow             = 5 * time.Minute
	DefaultConsentReGrantCooldown         = 5 * time.Minute
	DefaultRegistryCacheTTL               = 5 * time.Minute
	DefaultCitizenRegistryURL             = "http://localhost:8082"
	DefaultCitizenAPIKey                  = "citizen-registry-secret-key"
	DefaultRegistryTimeout                = 5 * time.Second
	DefaultDeviceCookieName               = "__Secure-Device-ID"
	DefaultDeviceCookieMaxAge             = 31536000 // 1 year
)

// FromEnv builds config from environment variables
func FromEnv() (Server, error) {
	env := getEnv("CREDO_ENV", "local")
	demoMode := env == "demo"
	disableRateLimiting := os.Getenv("DISABLE_RATE_LIMITING") == "true"

	cfg := Server{
		Addr:                getEnv("ID_GATEWAY_ADDR", ":8080"),
		Environment:         env,
		DemoMode:            demoMode,
		Auth:                loadAuthConfig(env, demoMode),
		Consent:             loadConsentConfig(),
		Registry:            loadRegistryConfig(),
		Security:            loadSecurityConfig(env, demoMode),
		DisableRateLimiting: disableRateLimiting,
	}

	if demoMode {
		if err := validateDemoMode(); err != nil {
			return Server{}, err
		}
	}

	return cfg, nil
}

func loadAuthConfig(env string, demoMode bool) AuthConfig {
	jwtSigningKey := os.Getenv("JWT_SIGNING_KEY")
	jwtIssuerBaseURL := getEnv("JWT_ISSUER_BASE_URL", "http://localhost:8080")
	jwtAudience := getEnv("JWT_AUDIENCE", "credo-client")

	if demoMode {
		jwtSigningKey = "demo-signing-key-change-me-locally"
		jwtIssuerBaseURL = "http://localhost:8080"
	} else if jwtSigningKey == "" {
		jwtSigningKey = "dev-secret-key-change-in-production"
	}

	return AuthConfig{
		JWTSigningKey:                  jwtSigningKey,
		JWTIssuerBaseURL:               jwtIssuerBaseURL,
		JWTAudience:                    jwtAudience,
		TokenTTL:                       parseDuration("TOKEN_TTL", DefaultTokenTTL),
		SessionTTL:                     parseDuration("SESSION_TTL", DefaultSessionTTL),
		TokenRevocationCleanupInterval: parseDuration("TOKEN_REVOCATION_CLEANUP_INTERVAL", DefaultTokenRevocationCleanupInterval),
		AuthCleanupInterval:            parseDuration("AUTH_CLEANUP_INTERVAL", DefaultAuthCleanupInterval),
		AllowedRedirectSchemes:         parseAllowedRedirectSchemes(os.Getenv("ALLOWED_REDIRECT_SCHEMES"), env),
		DeviceBindingEnabled:           os.Getenv("DEVICE_BINDING_ENABLED") == "true",
		DeviceCookieName:               getEnv("DEVICE_COOKIE_NAME", DefaultDeviceCookieName),
		DeviceCookieMaxAge:             parseInt("DEVICE_COOKIE_MAX_AGE", DefaultDeviceCookieMaxAge),
	}
}

func loadConsentConfig() ConsentConfig {
	return ConsentConfig{
		ConsentTTL:         parseDuration("CONSENT_TTL", DefaultConsentTTL),
		ConsentGrantWindow: parseDuration("CONSENT_GRANT_WINDOW", DefaultConsentGrantWindow),
		ReGrantCooldown:    parseDuration("CONSENT_REGRANT_COOLDOWN", DefaultConsentReGrantCooldown),
	}
}

func loadRegistryConfig() RegistryConfig {
	return RegistryConfig{
		CacheTTL:           parseDuration("REGISTRY_CACHE_TTL", DefaultRegistryCacheTTL),
		CitizenRegistryURL: getEnv("CITIZEN_REGISTRY_URL", DefaultCitizenRegistryURL),
		CitizenAPIKey:      getEnv("CITIZEN_REGISTRY_API_KEY", DefaultCitizenAPIKey),
		RegistryTimeout:    parseDuration("REGISTRY_TIMEOUT", DefaultRegistryTimeout),
	}
}

func loadSecurityConfig(env string, demoMode bool) SecurityConfig {
	// REGULATED_MODE env var takes precedence; if unset, demo mode defaults to unregulated
	regulatedEnv := os.Getenv("REGULATED_MODE")
	var regulated bool
	if regulatedEnv != "" {
		regulated = regulatedEnv == "true"
	} else if demoMode {
		regulated = false
	}

	adminToken := os.Getenv("ADMIN_API_TOKEN")
	if adminToken == "" {
		switch strings.ToLower(env) {
		case "local", "dev", "development", "testing", "test", "demo":
			adminToken = "demo-admin-token"
		}
	}

	return SecurityConfig{
		RegulatedMode: regulated,
		AdminAPIToken: adminToken,
	}
}

// Helper functions

func getEnv(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

func parseDuration(key string, defaultValue time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			return duration
		}
	}
	return defaultValue
}

func parseInt(key string, defaultValue int) int {
	if val := os.Getenv(key); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultValue
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

	// Environment-based defaults
	switch strings.ToLower(env) {
	case "local", "dev", "development", "demo", "testing", "test":
		return []string{"http", "https"}
	default:
		return []string{"https"}
	}
}

func validateDemoMode() error {
	prodVars := []string{"DB_URL", "JWT_SIGNING_KEY", "REDIS_URL"}
	for _, key := range prodVars {
		if val := os.Getenv(key); val != "" {
			return fmt.Errorf("refusing to start demo env with production variables: %s", key)
		}
	}

	for _, kv := range os.Environ() {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 && strings.Contains(strings.ToLower(parts[0]), "prod") {
			return fmt.Errorf("refusing to start demo env with production variables: %s", parts[0])
		}
	}

	return nil
}
