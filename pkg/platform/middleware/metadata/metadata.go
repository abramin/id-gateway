package metadata

import (
	"net/http"
	"net/netip"
	"strings"

	"credo/pkg/requestcontext"
)

// MaxXFFHeaderLength is the maximum allowed length for X-Forwarded-For header
// to prevent header injection attacks (PRD-017 TR-5).
const MaxXFFHeaderLength = 500

// Config holds configuration for the metadata middleware.
type Config struct {
	// TrustedProxies is a list of IP prefixes (CIDR notation) that are trusted
	// to set X-Forwarded-For headers. If empty, XFF is never trusted.
	TrustedProxies []netip.Prefix
}

// DefaultConfig returns a Config with no trusted proxies (secure by default).
func DefaultConfig() *Config {
	return &Config{
		TrustedProxies: nil,
	}
}

// Middleware handles client metadata extraction with configurable trusted proxies.
type Middleware struct {
	config *Config
}

// NewMiddleware creates a new metadata middleware with the given config.
func NewMiddleware(cfg *Config) *Middleware {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Middleware{config: cfg}
}

// Handler extracts client IP address and User-Agent from the request
// and adds them to the context for use by handlers and services.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := m.extractClientIP(r)
		userAgent := r.Header.Get("User-Agent")

		ctx := r.Context()
		ctx = requestcontext.WithClientMetadata(ctx, ip, userAgent)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractClientIP extracts the client IP with trusted proxy validation (PRD-017 TR-5).
func (m *Middleware) extractClientIP(r *http.Request) string {
	// Parse RemoteAddr to get the direct connection IP
	remoteIP := parseRemoteAddr(r.RemoteAddr)
	if remoteIP == "" {
		return "unknown"
	}

	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		// No XFF header, check X-Real-IP
		if xri := r.Header.Get("X-Real-IP"); xri != "" && m.isTrustedProxy(remoteIP) {
			if len(xri) <= MaxXFFHeaderLength {
				return strings.TrimSpace(xri)
			}
		}
		return remoteIP
	}

	// XFF header present - only trust if request came from trusted proxy
	if !m.isTrustedProxy(remoteIP) {
		// Request not from trusted proxy, use RemoteAddr
		return remoteIP
	}

	// Size limit to prevent header injection attacks
	if len(xff) > MaxXFFHeaderLength {
		return remoteIP
	}

	// Parse first IP in XFF chain (original client)
	var clientIP string
	if before, _, ok := strings.Cut(xff, ","); ok {
		clientIP = strings.TrimSpace(before)
	} else {
		clientIP = strings.TrimSpace(xff)
	}

	// Validate IP format
	if _, err := netip.ParseAddr(clientIP); err != nil {
		return remoteIP
	}

	return clientIP
}

// isTrustedProxy checks if the given IP is in the trusted proxy list.
func (m *Middleware) isTrustedProxy(ip string) bool {
	if len(m.config.TrustedProxies) == 0 {
		return false
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

	for _, prefix := range m.config.TrustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// parseRemoteAddr extracts the IP from RemoteAddr (strips port).
func parseRemoteAddr(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}

	// Handle IPv6 with brackets: [::1]:port
	if strings.HasPrefix(remoteAddr, "[") {
		if idx := strings.LastIndex(remoteAddr, "]:"); idx != -1 {
			return remoteAddr[1:idx]
		}
		// Malformed, try to extract anyway
		return strings.Trim(strings.Split(remoteAddr, "]:")[0], "[]")
	}

	// Handle IPv4: 127.0.0.1:port
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		return remoteAddr[:idx]
	}

	return remoteAddr
}
