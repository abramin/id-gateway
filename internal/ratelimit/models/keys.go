package models

import (
	"fmt"
	"strings"
)

// KeyPrefix represents the type of rate limit key.
type KeyPrefix string

const (
	KeyPrefixIP     KeyPrefix = "ip"
	KeyPrefixUser   KeyPrefix = "user"
	KeyPrefixAuth   KeyPrefix = "auth"
	KeyPrefixClient KeyPrefix = "client"
)

// RateLimitKey is a value object encapsulating rate limit bucket key construction.
// It centralizes key format and sanitization to prevent key collision attacks.
type RateLimitKey struct {
	prefix     KeyPrefix
	identifier string
	class      EndpointClass // optional, empty for auth keys
}

// NewRateLimitKey creates a rate limit key for IP or user-based limits.
func NewRateLimitKey(prefix KeyPrefix, identifier string, class EndpointClass) RateLimitKey {
	return RateLimitKey{
		prefix:     prefix,
		identifier: sanitizeKeySegment(identifier),
		class:      class,
	}
}

// NewAuthLockoutKey creates a composite key for auth lockout tracking.
// Combines identifier (username/email) with IP for per-identity-per-IP tracking.
func NewAuthLockoutKey(identifier, ip string) RateLimitKey {
	composite := fmt.Sprintf("%s:%s", sanitizeKeySegment(identifier), sanitizeKeySegment(ip))
	return RateLimitKey{
		prefix:     KeyPrefixAuth,
		identifier: composite,
	}
}

// String returns the formatted key for storage lookup.
func (k RateLimitKey) String() string {
	if k.class == "" {
		return fmt.Sprintf("%s:%s", k.prefix, k.identifier)
	}
	return fmt.Sprintf("%s:%s:%s", k.prefix, k.identifier, k.class)
}

// sanitizeKeySegment escapes delimiter characters in rate limit key segments
// to prevent key collision attacks where user-controlled identifiers containing
// ':' could manipulate adjacent rate limit buckets.
//
// Escape rules (order matters):
//  1. Escape '_' to '__' (escape the escape character first)
//  2. Escape ':' to '_c' (escape the delimiter)
//
// Examples:
//   - "user:admin"  → "user_cadmin"  (colon escaped)
//   - "user_admin"  → "user__admin"  (underscore escaped)
//   - "user_:admin" → "user___cadmin" (both escaped, no collision)
//
// This ensures no two distinct inputs produce the same sanitized output,
// preventing key collision attacks.
func sanitizeKeySegment(s string) string {
	// Order matters: escape the escape character first
	s = strings.ReplaceAll(s, "_", "__")
	s = strings.ReplaceAll(s, ":", "_c")
	return s
}

// NewClientRateLimitKey creates a key for per-client endpoint limits.
func NewClientRateLimitKey(clientID, endpoint string) string {
	return fmt.Sprintf("%s:%s:%s",
		KeyPrefixClient,
		sanitizeKeySegment(clientID),
		sanitizeKeySegment(endpoint),
	)
}
