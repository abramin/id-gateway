package models

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

// =============================================================================
// Rate Limit Key Security Test Suite
// =============================================================================
// Justification: Key collision attacks could allow attackers to manipulate
// rate limit buckets by crafting identifiers containing delimiter characters.

type KeySecuritySuite struct {
	suite.Suite
}

func TestKeySecuritySuite(t *testing.T) {
	suite.Run(t, new(KeySecuritySuite))
}

// =============================================================================
// Key Collision Attack Tests
// =============================================================================
// Security test: Attempt identifier values containing ':' characters
// to verify no bucket crossover occurs.

func (s *KeySecuritySuite) TestKeyCollisionAttack() {
	s.Run("colon in identifier is sanitized to prevent bucket crossover", func() {
		// Attack scenario: An attacker provides identifier "user:admin" hoping
		// to affect the rate limit bucket for a different user or key type
		maliciousIdentifier := "user:admin"

		key := NewRateLimitKey(KeyPrefixIP, maliciousIdentifier, ClassAuth)

		// The colon should be replaced with underscore
		s.Contains(key.String(), "user_admin")
		s.NotContains(key.String(), "user:admin")
	})

	s.Run("multiple colons are all sanitized", func() {
		maliciousIdentifier := "ip:192:168:1:1"

		key := NewRateLimitKey(KeyPrefixIP, maliciousIdentifier, ClassRead)

		// All colons in the identifier segment should be replaced
		keyStr := key.String()
		s.Contains(keyStr, "ip_192_168_1_1")
	})

	s.Run("auth lockout key sanitizes both identifier and IP", func() {
		maliciousIdentifier := "admin:user"
		maliciousIP := "192.168.1.1:8080" // IP with port (contains colon)

		key := NewAuthLockoutKey(maliciousIdentifier, maliciousIP)

		keyStr := key.String()
		// Both segments should be sanitized
		s.NotContains(keyStr, "admin:user")
		s.NotContains(keyStr, "192.168.1.1:8080")
		// Verify proper format after sanitization
		s.Contains(keyStr, "admin_user")
		s.Contains(keyStr, "192.168.1.1_8080")
	})

	s.Run("legitimate keys are unaffected", func() {
		// Normal identifiers without colons should pass through unchanged (except formatting)
		key := NewRateLimitKey(KeyPrefixUser, "user-123", ClassWrite)

		s.Equal("user:user-123:write", key.String())
	})

	s.Run("empty string identifier is preserved", func() {
		// Edge case: empty strings should not cause issues
		key := NewRateLimitKey(KeyPrefixIP, "", ClassAuth)

		// Should still format correctly even with empty identifier
		s.Equal("ip::auth", key.String())
	})

	s.Run("key prefix is not confused with user-controlled data", func() {
		// Attack scenario: User provides "ip" as identifier hoping to
		// create confusion with the key prefix
		userIdentifier := "ip"

		key := NewRateLimitKey(KeyPrefixUser, userIdentifier, ClassAuth)

		// Key should clearly show user prefix, not IP prefix
		s.Equal("user:ip:auth", key.String())
	})
}
