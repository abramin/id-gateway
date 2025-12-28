package revocation

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// AGENTS.MD JUSTIFICATION: TRL invariants (revocation visibility, cleanup)
// are covered here because feature tests do not hit in-memory store behavior.
type InMemoryTRLSuite struct {
	suite.Suite
	store *InMemoryTRL
}

func (s *InMemoryTRLSuite) SetupTest() {
	s.store = NewInMemoryTRL(WithCleanupInterval(5 * time.Millisecond))
}

func (s *InMemoryTRLSuite) TestTRL_RevocationVisibility() {
	ctx := context.Background()

	// Given a token JTI
	jti := "jti_123"

	// When it is revoked
	err := s.store.RevokeToken(ctx, jti, time.Hour)
	s.Require().NoError(err)

	// Then it should be reported as revoked
	revoked, err := s.store.IsRevoked(ctx, jti)
	s.Require().NoError(err)
	s.True(revoked)
}

func (s *InMemoryTRLSuite) TestTRL_MissingTokenReturnsFalse() {
	ctx := context.Background()

	revoked, err := s.store.IsRevoked(ctx, "missing")
	s.Require().NoError(err)
	s.False(revoked)
}

func (s *InMemoryTRLSuite) TestTRL_ExpiredTokenReturnsFalse() {
	ctx := context.Background()

	jti := "jti_expired"
	s.Require().NoError(s.store.RevokeToken(ctx, jti, 5*time.Millisecond))

	s.Require().Eventually(func() bool {
		revoked, err := s.store.IsRevoked(ctx, jti)
		return err == nil && !revoked
	}, 200*time.Millisecond, 5*time.Millisecond)
}

func (s *InMemoryTRLSuite) TestTRL_RevokesSessionTokens() {
	ctx := context.Background()

	jtis := []string{"jti_1", "jti_2", "jti_3"}
	err := s.store.RevokeSessionTokens(ctx, "session_123", jtis, time.Hour)
	s.Require().NoError(err)

	for _, jti := range jtis {
		revoked, err := s.store.IsRevoked(ctx, jti)
		s.Require().NoError(err)
		s.True(revoked)
	}
}

func (s *InMemoryTRLSuite) TestTRL_CleanupRemovesExpiredEntries() {
	ctx := context.Background()

	jti := "jti_cleanup"
	s.Require().NoError(s.store.RevokeToken(ctx, jti, 5*time.Millisecond))

	s.Require().Eventually(func() bool {
		s.store.mu.RLock()
		_, exists := s.store.revoked[jti]
		s.store.mu.RUnlock()
		return !exists
	}, 200*time.Millisecond, 5*time.Millisecond)
}

func (s *InMemoryTRLSuite) TestTRL_CleanupIntervalOption() {
	s.store = NewInMemoryTRL(WithCleanupInterval(123 * time.Millisecond))
	s.Equal(123*time.Millisecond, s.store.cleanupInterval)

	s.store = NewInMemoryTRL(WithCleanupInterval(0))
	s.Equal(1*time.Minute, s.store.cleanupInterval) // Default reduced from 5min for bounded memory
}

func TestInMemoryTRLSuite(t *testing.T) {
	suite.Run(t, new(InMemoryTRLSuite))
}
