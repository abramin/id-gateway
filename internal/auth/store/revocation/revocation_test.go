package revocation

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type InMemoryTRLSuite struct {
	suite.Suite
	store *InMemoryTRL
}

func (s *InMemoryTRLSuite) SetupTest() {
	s.store = NewInMemoryTRL(WithCleanupInterval(5 * time.Millisecond))
}

func (s *InMemoryTRLSuite) TestRevokeTokenAndIsRevoked() {
	ctx := context.Background()

	// Given a token JTI
	jti := "jti_123"

	// When it is revoked
	err := s.store.RevokeToken(ctx, jti, time.Hour)
	require.NoError(s.T(), err)

	// Then it should be reported as revoked
	revoked, err := s.store.IsRevoked(ctx, jti)
	require.NoError(s.T(), err)
	assert.True(s.T(), revoked)
}

func (s *InMemoryTRLSuite) TestIsRevokedNotFoundReturnsFalse() {
	ctx := context.Background()

	revoked, err := s.store.IsRevoked(ctx, "missing")
	require.NoError(s.T(), err)
	assert.False(s.T(), revoked)
}

func (s *InMemoryTRLSuite) TestIsRevokedExpiredReturnsFalse() {
	ctx := context.Background()

	jti := "jti_expired"
	require.NoError(s.T(), s.store.RevokeToken(ctx, jti, 5*time.Millisecond))

	require.Eventually(s.T(), func() bool {
		revoked, err := s.store.IsRevoked(ctx, jti)
		return err == nil && !revoked
	}, 200*time.Millisecond, 5*time.Millisecond)
}

func (s *InMemoryTRLSuite) TestRevokeSessionTokensRevokesAll() {
	ctx := context.Background()

	jtis := []string{"jti_1", "jti_2", "jti_3"}
	err := s.store.RevokeSessionTokens(ctx, "session_123", jtis, time.Hour)
	require.NoError(s.T(), err)

	for _, jti := range jtis {
		revoked, err := s.store.IsRevoked(ctx, jti)
		require.NoError(s.T(), err)
		assert.True(s.T(), revoked)
	}
}

func (s *InMemoryTRLSuite) TestCleanupRemovesExpiredEntries() {
	ctx := context.Background()

	jti := "jti_cleanup"
	require.NoError(s.T(), s.store.RevokeToken(ctx, jti, 5*time.Millisecond))

	require.Eventually(s.T(), func() bool {
		s.store.mu.RLock()
		_, exists := s.store.revoked[jti]
		s.store.mu.RUnlock()
		return !exists
	}, 200*time.Millisecond, 5*time.Millisecond)
}

func (s *InMemoryTRLSuite) TestWithCleanupInterval() {
	s.store = NewInMemoryTRL(WithCleanupInterval(123 * time.Millisecond))
	assert.Equal(s.T(), 123*time.Millisecond, s.store.cleanupInterval)

	s.store = NewInMemoryTRL(WithCleanupInterval(0))
	assert.Equal(s.T(), 1*time.Minute, s.store.cleanupInterval) // Default reduced from 5min for bounded memory
}

func TestInMemoryTRLSuite(t *testing.T) {
	suite.Run(t, new(InMemoryTRLSuite))
}
