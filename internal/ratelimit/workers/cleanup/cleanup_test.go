package cleanup

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type AuthLockoutCleanerSuite struct {
	suite.Suite
	// TODO: add dependencies here once the cleaner has a concrete store interface.
}

func TestAuthLockoutCleanerSuite(t *testing.T) {
	suite.Run(t, new(AuthLockoutCleanerSuite))
}

func (s *AuthLockoutCleanerSuite) SetupTest() {
	// TODO: initialize cleaner with in-memory store and deterministic clock.
}

func (s *AuthLockoutCleanerSuite) TestRunResetsFailureCountAfterWindow() {
	// TODO: seed a lockout record with LastFailureAt older than WindowDuration.
	// TODO: run cleanup and assert FailureCount resets while DailyFailures stays.
	s.T().Skip("TODO: add contract-focused test for window-based failure reset")
}

func (s *AuthLockoutCleanerSuite) TestRunResetsDailyFailuresAfterDayBoundary() {
	// TODO: seed a lockout record with LastFailureAt older than 24h boundary.
	// TODO: run cleanup and assert DailyFailures resets while recent FailureCount is preserved.
	s.T().Skip("TODO: add contract-focused test for daily failure reset")
}

func (s *AuthLockoutCleanerSuite) TestRunNoChangesForRecentFailures() {
	// TODO: seed a lockout record within window and within daily period.
	// TODO: run cleanup and assert counters remain unchanged.
	s.T().Skip("TODO: add contract-focused test for no-op on recent records")
}

func (s *AuthLockoutCleanerSuite) TestRunHandlesEmptyStore() {
	// TODO: run cleanup with no records and assert no errors or panics.
	s.T().Skip("TODO: add contract-focused test for empty store cleanup")
}
