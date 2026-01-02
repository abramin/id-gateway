package cleanup

// Justification: These tests verify time-based invariants that cannot be expressed
// in Gherkin without unreasonably long test execution. They test:
// - Window failure count resets after 15 minutes (ResetFailureCount)
// - Daily failure count resets after 24 hours (ResetDailyFailures)
// - Error propagation from store layer
//
// E2E tests cover the user-visible lockout behavior; these tests verify
// the cleanup worker correctly resets internal state after time windows expire.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type mockAuthLockoutStore struct {
	resetFailureCountCalled  int
	resetDailyFailuresCalled int

	failuresResetToReturn      int
	dailyFailuresResetToReturn int

	errToReturn error

	// Capture the cutoff times passed to verify business logic is in the service
	lastFailureCountCutoff  time.Time
	lastDailyFailuresCutoff time.Time
}

func (m *mockAuthLockoutStore) ResetFailureCount(_ context.Context, cutoff time.Time) (int, error) {
	m.resetFailureCountCalled++
	m.lastFailureCountCutoff = cutoff
	return m.failuresResetToReturn, m.errToReturn
}

func (m *mockAuthLockoutStore) ResetDailyFailures(_ context.Context, cutoff time.Time) (int, error) {
	m.resetDailyFailuresCalled++
	m.lastDailyFailuresCutoff = cutoff
	return m.dailyFailuresResetToReturn, m.errToReturn
}

type AuthLockoutCleanerSuite struct {
	suite.Suite
	store   *mockAuthLockoutStore
	service *AuthLockoutCleanupService
}

func TestAuthLockoutCleanerSuite(t *testing.T) {
	suite.Run(t, new(AuthLockoutCleanerSuite))
}

func (s *AuthLockoutCleanerSuite) SetupTest() {
	s.store = &mockAuthLockoutStore{}
	s.service = New(s.store)
}

func (s *AuthLockoutCleanerSuite) TestRunResetsFailureCountAfterWindow() {
	// In a real scenario, these would be records with LastFailureAt > 15 min ago
	s.store.failuresResetToReturn = 3
	s.store.dailyFailuresResetToReturn = 0

	result, err := s.service.RunOnce(context.Background())
	s.Require().NoError(err)
	s.Equal(1, s.store.resetFailureCountCalled, "ResetFailureCount should be called once per cleanup run")
	s.Equal(3, result.FailuresReset, "Result should reflect 3 failure counts were reset")
	s.Equal(0, result.DailyFailuresReset, "No daily failures should be reset in this scenario")
}

func (s *AuthLockoutCleanerSuite) TestRunResetsDailyFailuresAfterDayBoundary() {
	s.store.failuresResetToReturn = 0
	s.store.dailyFailuresResetToReturn = 2

	result, err := s.service.RunOnce(context.Background())
	s.Require().NoError(err)
	s.Equal(1, s.store.resetFailureCountCalled)
	s.Equal(1, s.store.resetDailyFailuresCalled)
	s.Equal(0, result.FailuresReset)
	s.Equal(2, result.DailyFailuresReset, "Result should reflect 2 daily failure counts were reset")
}

func (s *AuthLockoutCleanerSuite) TestRunNoChangesForRecentFailures() {
	s.store.failuresResetToReturn = 0
	s.store.dailyFailuresResetToReturn = 0

	result, err := s.service.RunOnce(context.Background())
	s.Require().NoError(err)
	s.Equal(1, s.store.resetFailureCountCalled, "ResetFailureCount should still be called")
	s.Equal(1, s.store.resetDailyFailuresCalled, "ResetDailyFailures should still be called")
	s.Equal(0, result.FailuresReset, "No failures should be reset for recent records")
	s.Equal(0, result.DailyFailuresReset, "No daily failures should be reset for recent records")
}

func (s *AuthLockoutCleanerSuite) TestRunHandlesEmptyStore() {
	result, err := s.service.RunOnce(context.Background())

	s.Require().NoError(err)
	s.Equal(1, s.store.resetFailureCountCalled)
	s.Equal(1, s.store.resetDailyFailuresCalled)
	s.NotNil(result, "Result should never be nil on success")
	s.Equal(0, result.FailuresReset)
	s.Equal(0, result.DailyFailuresReset)
}

func (s *AuthLockoutCleanerSuite) TestRunPropagatesStoreErrors() {
	s.store.errToReturn = context.DeadlineExceeded
	result, err := s.service.RunOnce(context.Background())

	s.Require().Error(err)
	s.ErrorIs(err, context.DeadlineExceeded)
	s.Nil(result, "Result should be nil when an error occurs")
	s.Equal(1, s.store.resetFailureCountCalled, "First operation should be attempted")
}
