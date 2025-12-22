package cleanup

// TODO: REwrite this to do following
// - FailureCount resets after WindowDuration (15 min)
// - DailyFailures resets after 24 hours

type AuthLockoutCleaner struct {
}
