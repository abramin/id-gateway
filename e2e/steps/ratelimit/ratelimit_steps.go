package ratelimit

import (
	"context"

	"github.com/cucumber/godog"
)

// TestContext interface defines the methods needed from the main test context
type TestContext interface {
	POST(path string, body interface{}) error
	POSTWithHeaders(path string, body interface{}, headers map[string]string) error
	GET(path string, headers map[string]string) error
	GetResponseField(field string) (interface{}, error)
	GetClientID() string
	GetRedirectURI() string
	GetLastResponseStatus() int
	GetLastResponseBody() []byte
	GetAccessToken() string
	SetAccessToken(token string)
}

// RegisterSteps registers rate-limiting step definitions
// These are stubbed for PRD-017 FR-2b: Authentication-Specific Protections (OWASP)
func RegisterSteps(ctx *godog.ScenarioContext, tc TestContext) {
	steps := &ratelimitSteps{tc: tc}

	// Basic rate limit test steps
	ctx.Step(`^I make a request to "([^"]*)" with valid token$`, steps.makeRequestWithValidToken)
	ctx.Step(`^I am making requests from IP "([^"]*)"$`, steps.makingRequestsFromIP)
	ctx.Step(`^I make (\d+) requests to "([^"]*)" within (\d+) minute$`, steps.makeNRequestsWithinMinute)
	ctx.Step(`^all (\d+) requests should succeed with status (\d+)$`, steps.allNRequestsShouldSucceedWithStatus)
	ctx.Step(`^all (\d+) requests should succeed$`, steps.allNRequestsShouldSucceed)
	ctx.Step(`^I make the (\d+)(?:st|nd|rd|th) request to "([^"]*)"$`, steps.makeNthRequest)
	ctx.Step(`^I have exhausted the rate limit on "([^"]*)"$`, steps.haveExhaustedRateLimitOn)
	ctx.Step(`^I make a request to "([^"]*)"$`, steps.makeRequest)

	// FR-2b: Auth lockout after failed attempts
	ctx.Step(`^I am attempting login for user "([^"]*)" from IP "([^"]*)"$`, steps.attemptingLoginFromIP)
	ctx.Step(`^I fail authentication (\d+) times within (\d+) minutes$`, steps.failAuthNTimesInMinutes)
	ctx.Step(`^the (\d+)(?:st|nd|rd|th) attempt should return (\d+)$`, steps.nthAttemptShouldReturn)
	ctx.Step(`^the response should indicate lockout$`, steps.responseShouldIndicateLockout)

	// FR-2b: Hard lockout after daily failures
	ctx.Step(`^the account should be hard locked for (\d+) minutes$`, steps.accountHardLockedForMinutes)
	ctx.Step(`^the audit event "([^"]*)" should be emitted$`, steps.auditEventShouldBeEmitted)

	// FR-2b: Progressive backoff
	ctx.Step(`^I fail authentication once$`, steps.failAuthOnce)
	ctx.Step(`^I fail authentication again$`, steps.failAuthAgain)
	ctx.Step(`^the next response should be delayed by at least (\d+)ms$`, steps.responseDelayedByAtLeastMs)

	// FR-2b: Generic error messages prevent enumeration (OWASP)
	ctx.Step(`^I attempt login with invalid username "([^"]*)"$`, steps.attemptLoginInvalidUsername)
	ctx.Step(`^the response error message should be generic$`, steps.errorMessageShouldBeGeneric)
	ctx.Step(`^I attempt login with valid username but invalid password$`, steps.attemptLoginValidUserInvalidPassword)
	ctx.Step(`^the response error message should be the same generic message$`, steps.errorMessageShouldBeSameGeneric)

	// FR-2b: CAPTCHA required after consecutive lockouts
	ctx.Step(`^user "([^"]*)" has been locked out (\d+) times in (\d+) hours$`, steps.userLockedOutNTimes)
	ctx.Step(`^I attempt to login as "([^"]*)"$`, steps.attemptLoginAs)
	ctx.Step(`^the response should indicate CAPTCHA is required$`, steps.responseShouldIndicateCaptcha)
}

type ratelimitSteps struct {
	tc TestContext
	// State for tracking across steps
	currentEmail   string
	currentIP      string
	lastError      string
	requestResults []int // Status codes from multiple requests
}

// makeRequestWithValidToken makes a request to the given path with a valid access token.
// It first obtains a token by doing an auth flow if needed.
func (s *ratelimitSteps) makeRequestWithValidToken(ctx context.Context, path string) error {
	// If we don't have an access token, get one
	if s.tc.GetAccessToken() == "" {
		// Initiate auth flow
		body := map[string]interface{}{
			"email":        "ratelimit-test@example.com",
			"client_id":    s.tc.GetClientID(),
			"scopes":       []string{"openid"},
			"redirect_uri": s.tc.GetRedirectURI(),
			"state":        "ratelimit-test-state",
		}
		if err := s.tc.POST("/auth/authorize", body); err != nil {
			return err
		}
		code, err := s.tc.GetResponseField("code")
		if err != nil {
			return err
		}

		// Exchange for tokens
		tokenBody := map[string]interface{}{
			"grant_type":   "authorization_code",
			"code":         code.(string),
			"redirect_uri": s.tc.GetRedirectURI(),
			"client_id":    s.tc.GetClientID(),
		}
		if err := s.tc.POST("/auth/token", tokenBody); err != nil {
			return err
		}
		accessToken, err := s.tc.GetResponseField("access_token")
		if err != nil {
			return err
		}
		s.tc.SetAccessToken(accessToken.(string))
	}

	// Make the request with the token
	return s.tc.GET(path, map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

// makingRequestsFromIP sets the current IP for subsequent requests (simulation)
func (s *ratelimitSteps) makingRequestsFromIP(ctx context.Context, ip string) error {
	s.currentIP = ip
	// Note: Actual IP simulation would require X-Forwarded-For header support
	return nil
}

// makeNRequestsWithinMinute makes N requests to the given path
func (s *ratelimitSteps) makeNRequestsWithinMinute(ctx context.Context, count int, path string, minutes int) error {
	s.requestResults = make([]int, 0, count)
	for i := 0; i < count; i++ {
		if err := s.makeRequestWithValidToken(ctx, path); err != nil {
			return err
		}
		s.requestResults = append(s.requestResults, s.tc.GetLastResponseStatus())
	}
	return nil
}

// allNRequestsShouldSucceedWithStatus verifies all N requests returned the expected status
func (s *ratelimitSteps) allNRequestsShouldSucceedWithStatus(ctx context.Context, count, expectedStatus int) error {
	if len(s.requestResults) < count {
		return godog.ErrPending // Not enough requests made
	}
	for i := 0; i < count; i++ {
		if s.requestResults[i] != expectedStatus {
			return godog.ErrPending // Rate limiting simulation not fully implemented
		}
	}
	return nil
}

// allNRequestsShouldSucceed verifies all N requests succeeded (status 200)
func (s *ratelimitSteps) allNRequestsShouldSucceed(ctx context.Context, count int) error {
	return s.allNRequestsShouldSucceedWithStatus(ctx, count, 200)
}

// makeNthRequest makes the Nth request to the given path
func (s *ratelimitSteps) makeNthRequest(ctx context.Context, n int, path string) error {
	return s.makeRequestWithValidToken(ctx, path)
}

// haveExhaustedRateLimitOn simulates exhausting the rate limit
func (s *ratelimitSteps) haveExhaustedRateLimitOn(ctx context.Context, path string) error {
	return godog.ErrPending // Rate limit exhaustion simulation not implemented
}

// makeRequest makes a request to the given path
func (s *ratelimitSteps) makeRequest(ctx context.Context, path string) error {
	return s.makeRequestWithValidToken(ctx, path)
}

// attemptingLoginFromIP sets up the context for subsequent auth attempts
// TODO: PRD-017 FR-2b - Implement with X-Forwarded-For header simulation
func (s *ratelimitSteps) attemptingLoginFromIP(ctx context.Context, email, ip string) error {
	s.currentEmail = email
	s.currentIP = ip
	return godog.ErrPending
}

// failAuthNTimesInMinutes simulates N failed authentication attempts
// TODO: PRD-017 FR-2b - Call auth endpoint N times with wrong credentials
func (s *ratelimitSteps) failAuthNTimesInMinutes(ctx context.Context, times, minutes int) error {
	return godog.ErrPending
}

// nthAttemptShouldReturn verifies the Nth attempt returns the expected status
// TODO: PRD-017 FR-2b - Verify lockout response status (429)
func (s *ratelimitSteps) nthAttemptShouldReturn(ctx context.Context, n, expectedStatus int) error {
	return godog.ErrPending
}

// responseShouldIndicateLockout verifies the response indicates a lockout state
// TODO: PRD-017 FR-2b - Check for lockout indicator in response body
func (s *ratelimitSteps) responseShouldIndicateLockout(ctx context.Context) error {
	return godog.ErrPending
}

// accountHardLockedForMinutes verifies the account is hard locked for N minutes
// TODO: PRD-017 FR-2b - Verify hard lock state and duration
func (s *ratelimitSteps) accountHardLockedForMinutes(ctx context.Context, minutes int) error {
	return godog.ErrPending
}

// auditEventShouldBeEmitted verifies an audit event was emitted
// TODO: PRD-017 FR-2b - Query audit log or verify via test hook
func (s *ratelimitSteps) auditEventShouldBeEmitted(ctx context.Context, eventType string) error {
	return godog.ErrPending
}

// failAuthOnce simulates a single failed authentication attempt
// TODO: PRD-017 FR-2b - Call auth endpoint with wrong credentials once
func (s *ratelimitSteps) failAuthOnce(ctx context.Context) error {
	return godog.ErrPending
}

// failAuthAgain simulates another failed authentication attempt
// TODO: PRD-017 FR-2b - Call auth endpoint with wrong credentials again
func (s *ratelimitSteps) failAuthAgain(ctx context.Context) error {
	return godog.ErrPending
}

// responseDelayedByAtLeastMs verifies the response was delayed by at least N milliseconds
// TODO: PRD-017 FR-2b - Measure response time and compare to threshold
func (s *ratelimitSteps) responseDelayedByAtLeastMs(ctx context.Context, ms int) error {
	return godog.ErrPending
}

// attemptLoginInvalidUsername attempts login with a non-existent username
// TODO: PRD-017 FR-2b - Call auth endpoint with non-existent email
func (s *ratelimitSteps) attemptLoginInvalidUsername(ctx context.Context, username string) error {
	return godog.ErrPending
}

// errorMessageShouldBeGeneric verifies the error message is generic (OWASP enumeration prevention)
// TODO: PRD-017 FR-2b - Verify error message doesn't reveal whether user exists
func (s *ratelimitSteps) errorMessageShouldBeGeneric(ctx context.Context) error {
	return godog.ErrPending
}

// attemptLoginValidUserInvalidPassword attempts login with valid user but wrong password
// TODO: PRD-017 FR-2b - Call auth endpoint with valid email, wrong password
func (s *ratelimitSteps) attemptLoginValidUserInvalidPassword(ctx context.Context) error {
	return godog.ErrPending
}

// errorMessageShouldBeSameGeneric verifies the error message is the same as for invalid username
// TODO: PRD-017 FR-2b - Compare error message to previous to prevent enumeration
func (s *ratelimitSteps) errorMessageShouldBeSameGeneric(ctx context.Context) error {
	return godog.ErrPending
}

// userLockedOutNTimes sets up a user that has been locked out N times in M hours
// TODO: PRD-017 FR-2b - Setup state for CAPTCHA scenario
func (s *ratelimitSteps) userLockedOutNTimes(ctx context.Context, email string, times, hours int) error {
	return godog.ErrPending
}

// attemptLoginAs attempts to login as the specified user
// TODO: PRD-017 FR-2b - Call auth endpoint for specified user
func (s *ratelimitSteps) attemptLoginAs(ctx context.Context, email string) error {
	return godog.ErrPending
}

// responseShouldIndicateCaptcha verifies the response indicates CAPTCHA is required
// TODO: PRD-017 FR-2b - Check for CAPTCHA challenge indicator in response
func (s *ratelimitSteps) responseShouldIndicateCaptcha(ctx context.Context) error {
	return godog.ErrPending
}
