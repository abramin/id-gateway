package common

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cucumber/godog"
)

// TestContext interface defines the methods needed from the main test context
type TestContext interface {
	POST(path string, body interface{}) error
	GET(path string, headers map[string]string) error
	GetResponseField(field string) (interface{}, error)
	ResponseContains(field string) bool
	GetLastResponseStatus() int
	GetLastResponseBody() []byte
}

// RegisterSteps registers common step definitions used across features
func RegisterSteps(ctx *godog.ScenarioContext, tc TestContext) {
	steps := &commonSteps{tc: tc}

	// Background steps
	ctx.Step(`^the ID Gateway is running$`, steps.idGatewayIsRunning)

	// Generic request steps
	ctx.Step(`^I POST to "([^"]*)" with empty body$`, steps.postWithEmptyBody)
	ctx.Step(`^I GET "([^"]*)" without authorization$`, steps.getWithoutAuth)

	// Response assertion steps
	ctx.Step(`^the response status should be (\d+)$`, steps.responseStatusShouldBe)
	ctx.Step(`^the response should contain "([^"]*)"$`, steps.responseShouldContain)
	ctx.Step(`^the response should contain an authorization code$`, steps.responseShouldContainAuthCode)
	ctx.Step(`^the response field "([^"]*)" should equal "([^"]*)"$`, steps.responseFieldShouldEqual)
	ctx.Step(`^the response field "([^"]*)" should contain "([^"]*)"$`, steps.responseFieldShouldContain)

	// Simulation/documentation steps (no-op for documentation purposes)
	ctx.Step(`^PKCE is a recommended security feature$`, func(context.Context) error { return nil })
	ctx.Step(`^redirect URI validation prevents token theft$`, func(context.Context) error { return nil })
	ctx.Step(`^CSRF protection is important$`, func(context.Context) error { return nil })
	ctx.Step(`^implicit flow leaks tokens in browser history$`, func(context.Context) error { return nil })
	ctx.Step(`^authorization codes should be single-use$`, func(context.Context) error { return nil })
	ctx.Step(`^public clients cannot keep secrets$`, func(context.Context) error { return nil })
	ctx.Step(`^client status validation is enforced on token refresh$`, func(context.Context) error { return nil })
	ctx.Step(`^user status validation is enforced on token refresh$`, func(context.Context) error { return nil })
	ctx.Step(`^log "([^"]*)"$`, steps.logMessage)
}

type commonSteps struct {
	tc TestContext
}

func (s *commonSteps) idGatewayIsRunning(ctx context.Context) error {
	return nil
}

func (s *commonSteps) postWithEmptyBody(ctx context.Context, path string) error {
	return s.tc.POST(path, map[string]interface{}{})
}

func (s *commonSteps) getWithoutAuth(ctx context.Context, path string) error {
	return s.tc.GET(path, nil)
}

func (s *commonSteps) responseStatusShouldBe(ctx context.Context, expectedStatus int) error {
	actualStatus := s.tc.GetLastResponseStatus()
	if actualStatus != expectedStatus {
		return fmt.Errorf("expected status %d but got %d", expectedStatus, actualStatus)
	}
	return nil
}

func (s *commonSteps) responseShouldContain(ctx context.Context, field string) error {
	if !s.tc.ResponseContains(field) {
		return fmt.Errorf("response does not contain field: %s\nResponse: %s", field, string(s.tc.GetLastResponseBody()))
	}
	return nil
}

func (s *commonSteps) responseShouldContainAuthCode(ctx context.Context) error {
	return s.responseShouldContain(ctx, "code")
}

func (s *commonSteps) responseFieldShouldEqual(ctx context.Context, field, expectedValue string) error {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	actualValue, ok := data[field]
	if !ok {
		return fmt.Errorf("field %s not found in response", field)
	}

	if fmt.Sprint(actualValue) != expectedValue {
		return fmt.Errorf("field %s: expected %s but got %v", field, expectedValue, actualValue)
	}
	return nil
}

func (s *commonSteps) responseFieldShouldContain(ctx context.Context, field, expectedSubstring string) error {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	actualValue, ok := data[field]
	if !ok {
		return fmt.Errorf("field %s not found in response", field)
	}

	actualStr := fmt.Sprint(actualValue)
	if !contains(actualStr, expectedSubstring) {
		return fmt.Errorf("field %s: expected to contain %s but got %v", field, expectedSubstring, actualValue)
	}
	return nil
}

func (s *commonSteps) logMessage(ctx context.Context, message string) error {
	fmt.Println(message)
	return nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
