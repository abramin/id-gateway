package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
)

// RegisterSteps registers all step definitions
func RegisterSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	// Background steps
	ctx.Step(`^the ID Gateway is running$`, tc.idGatewayIsRunning)

	// Authorization steps
	ctx.Step(`^I initiate authorization with email "([^"]*)" and scopes "([^"]*)"$`, tc.initiateAuthorization)
	ctx.Step(`^I save the authorization code$`, tc.saveAuthorizationCode)
	ctx.Step(`^I exchange the authorization code for tokens$`, tc.exchangeCodeForTokens)
	ctx.Step(`^I exchange invalid authorization code "([^"]*)"$`, tc.exchangeInvalidCode)
	ctx.Step(`^I attempt to reuse the same authorization code$`, tc.reuseAuthorizationCode)

	// Request steps
	ctx.Step(`^I POST to "([^"]*)" with empty body$`, tc.postWithEmptyBody)
	ctx.Step(`^I POST to "([^"]*)" with invalid email "([^"]*)"$`, tc.postWithInvalidEmail)
	ctx.Step(`^I POST to "([^"]*)" with grant_type "([^"]*)"$`, tc.postWithGrantType)
	ctx.Step(`^I GET "([^"]*)" without authorization$`, tc.getWithoutAuth)
	ctx.Step(`^I GET "([^"]*)" with invalid token "([^"]*)"$`, tc.getWithInvalidToken)
	ctx.Step(`^I request user info with the access token$`, tc.requestUserInfo)

	// Assertion steps
	ctx.Step(`^the response status should be (\d+)$`, tc.responseStatusShouldBe)
	ctx.Step(`^the response should contain "([^"]*)"$`, tc.responseShouldContain)
	ctx.Step(`^the response should contain an authorization code$`, tc.responseShouldContainAuthCode)
	ctx.Step(`^the response field "([^"]*)" should equal "([^"]*)"$`, tc.responseFieldShouldEqual)

	// Simulation steps
	ctx.Step(`^PKCE is a recommended security feature$`, func(context.Context) error { return nil })
	ctx.Step(`^redirect URI validation prevents token theft$`, func(context.Context) error { return nil })
	ctx.Step(`^CSRF protection is important$`, func(context.Context) error { return nil })
	ctx.Step(`^implicit flow leaks tokens in browser history$`, func(context.Context) error { return nil })
	ctx.Step(`^authorization codes should be single-use$`, func(context.Context) error { return nil })
	ctx.Step(`^public clients cannot keep secrets$`, func(context.Context) error { return nil })
	ctx.Step(`^log "([^"]*)"$`, tc.logMessage)
}

func (tc *TestContext) idGatewayIsRunning(ctx context.Context) error {
	return nil
}

func (tc *TestContext) initiateAuthorization(ctx context.Context, email, scopes string) error {
	body := map[string]interface{}{
		"email":        email,
		"client_id":    tc.ClientID,
		"scopes":       strings.Split(scopes, ","),
		"redirect_uri": tc.RedirectURI,
		"state":        "test-state-123",
	}
	return tc.POST("/auth/authorize", body)
}

func (tc *TestContext) saveAuthorizationCode(ctx context.Context) error {
	code, err := tc.GetResponseField("code")
	if err != nil {
		return err
	}
	tc.AuthCode = code.(string)
	return nil
}

func (tc *TestContext) exchangeCodeForTokens(ctx context.Context) error {
	body := map[string]interface{}{
		"grant_type":   "authorization_code",
		"code":         tc.AuthCode,
		"redirect_uri": tc.RedirectURI,
		"client_id":    tc.ClientID,
	}
	return tc.POST("/auth/token", body)
}

func (tc *TestContext) exchangeInvalidCode(ctx context.Context, code string) error {
	body := map[string]interface{}{
		"grant_type":   "authorization_code",
		"code":         code,
		"redirect_uri": tc.RedirectURI,
		"client_id":    tc.ClientID,
	}
	return tc.POST("/auth/token", body)
}

func (tc *TestContext) reuseAuthorizationCode(ctx context.Context) error {
	return tc.exchangeCodeForTokens(ctx)
}

func (tc *TestContext) postWithEmptyBody(ctx context.Context, path string) error {
	return tc.POST(path, map[string]interface{}{})
}

func (tc *TestContext) postWithInvalidEmail(ctx context.Context, path, email string) error {
	body := map[string]interface{}{
		"email":        email,
		"client_id":    tc.ClientID,
		"scopes":       []string{"openid"},
		"redirect_uri": tc.RedirectURI,
	}
	return tc.POST(path, body)
}

func (tc *TestContext) postWithGrantType(ctx context.Context, path, grantType string) error {
	body := map[string]interface{}{
		"grant_type":   grantType,
		"code":         "some-code",
		"redirect_uri": tc.RedirectURI,
		"client_id":    tc.ClientID,
	}
	return tc.POST(path, body)
}

func (tc *TestContext) getWithoutAuth(ctx context.Context, path string) error {
	return tc.GET(path, nil)
}

func (tc *TestContext) getWithInvalidToken(ctx context.Context, path, token string) error {
	return tc.GET(path, map[string]string{
		"Authorization": "Bearer " + token,
	})
}

func (tc *TestContext) requestUserInfo(ctx context.Context) error {
	accessToken, err := tc.GetResponseField("access_token")
	if err != nil {
		return err
	}
	tc.AccessToken = accessToken.(string)

	return tc.GET("/auth/userinfo", map[string]string{
		"Authorization": "Bearer " + tc.AccessToken,
	})
}

func (tc *TestContext) responseStatusShouldBe(ctx context.Context, expectedStatus int) error {
	if tc.LastResponse.StatusCode != expectedStatus {
		return fmt.Errorf("expected status %d but got %d", expectedStatus, tc.LastResponse.StatusCode)
	}
	return nil
}

func (tc *TestContext) responseShouldContain(ctx context.Context, field string) error {
	if !tc.ResponseContains(field) {
		return fmt.Errorf("response does not contain field: %s\nResponse: %s", field, string(tc.LastResponseBody))
	}
	return nil
}

func (tc *TestContext) responseShouldContainAuthCode(ctx context.Context) error {
	return tc.responseShouldContain(ctx, "code")
}

func (tc *TestContext) responseFieldShouldEqual(ctx context.Context, field, expectedValue string) error {
	var data map[string]interface{}
	if err := json.Unmarshal(tc.LastResponseBody, &data); err != nil {
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

func (tc *TestContext) logMessage(ctx context.Context, message string) error {
	fmt.Println(message)
	return nil
}
