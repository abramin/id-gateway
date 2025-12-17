package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/cucumber/godog"
)

// TestContext interface defines the methods needed from the main test context
type TestContext interface {
	POST(path string, body interface{}) error
	GET(path string, headers map[string]string) error
	DELETE(path string, headers map[string]string) error
	GetResponseField(field string) (interface{}, error)
	GetClientID() string
	GetRedirectURI() string
	GetAuthCode() string
	SetAuthCode(code string)
	GetAccessToken() string
	SetAccessToken(token string)
	GetAccessTokenFor(name string) string
	SetAccessTokenFor(name, token string)
	GetRefreshToken() string
	SetRefreshToken(token string)
	GetPreviousRefreshToken() string
	SetPreviousRefreshToken(token string)
	GetRefreshTokenFor(name string) string
	SetRefreshTokenFor(name, token string)
	GetSessionIDFor(name string) string
	SetSessionIDFor(name, id string)
	GetUserID() string
	SetUserID(userID string)
	GetAdminToken() string
	ResponseContains(text string) bool
	GetLastResponseStatus() int
	GetLastResponseBody() []byte
}

// RegisterSteps registers authentication-related step definitions
func RegisterSteps(ctx *godog.ScenarioContext, tc TestContext) {
	steps := &authSteps{tc: tc}

	// Authorization steps
	ctx.Step(`^I initiate authorization with email "([^"]*)" and scopes "([^"]*)"$`, steps.initiateAuthorization)
	ctx.Step(`^I save the authorization code$`, steps.saveAuthorizationCode)
	ctx.Step(`^I exchange the authorization code for tokens$`, steps.exchangeCodeForTokens)
	ctx.Step(`^I exchange invalid authorization code "([^"]*)"$`, steps.exchangeInvalidCode)
	ctx.Step(`^I attempt to reuse the same authorization code$`, steps.reuseAuthorizationCode)
	ctx.Step(`^I request user info with the access token$`, steps.requestUserInfo)
	ctx.Step(`^I save the tokens from the response$`, steps.saveTokensFromResponse)
	ctx.Step(`^I save the tokens from the response as "([^"]*)"$`, steps.saveTokensFromResponseAs)
	ctx.Step(`^I refresh tokens with the saved refresh token$`, steps.refreshTokensWithSavedRefreshToken)
	ctx.Step(`^I attempt to refresh with the previous refresh token$`, steps.attemptRefreshWithPreviousRefreshToken)
	ctx.Step(`^the new refresh token should differ from the previous one$`, steps.newRefreshTokenShouldDifferFromPrevious)
	ctx.Step(`^I revoke the saved refresh token$`, steps.revokeSavedRefreshToken)
	ctx.Step(`^I revoke the saved access token$`, steps.revokeSavedAccessToken)
	ctx.Step(`^I list sessions with access token "([^"]*)"$`, steps.listSessionsWithAccessToken)
	ctx.Step(`^the response should list at least (\d+) sessions$`, steps.responseShouldListAtLeastNSessions)
	ctx.Step(`^I save the current session id as "([^"]*)"$`, steps.saveCurrentSessionIDAs)
	ctx.Step(`^I revoke session "([^"]*)" using access token "([^"]*)"$`, steps.revokeSessionUsingAccessToken)
	ctx.Step(`^I request user info with access token "([^"]*)"$`, steps.requestUserInfoWithNamedAccessToken)

	// Validation steps
	ctx.Step(`^I POST to "([^"]*)" with invalid email "([^"]*)"$`, steps.postWithInvalidEmail)
	ctx.Step(`^I POST to "([^"]*)" with grant_type "([^"]*)"$`, steps.postWithGrantType)
	ctx.Step(`^I GET "([^"]*)" with invalid token "([^"]*)"$`, steps.getWithInvalidToken)
	ctx.Step(`^I request authorization with unknown client_id "([^"]*)"$`, steps.requestAuthWithUnknownClientID)
	ctx.Step(`^I request authorization with empty client_id$`, steps.requestAuthWithEmptyClientID)

	// Admin steps
	ctx.Step(`^I save the user ID from the userinfo response$`, steps.saveUserIDFromUserInfo)
	ctx.Step(`^I delete the user via admin API$`, steps.deleteUserViaAdmin)
	ctx.Step(`^I delete the user via admin API with token "([^"]*)"$`, steps.deleteUserViaAdminWithToken)
	ctx.Step(`^I attempt to delete user with ID "([^"]*)" via admin API$`, steps.deleteSpecificUserViaAdmin)
	ctx.Step(`^I attempt to get user info with the saved access token$`, steps.attemptGetUserInfo)
}

type authSteps struct {
	tc TestContext
}

func (s *authSteps) initiateAuthorization(ctx context.Context, email, scopes string) error {
	body := map[string]interface{}{
		"email":        email,
		"client_id":    s.tc.GetClientID(),
		"scopes":       strings.Split(scopes, ","),
		"redirect_uri": s.tc.GetRedirectURI(),
		"state":        "test-state-123",
	}
	return s.tc.POST("/auth/authorize", body)
}

func (s *authSteps) saveAuthorizationCode(ctx context.Context) error {
	code, err := s.tc.GetResponseField("code")
	if err != nil {
		return err
	}
	s.tc.SetAuthCode(code.(string))
	return nil
}

func (s *authSteps) exchangeCodeForTokens(ctx context.Context) error {
	body := map[string]interface{}{
		"grant_type":   "authorization_code",
		"code":         s.tc.GetAuthCode(),
		"redirect_uri": s.tc.GetRedirectURI(),
		"client_id":    s.tc.GetClientID(),
	}
	return s.tc.POST("/auth/token", body)
}

func (s *authSteps) exchangeInvalidCode(ctx context.Context, code string) error {
	body := map[string]interface{}{
		"grant_type":   "authorization_code",
		"code":         code,
		"redirect_uri": s.tc.GetRedirectURI(),
		"client_id":    s.tc.GetClientID(),
	}
	return s.tc.POST("/auth/token", body)
}

func (s *authSteps) reuseAuthorizationCode(ctx context.Context) error {
	return s.exchangeCodeForTokens(ctx)
}

func (s *authSteps) postWithInvalidEmail(ctx context.Context, path, email string) error {
	body := map[string]interface{}{
		"email":        email,
		"client_id":    s.tc.GetClientID(),
		"scopes":       []string{"openid"},
		"redirect_uri": s.tc.GetRedirectURI(),
	}
	return s.tc.POST(path, body)
}

func (s *authSteps) postWithGrantType(ctx context.Context, path, grantType string) error {
	body := map[string]interface{}{
		"grant_type":   grantType,
		"code":         "some-code",
		"redirect_uri": s.tc.GetRedirectURI(),
		"client_id":    s.tc.GetClientID(),
	}
	return s.tc.POST(path, body)
}

func (s *authSteps) getWithInvalidToken(ctx context.Context, path, token string) error {
	return s.tc.GET(path, map[string]string{
		"Authorization": "Bearer " + token,
	})
}

func (s *authSteps) requestAuthWithUnknownClientID(ctx context.Context, clientID string) error {
	body := map[string]interface{}{
		"email":        "test@example.com",
		"client_id":    clientID,
		"scopes":       []string{"openid"},
		"redirect_uri": s.tc.GetRedirectURI(),
		"state":        "test-state-123",
	}
	return s.tc.POST("/auth/authorize", body)
}

func (s *authSteps) requestAuthWithEmptyClientID(ctx context.Context) error {
	body := map[string]interface{}{
		"email":        "test@example.com",
		"client_id":    "",
		"scopes":       []string{"openid"},
		"redirect_uri": s.tc.GetRedirectURI(),
		"state":        "test-state-123",
	}
	return s.tc.POST("/auth/authorize", body)
}

func (s *authSteps) requestUserInfo(ctx context.Context) error {
	accessToken, err := s.tc.GetResponseField("access_token")
	if err != nil {
		return err
	}
	s.tc.SetAccessToken(accessToken.(string))

	return s.tc.GET("/auth/userinfo", map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

func (s *authSteps) saveTokensFromResponse(ctx context.Context) error {
	accessTokenRaw, err := s.tc.GetResponseField("access_token")
	if err != nil {
		return err
	}
	accessToken, err := toString(accessTokenRaw)
	if err != nil {
		return err
	}
	refreshTokenRaw, err := s.tc.GetResponseField("refresh_token")
	if err != nil {
		return err
	}
	refreshToken, err := toString(refreshTokenRaw)
	if err != nil {
		return err
	}
	s.tc.SetAccessToken(accessToken)
	s.tc.SetRefreshToken(refreshToken)
	s.tc.SetAccessTokenFor("latest", accessToken)
	s.tc.SetRefreshTokenFor("latest", refreshToken)

	if idTokenRaw, err := s.tc.GetResponseField("id_token"); err == nil {
		if idToken, convErr := toString(idTokenRaw); convErr == nil {
			_ = idToken
		}
	}
	return nil
}

func (s *authSteps) saveTokensFromResponseAs(ctx context.Context, name string) error {
	if err := s.saveTokensFromResponse(ctx); err != nil {
		return err
	}
	s.tc.SetAccessTokenFor(name, s.tc.GetAccessToken())
	s.tc.SetRefreshTokenFor(name, s.tc.GetRefreshToken())
	return nil
}

func (s *authSteps) refreshTokensWithSavedRefreshToken(ctx context.Context) error {
	refreshToken := s.tc.GetRefreshToken()
	if refreshToken == "" {
		return fmt.Errorf("no refresh token saved")
	}

	body := map[string]interface{}{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     s.tc.GetClientID(),
	}
	if err := s.tc.POST("/auth/token", body); err != nil {
		return err
	}
	if s.tc.GetLastResponseStatus() == http.StatusOK {
		s.tc.SetPreviousRefreshToken(refreshToken)
		return s.saveTokensFromResponse(ctx)
	}
	return nil
}

func (s *authSteps) attemptRefreshWithPreviousRefreshToken(ctx context.Context) error {
	refreshToken := s.tc.GetPreviousRefreshToken()
	if refreshToken == "" {
		return fmt.Errorf("no previous refresh token saved")
	}

	body := map[string]interface{}{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     s.tc.GetClientID(),
	}
	return s.tc.POST("/auth/token", body)
}

func (s *authSteps) newRefreshTokenShouldDifferFromPrevious(ctx context.Context) error {
	if s.tc.GetRefreshToken() == "" || s.tc.GetPreviousRefreshToken() == "" {
		return fmt.Errorf("refresh tokens not captured for comparison")
	}
	if s.tc.GetRefreshToken() == s.tc.GetPreviousRefreshToken() {
		return fmt.Errorf("expected rotated refresh token to differ from previous")
	}
	return nil
}

func (s *authSteps) revokeSavedRefreshToken(ctx context.Context) error {
	refreshToken := s.tc.GetRefreshToken()
	if refreshToken == "" {
		return fmt.Errorf("no refresh token saved")
	}
	body := map[string]interface{}{
		"token":           refreshToken,
		"token_type_hint": "refresh_token",
	}
	return s.tc.POST("/auth/revoke", body)
}

func (s *authSteps) revokeSavedAccessToken(ctx context.Context) error {
	accessToken := s.tc.GetAccessToken()
	if accessToken == "" {
		return fmt.Errorf("no access token saved")
	}
	body := map[string]interface{}{
		"token":           accessToken,
		"token_type_hint": "access_token",
	}
	return s.tc.POST("/auth/revoke", body)
}

func (s *authSteps) saveUserIDFromUserInfo(ctx context.Context) error {
	userID, err := s.tc.GetResponseField("sub")
	if err != nil {
		return err
	}
	s.tc.SetUserID(userID.(string))
	return nil
}

func (s *authSteps) deleteUserViaAdmin(ctx context.Context) error {
	userID := s.tc.GetUserID()
	if userID == "" {
		return fmt.Errorf("no user ID saved")
	}
	return s.tc.DELETE("/admin/auth/users/"+userID, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *authSteps) deleteUserViaAdminWithToken(ctx context.Context, token string) error {
	userID := s.tc.GetUserID()
	if userID == "" {
		return fmt.Errorf("no user ID saved")
	}
	return s.tc.DELETE("/admin/auth/users/"+userID, map[string]string{
		"X-Admin-Token": token,
	})
}

func (s *authSteps) deleteSpecificUserViaAdmin(ctx context.Context, userID string) error {
	return s.tc.DELETE("/admin/auth/users/"+userID, map[string]string{
		"X-Admin-Token": s.tc.GetAdminToken(),
	})
}

func (s *authSteps) attemptGetUserInfo(ctx context.Context) error {
	return s.tc.GET("/auth/userinfo", map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

func (s *authSteps) listSessionsWithAccessToken(ctx context.Context, tokenName string) error {
	token := s.tc.GetAccessTokenFor(tokenName)
	if token == "" {
		token = s.tc.GetAccessToken()
	}
	if token == "" {
		return fmt.Errorf("no access token saved for %s", tokenName)
	}
	return s.tc.GET("/auth/sessions", map[string]string{
		"Authorization": "Bearer " + token,
	})
}

func (s *authSteps) responseShouldListAtLeastNSessions(ctx context.Context, expected int) error {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to parse sessions response: %w", err)
	}

	rawSessions, ok := data["sessions"].([]interface{})
	if !ok {
		return fmt.Errorf("sessions field missing or invalid")
	}
	if len(rawSessions) < expected {
		return fmt.Errorf("expected at least %d sessions, got %d", expected, len(rawSessions))
	}
	return nil
}

func (s *authSteps) saveCurrentSessionIDAs(ctx context.Context, name string) error {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to parse sessions response: %w", err)
	}

	rawSessions, ok := data["sessions"].([]interface{})
	if !ok {
		return fmt.Errorf("sessions field missing or invalid")
	}

	for _, raw := range rawSessions {
		sessionMap, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		isCurrent, _ := sessionMap["is_current"].(bool)
		if isCurrent {
			sessionID, err := toString(sessionMap["session_id"])
			if err != nil {
				return err
			}
			s.tc.SetSessionIDFor(name, sessionID)
			return nil
		}
	}

	return fmt.Errorf("no current session found in response")
}

func (s *authSteps) revokeSessionUsingAccessToken(ctx context.Context, sessionName, tokenName string) error {
	sessionID := s.tc.GetSessionIDFor(sessionName)
	if sessionID == "" {
		return fmt.Errorf("no session id saved for %s", sessionName)
	}
	token := s.tc.GetAccessTokenFor(tokenName)
	if token == "" {
		token = s.tc.GetAccessToken()
	}
	if token == "" {
		return fmt.Errorf("no access token saved for %s", tokenName)
	}

	return s.tc.DELETE("/auth/sessions/"+sessionID, map[string]string{
		"Authorization": "Bearer " + token,
	})
}

func (s *authSteps) requestUserInfoWithNamedAccessToken(ctx context.Context, tokenName string) error {
	token := s.tc.GetAccessTokenFor(tokenName)
	if token == "" {
		token = s.tc.GetAccessToken()
	}
	if token == "" {
		return fmt.Errorf("no access token saved for %s", tokenName)
	}
	return s.tc.GET("/auth/userinfo", map[string]string{
		"Authorization": "Bearer " + token,
	})
}

func toString(value interface{}) (string, error) {
	if value == nil {
		return "", fmt.Errorf("value is nil")
	}
	switch v := value.(type) {
	case string:
		return v, nil
	default:
		return fmt.Sprint(v), nil
	}
}
