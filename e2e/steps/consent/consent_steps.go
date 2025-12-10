package consent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// TestContext interface defines the methods needed from the main test context
type TestContext interface {
	POST(path string, body interface{}) error
	POSTWithHeaders(path string, body interface{}, headers map[string]string) error
	GET(path string, headers map[string]string) error
	GetResponseField(field string) (interface{}, error)
	ResponseContains(field string) bool
	GetAccessToken() string
	SetAccessToken(token string)
	GetClientID() string
	GetRedirectURI() string
	GetLastResponseBody() []byte
}

// RegisterSteps registers consent-related step definitions
func RegisterSteps(ctx *godog.ScenarioContext, tc TestContext) {
	steps := &consentSteps{tc: tc}

	// Consent management steps
	ctx.Step(`^I am authenticated as "([^"]*)"$`, steps.authenticateAs)
	ctx.Step(`^I grant consent for purposes "([^"]*)"$`, steps.grantConsentForPurposes)
	ctx.Step(`^I revoke consent for purposes "([^"]*)"$`, steps.revokeConsentForPurposes)
	ctx.Step(`^I list my consents$`, steps.listMyConsents)
	ctx.Step(`^I grant consent for purposes "([^"]*)" without authentication$`, steps.grantConsentWithoutAuth)
	ctx.Step(`^I revoke consent for purposes "([^"]*)" without authentication$`, steps.revokeConsentWithoutAuth)
	ctx.Step(`^I POST to "([^"]*)" with empty purposes array$`, steps.postWithEmptyPurposes)
	ctx.Step(`^I wait (\d+) seconds$`, steps.waitSeconds)

	// Consent assertion steps
	ctx.Step(`^the response should contain at least (\d+) consent records$`, steps.responseShouldContainAtLeastNConsents)
	ctx.Step(`^each granted consent should have "([^"]*)" equal to "([^"]*)"$`, steps.eachGrantedConsentShouldHaveField)
	ctx.Step(`^each granted consent should have "([^"]*)"$`, steps.eachGrantedConsentShouldHaveFieldPresent)
	ctx.Step(`^the revoked consent should have "([^"]*)" equal to "([^"]*)"$`, steps.revokedConsentShouldHaveField)
	ctx.Step(`^the revoked consent should have "([^"]*)"$`, steps.revokedConsentShouldHaveFieldPresent)
	ctx.Step(`^the consent for purpose "([^"]*)" should have status "([^"]*)"$`, steps.consentForPurposeShouldHaveStatus)
	ctx.Step(`^the consent should have a new "([^"]*)" timestamp$`, steps.consentShouldHaveNewTimestamp)
}

type consentSteps struct {
	tc            TestContext
	prevGrantedAt map[string]time.Time
	prevExpiresAt map[string]time.Time
	lastGrantedAt map[string]time.Time
	lastExpiresAt map[string]time.Time
}

func (s *consentSteps) authenticateAs(ctx context.Context, email string) error {
	// Start auth flow to obtain access token
	body := map[string]interface{}{
		"email":        email,
		"client_id":    s.tc.GetClientID(),
		"scopes":       []string{"openid", "profile"},
		"redirect_uri": s.tc.GetRedirectURI(),
		"state":        "consent-state",
	}
	if err := s.tc.POST("/auth/authorize", body); err != nil {
		return err
	}
	code, err := s.tc.GetResponseField("code")
	if err != nil {
		return err
	}

	tokenReq := map[string]interface{}{
		"grant_type":   "authorization_code",
		"code":         code.(string),
		"redirect_uri": s.tc.GetRedirectURI(),
		"client_id":    s.tc.GetClientID(),
	}
	if err := s.tc.POST("/auth/token", tokenReq); err != nil {
		return err
	}
	accessToken, err := s.tc.GetResponseField("access_token")
	if err != nil {
		return err
	}
	s.tc.SetAccessToken(accessToken.(string))
	return nil
}

func (s *consentSteps) grantConsentForPurposes(ctx context.Context, purposes string) error {
	s.ensureMaps()
	// snapshot current timestamps before re-grant to validate renewal
	s.prevGrantedAt = cloneTimeMap(s.lastGrantedAt)
	s.prevExpiresAt = cloneTimeMap(s.lastExpiresAt)

	body := map[string]interface{}{
		"purposes": strings.Split(purposes, ","),
	}
	err := s.tc.POSTWithHeaders("/auth/consent", body, map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
	if err != nil {
		return err
	}
	s.captureGrantTimestamps()
	return nil
}

func (s *consentSteps) revokeConsentForPurposes(ctx context.Context, purposes string) error {
	body := map[string]interface{}{
		"purposes": strings.Split(purposes, ","),
	}
	return s.tc.POSTWithHeaders("/auth/consent/revoke", body, map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

func (s *consentSteps) listMyConsents(ctx context.Context) error {
	return s.tc.GET("/auth/consent", map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

func (s *consentSteps) grantConsentWithoutAuth(ctx context.Context, purposes string) error {
	body := map[string]interface{}{
		"purposes": strings.Split(purposes, ","),
	}
	// Make request without Authorization header
	return s.tc.POST("/auth/consent", body)
}

func (s *consentSteps) revokeConsentWithoutAuth(ctx context.Context, purposes string) error {
	body := map[string]interface{}{
		"purposes": strings.Split(purposes, ","),
	}
	// Make request without Authorization header
	return s.tc.POST("/auth/consent/revoke", body)
}

func (s *consentSteps) postWithEmptyPurposes(ctx context.Context, path string) error {
	body := map[string]interface{}{
		"purposes": []string{},
	}
	headers := map[string]string{}
	if token := s.tc.GetAccessToken(); token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	return s.tc.POSTWithHeaders(path, body, headers)
}

func (s *consentSteps) waitSeconds(ctx context.Context, seconds int) error {
	time.Sleep(time.Duration(seconds) * time.Second)
	return nil
}

func (s *consentSteps) responseShouldContainAtLeastNConsents(ctx context.Context, count int) error {
	consents, err := s.extractArray("consents")
	if err != nil {
		return err
	}
	if len(consents) < count {
		return fmt.Errorf("expected at least %d consents, got %d", count, len(consents))
	}
	return nil
}

func (s *consentSteps) eachGrantedConsentShouldHaveField(ctx context.Context, field, value string) error {
	granted, err := s.extractArray("granted")
	if err != nil {
		return err
	}
	for _, g := range granted {
		if g[field] != value {
			return fmt.Errorf("expected %s to be %s, got %v", field, value, g[field])
		}
	}
	return nil
}

func (s *consentSteps) eachGrantedConsentShouldHaveFieldPresent(ctx context.Context, field string) error {
	granted, err := s.extractArray("granted")
	if err != nil {
		return err
	}
	for _, g := range granted {
		if _, ok := g[field]; !ok {
			return fmt.Errorf("field %s missing in grant %v", field, g)
		}
	}
	return nil
}

func (s *consentSteps) revokedConsentShouldHaveField(ctx context.Context, field, value string) error {
	revoked, err := s.extractArray("revoked")
	if err != nil {
		return err
	}
	for _, r := range revoked {
		if r[field] != value {
			return fmt.Errorf("expected %s to be %s, got %v", field, value, r[field])
		}
	}
	return nil
}

func (s *consentSteps) revokedConsentShouldHaveFieldPresent(ctx context.Context, field string) error {
	revoked, err := s.extractArray("revoked")
	if err != nil {
		return err
	}
	for _, r := range revoked {
		if _, ok := r[field]; !ok {
			return fmt.Errorf("field %s missing in revoked consent %v", field, r)
		}
	}
	return nil
}

func (s *consentSteps) consentForPurposeShouldHaveStatus(ctx context.Context, purpose, status string) error {
	consents, err := s.extractArray("consents")
	if err != nil {
		// try "granted" for immediate grant responses
		consents, err = s.extractArray("granted")
		if err != nil {
			return err
		}
	}
	for _, c := range consents {
		if c["purpose"] == purpose {
			if c["status"] != status {
				return fmt.Errorf("expected status %s for %s, got %v", status, purpose, c["status"])
			}
			return nil
		}
	}
	return fmt.Errorf("purpose %s not found in response", purpose)
}

func (s *consentSteps) consentShouldHaveNewTimestamp(ctx context.Context, field string) error {
	if s.prevGrantedAt == nil {
		return fmt.Errorf("no previous consent timestamp to compare")
	}
	granted, err := s.extractArray("granted")
	if err != nil {
		return err
	}
	if len(granted) == 0 {
		return fmt.Errorf("no granted consents in response")
	}
	for _, g := range granted {
		p := g["purpose"].(string)
		raw := g[field]
		strVal, ok := raw.(string)
		if !ok {
			return fmt.Errorf("%s not a string for purpose %s", field, p)
		}
		t, err := time.Parse(time.RFC3339, strVal)
		if err != nil {
			return err
		}
		var prev time.Time
		if field == "granted_at" {
			prev = s.prevGrantedAt[p]
			s.lastGrantedAt[p] = t
		} else {
			prev = s.prevExpiresAt[p]
			s.lastExpiresAt[p] = t
		}
		if !prev.IsZero() && !t.After(prev) {
			return fmt.Errorf("%s did not advance for %s", field, p)
		}
	}
	return nil
}

func (s *consentSteps) extractArray(key string) ([]map[string]interface{}, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return nil, err
	}
	arrRaw, ok := data[key]
	if !ok {
		return nil, fmt.Errorf("key %s not found in response", key)
	}
	items, ok := arrRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("key %s is not an array", key)
	}
	var result []map[string]interface{}
	for _, item := range items {
		if m, ok := item.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}
	return result, nil
}

func (s *consentSteps) captureGrantTimestamps() {
	granted, err := s.extractArray("granted")
	if err != nil {
		return
	}
	for _, g := range granted {
		p := g["purpose"].(string)
		if tStr, ok := g["granted_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339, tStr); err == nil {
				s.lastGrantedAt[p] = t
			}
		}
		if tStr, ok := g["expires_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339, tStr); err == nil {
				s.lastExpiresAt[p] = t
			}
		}
	}
}

func (s *consentSteps) ensureMaps() {
	if s.prevGrantedAt == nil {
		s.prevGrantedAt = map[string]time.Time{}
	}
	if s.prevExpiresAt == nil {
		s.prevExpiresAt = map[string]time.Time{}
	}
	if s.lastGrantedAt == nil {
		s.lastGrantedAt = map[string]time.Time{}
	}
	if s.lastExpiresAt == nil {
		s.lastExpiresAt = map[string]time.Time{}
	}
}

func cloneTimeMap(src map[string]time.Time) map[string]time.Time {
	if src == nil {
		return map[string]time.Time{}
	}
	dst := make(map[string]time.Time, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
