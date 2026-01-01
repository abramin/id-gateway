package vc

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
	GetLastResponseBody() []byte
	GetLastResponseStatus() int
}

// RegisterSteps registers VC-related step definitions
func RegisterSteps(ctx *godog.ScenarioContext, tc TestContext) {
	steps := &vcSteps{
		tc:           tc,
		savedFields:  make(map[string]string),
		citizenMocks: make(map[string]citizenMock),
	}

	// Credential issuance steps
	ctx.Step(`^I request an AgeOver18 credential with national_id "([^"]*)"$`, steps.requestAgeOver18Credential)
	ctx.Step(`^I request an AgeOver18 credential with national_id "([^"]*)" without authentication$`, steps.requestCredentialWithoutAuth)
	ctx.Step(`^I request a credential with invalid type "([^"]*)" and national_id "([^"]*)"$`, steps.requestCredentialWithInvalidType)
	ctx.Step(`^I POST to "/vc/issue" with empty national_id$`, steps.postWithEmptyNationalID)
	ctx.Step(`^I POST to "/vc/issue" with missing type$`, steps.postWithMissingType)
	ctx.Step(`^I verify a credential with id "([^"]*)"$`, steps.verifyCredential)
	ctx.Step(`^I verify a credential with id "([^"]*)" without authentication$`, steps.verifyCredentialWithoutAuth)
	ctx.Step(`^I POST to "/vc/verify" with empty credential_id$`, steps.postVerifyWithEmptyCredentialID)
	ctx.Step(`^I verify the saved credential_id "([^"]*)"$`, steps.verifySavedCredential)

	// Response assertion steps
	ctx.Step(`^the response field "([^"]*)" should start with "([^"]*)"$`, steps.fieldShouldStartWith)
	ctx.Step(`^the credential claims should contain "([^"]*)" equal to (true|false)$`, steps.claimsShouldContainBool)
	ctx.Step(`^the credential claims should contain "([^"]*)"$`, steps.claimsShouldContainField)
	ctx.Step(`^the credential claims should NOT contain "([^"]*)"$`, steps.claimsShouldNotContainField)

	// Registry mock steps
	ctx.Step(`^the citizen registry contains a record for "([^"]*)" with birth date "([^"]*)"$`, steps.registryContainsCitizen)
	ctx.Step(`^the citizen registry contains a record for "([^"]*)" with birth date making them (\d+) years old$`, steps.registryContainsCitizenWithAge)
	ctx.Step(`^the citizen registry contains a record for "([^"]*)" with birth date making them exactly (\d+) years old$`, steps.registryContainsCitizenExactAge)
	ctx.Step(`^the citizen registry has no record for national_id "([^"]*)"$`, steps.registryHasNoRecord)
	ctx.Step(`^the citizen registry contains an invalid record for "([^"]*)"$`, steps.registryContainsInvalidRecord)

	// Consent steps (reuse from consent package but with vc context)
	ctx.Step(`^I have NOT granted consent for purposes "([^"]*)"$`, steps.haveNotGrantedConsent)
	ctx.Step(`^I have revoked consent for purposes "([^"]*)"$`, steps.haveRevokedConsent)

	// Regulated mode steps
	ctx.Step(`^the system is NOT running in regulated mode$`, steps.systemNotInRegulatedMode)

	// Field saving and comparison steps
	ctx.Step(`^I save the response field "([^"]*)" as "([^"]*)"$`, steps.saveResponseField)
	ctx.Step(`^the response field "([^"]*)" should not equal saved "([^"]*)"$`, steps.fieldShouldNotEqualSaved)
}

type citizenMock struct {
	nationalID  string
	birthDate   string
	valid       bool
	shouldExist bool
}

type vcSteps struct {
	tc           TestContext
	savedFields  map[string]string
	citizenMocks map[string]citizenMock
}

func (s *vcSteps) requestAgeOver18Credential(ctx context.Context, nationalID string) error {
	body := map[string]interface{}{
		"type":        "AgeOver18",
		"national_id": nationalID,
	}
	return s.tc.POSTWithHeaders("/vc/issue", body, map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

func (s *vcSteps) requestCredentialWithoutAuth(ctx context.Context, nationalID string) error {
	body := map[string]interface{}{
		"type":        "AgeOver18",
		"national_id": nationalID,
	}
	return s.tc.POST("/vc/issue", body)
}

func (s *vcSteps) requestCredentialWithInvalidType(ctx context.Context, credType, nationalID string) error {
	body := map[string]interface{}{
		"type":        credType,
		"national_id": nationalID,
	}
	return s.tc.POSTWithHeaders("/vc/issue", body, map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

func (s *vcSteps) postWithEmptyNationalID(ctx context.Context) error {
	body := map[string]interface{}{
		"type":        "AgeOver18",
		"national_id": "",
	}
	return s.tc.POSTWithHeaders("/vc/issue", body, map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

func (s *vcSteps) postWithMissingType(ctx context.Context) error {
	body := map[string]interface{}{
		"national_id": "TEST123456",
	}
	return s.tc.POSTWithHeaders("/vc/issue", body, map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

func (s *vcSteps) verifyCredential(ctx context.Context, credentialID string) error {
	body := map[string]interface{}{
		"credential_id": credentialID,
	}
	return s.tc.POSTWithHeaders("/vc/verify", body, map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

func (s *vcSteps) verifyCredentialWithoutAuth(ctx context.Context, credentialID string) error {
	body := map[string]interface{}{
		"credential_id": credentialID,
	}
	return s.tc.POST("/vc/verify", body)
}

func (s *vcSteps) postVerifyWithEmptyCredentialID(ctx context.Context) error {
	body := map[string]interface{}{
		"credential_id": "",
	}
	return s.tc.POSTWithHeaders("/vc/verify", body, map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

func (s *vcSteps) verifySavedCredential(ctx context.Context, key string) error {
	credentialID, ok := s.savedFields[key]
	if !ok {
		return fmt.Errorf("saved field %q not found", key)
	}
	return s.verifyCredential(ctx, credentialID)
}

func (s *vcSteps) fieldShouldStartWith(ctx context.Context, field, prefix string) error {
	val, err := s.tc.GetResponseField(field)
	if err != nil {
		return err
	}
	strVal, ok := val.(string)
	if !ok {
		return fmt.Errorf("field %s is not a string: %v", field, val)
	}
	if !strings.HasPrefix(strVal, prefix) {
		return fmt.Errorf("field %s should start with %q but got %q", field, prefix, strVal)
	}
	return nil
}

func (s *vcSteps) claimsShouldContainBool(ctx context.Context, claimName, expectedValue string) error {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	claims, ok := data["claims"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("claims not found or not an object in response")
	}

	val, exists := claims[claimName]
	if !exists {
		return fmt.Errorf("claim %q not found in claims: %v", claimName, claims)
	}

	boolVal, ok := val.(bool)
	if !ok {
		return fmt.Errorf("claim %q is not a boolean: %v", claimName, val)
	}

	expectedBool := expectedValue == "true"
	if boolVal != expectedBool {
		return fmt.Errorf("claim %q: expected %v but got %v", claimName, expectedBool, boolVal)
	}

	return nil
}

func (s *vcSteps) claimsShouldContainField(ctx context.Context, claimName string) error {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	claims, ok := data["claims"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("claims not found or not an object in response")
	}

	if _, exists := claims[claimName]; !exists {
		return fmt.Errorf("claim %q not found in claims: %v", claimName, claims)
	}

	return nil
}

func (s *vcSteps) claimsShouldNotContainField(ctx context.Context, claimName string) error {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	claims, ok := data["claims"].(map[string]interface{})
	if !ok {
		// No claims object means no claim field - this is acceptable
		return nil
	}

	if _, exists := claims[claimName]; exists {
		return fmt.Errorf("claim %q should NOT be present but was found in claims: %v", claimName, claims)
	}

	return nil
}

func (s *vcSteps) registryContainsCitizen(ctx context.Context, nationalID, birthDate string) error {
	// This step sets up expectations for the mock registry
	// The actual mock configuration would be done via the test environment
	s.citizenMocks[nationalID] = citizenMock{
		nationalID:  nationalID,
		birthDate:   birthDate,
		valid:       true,
		shouldExist: true,
	}
	return nil
}

func (s *vcSteps) registryContainsCitizenWithAge(ctx context.Context, nationalID string, age int) error {
	// Calculate birth date to make them exactly `age` years old (minus one day to be under age)
	birthDate := time.Now().AddDate(-age, 0, 1).Format("2006-01-02")
	s.citizenMocks[nationalID] = citizenMock{
		nationalID:  nationalID,
		birthDate:   birthDate,
		valid:       true,
		shouldExist: true,
	}
	return nil
}

func (s *vcSteps) registryContainsCitizenExactAge(ctx context.Context, nationalID string, age int) error {
	// Calculate birth date to make them exactly `age` years old today
	birthDate := time.Now().AddDate(-age, 0, 0).Format("2006-01-02")
	s.citizenMocks[nationalID] = citizenMock{
		nationalID:  nationalID,
		birthDate:   birthDate,
		valid:       true,
		shouldExist: true,
	}
	return nil
}

func (s *vcSteps) registryHasNoRecord(ctx context.Context, nationalID string) error {
	s.citizenMocks[nationalID] = citizenMock{
		nationalID:  nationalID,
		shouldExist: false,
	}
	return nil
}

func (s *vcSteps) registryContainsInvalidRecord(ctx context.Context, nationalID string) error {
	s.citizenMocks[nationalID] = citizenMock{
		nationalID:  nationalID,
		birthDate:   "1980-01-01",
		valid:       false,
		shouldExist: true,
	}
	return nil
}

func (s *vcSteps) haveNotGrantedConsent(ctx context.Context, purposes string) error {
	// This step indicates that no consent has been granted
	// The test environment should ensure no consent exists for this user
	return nil
}

func (s *vcSteps) haveRevokedConsent(ctx context.Context, purposes string) error {
	// Revoke consent for the given purposes
	purposeList := strings.Split(purposes, ",")
	body := map[string]interface{}{
		"purposes": purposeList,
	}
	return s.tc.POSTWithHeaders("/auth/consent/revoke", body, map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

func (s *vcSteps) systemNotInRegulatedMode(ctx context.Context) error {
	// This is handled by test environment configuration
	// REGULATED_MODE should be false or unset
	return nil
}

func (s *vcSteps) saveResponseField(ctx context.Context, field, name string) error {
	val, err := s.tc.GetResponseField(field)
	if err != nil {
		return err
	}
	s.savedFields[name] = fmt.Sprint(val)
	return nil
}

func (s *vcSteps) fieldShouldNotEqualSaved(ctx context.Context, field, savedName string) error {
	val, err := s.tc.GetResponseField(field)
	if err != nil {
		return err
	}
	saved, ok := s.savedFields[savedName]
	if !ok {
		return fmt.Errorf("no saved field named %q", savedName)
	}
	if fmt.Sprint(val) == saved {
		return fmt.Errorf("field %q should not equal saved %q but both are %q", field, savedName, saved)
	}
	return nil
}
