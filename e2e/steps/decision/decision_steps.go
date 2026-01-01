package decision

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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

// RegisterSteps registers decision-related step definitions
func RegisterSteps(ctx *godog.ScenarioContext, tc TestContext) {
	steps := &decisionSteps{
		tc:              tc,
		sanctionsMocks:  make(map[string]bool),
		savedDecisions:  make(map[string]map[string]interface{}),
	}

	// Decision evaluation steps
	ctx.Step(`^I evaluate "([^"]*)" for national_id "([^"]*)"$`, steps.evaluateDecision)
	ctx.Step(`^I evaluate "([^"]*)" for national_id "([^"]*)" without authentication$`, steps.evaluateDecisionWithoutAuth)
	ctx.Step(`^I evaluate "([^"]*)" without national_id$`, steps.evaluateDecisionWithoutNationalID)

	// Decision response assertion steps
	ctx.Step(`^the decision status should be "([^"]*)"$`, steps.decisionStatusShouldBe)
	ctx.Step(`^the decision reason should be "([^"]*)"$`, steps.decisionReasonShouldBe)
	ctx.Step(`^the conditions should include "([^"]*)"$`, steps.conditionsShouldInclude)
	ctx.Step(`^the evidence field "([^"]*)" should be (true|false)$`, steps.evidenceFieldShouldBe)

	// Sanctions mock setup steps
	ctx.Step(`^the sanctions registry marks "([^"]*)" as listed$`, steps.sanctionsRegistryMarksAsListed)
	ctx.Step(`^the sanctions registry marks "([^"]*)" as not listed$`, steps.sanctionsRegistryMarksAsNotListed)

	// Decision saving steps
	ctx.Step(`^I save the decision response as "([^"]*)"$`, steps.saveDecisionResponse)
}

type decisionSteps struct {
	tc              TestContext
	sanctionsMocks  map[string]bool // nationalID -> listed
	savedDecisions  map[string]map[string]interface{}
}

func (s *decisionSteps) evaluateDecision(ctx context.Context, purpose, nationalID string) error {
	body := map[string]interface{}{
		"purpose": purpose,
		"context": map[string]interface{}{
			"national_id": nationalID,
		},
	}
	return s.tc.POSTWithHeaders("/decision/evaluate", body, map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

func (s *decisionSteps) evaluateDecisionWithoutAuth(ctx context.Context, purpose, nationalID string) error {
	body := map[string]interface{}{
		"purpose": purpose,
		"context": map[string]interface{}{
			"national_id": nationalID,
		},
	}
	return s.tc.POST("/decision/evaluate", body)
}

func (s *decisionSteps) evaluateDecisionWithoutNationalID(ctx context.Context, purpose string) error {
	body := map[string]interface{}{
		"purpose": purpose,
		"context": map[string]interface{}{},
	}
	return s.tc.POSTWithHeaders("/decision/evaluate", body, map[string]string{
		"Authorization": "Bearer " + s.tc.GetAccessToken(),
	})
}

func (s *decisionSteps) decisionStatusShouldBe(ctx context.Context, expectedStatus string) error {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to parse response: %w (body: %s)", err, string(s.tc.GetLastResponseBody()))
	}

	status, ok := data["status"]
	if !ok {
		return fmt.Errorf("status field not found in response: %v", data)
	}

	if status != expectedStatus {
		return fmt.Errorf("expected status %q but got %q (full response: %v)", expectedStatus, status, data)
	}
	return nil
}

func (s *decisionSteps) decisionReasonShouldBe(ctx context.Context, expectedReason string) error {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	reason, ok := data["reason"]
	if !ok {
		return fmt.Errorf("reason field not found in response: %v", data)
	}

	if reason != expectedReason {
		return fmt.Errorf("expected reason %q but got %q", expectedReason, reason)
	}
	return nil
}

func (s *decisionSteps) conditionsShouldInclude(ctx context.Context, expectedCondition string) error {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	conditionsRaw, ok := data["conditions"]
	if !ok {
		return fmt.Errorf("conditions field not found in response: %v", data)
	}

	conditions, ok := conditionsRaw.([]interface{})
	if !ok {
		return fmt.Errorf("conditions is not an array: %v", conditionsRaw)
	}

	for _, c := range conditions {
		if c == expectedCondition {
			return nil
		}
	}

	return fmt.Errorf("condition %q not found in conditions: %v", expectedCondition, conditions)
}

func (s *decisionSteps) evidenceFieldShouldBe(ctx context.Context, field, expectedValue string) error {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	evidence, ok := data["evidence"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("evidence not found or not an object in response: %v", data)
	}

	// Map field names from feature file to JSON keys
	jsonField := s.mapFieldName(field)

	val, exists := evidence[jsonField]
	if !exists {
		return fmt.Errorf("evidence field %q (json: %q) not found in evidence: %v", field, jsonField, evidence)
	}

	boolVal, ok := val.(bool)
	if !ok {
		return fmt.Errorf("evidence field %q is not a boolean: %v", field, val)
	}

	expectedBool := expectedValue == "true"
	if boolVal != expectedBool {
		return fmt.Errorf("evidence field %q: expected %v but got %v", field, expectedBool, boolVal)
	}

	return nil
}

// mapFieldName maps feature file field names to JSON field names
func (s *decisionSteps) mapFieldName(field string) string {
	mapping := map[string]string{
		"is_over_18":        "is_over_18",
		"citizen_valid":     "citizen_valid",
		"has_credential":    "has_credential",
		"sanctions_listed":  "sanctions_listed",
	}
	if jsonField, ok := mapping[field]; ok {
		return jsonField
	}
	// Default: convert underscores to snake_case (already in snake_case)
	return strings.ReplaceAll(field, "-", "_")
}

func (s *decisionSteps) sanctionsRegistryMarksAsListed(ctx context.Context, nationalID string) error {
	// This sets up mock state that would be used by the test environment
	// In a real E2E environment, this would configure the mock sanctions registry
	s.sanctionsMocks[nationalID] = true
	return nil
}

func (s *decisionSteps) sanctionsRegistryMarksAsNotListed(ctx context.Context, nationalID string) error {
	s.sanctionsMocks[nationalID] = false
	return nil
}

func (s *decisionSteps) saveDecisionResponse(ctx context.Context, name string) error {
	var data map[string]interface{}
	if err := json.Unmarshal(s.tc.GetLastResponseBody(), &data); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	s.savedDecisions[name] = data
	return nil
}
