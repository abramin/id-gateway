package e2e

import (
	"github.com/cucumber/godog"

	"credo/e2e/steps/auth"
	"credo/e2e/steps/common"
	"credo/e2e/steps/consent"
)

// RegisterSteps registers all step definitions from modular packages
func RegisterSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	// Register common steps (background, generic requests, assertions)
	common.RegisterSteps(ctx, tc)

	// Register authentication-specific steps
	auth.RegisterSteps(ctx, tc)

	// Register consent-specific steps
	consent.RegisterSteps(ctx, tc)
}
