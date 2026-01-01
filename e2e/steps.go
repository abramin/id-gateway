package e2e

import (
	"github.com/cucumber/godog"

	"credo/e2e/steps/admin"
	"credo/e2e/steps/auth"
	"credo/e2e/steps/common"
	"credo/e2e/steps/consent"
	"credo/e2e/steps/decision"
	"credo/e2e/steps/ratelimit"
	"credo/e2e/steps/registry"
	"credo/e2e/steps/vc"
)

// RegisterSteps registers all step definitions from modular packages
func RegisterSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	// Register common steps (background, generic requests, assertions)
	common.RegisterSteps(ctx, tc)

	// Register authentication-specific steps
	auth.RegisterSteps(ctx, tc)

	// Register consent-specific steps
	consent.RegisterSteps(ctx, tc)

	// Register admin-specific steps (tenant/client management)
	admin.RegisterSteps(ctx, tc)

	// Register rate-limiting steps (PRD-017 FR-2b)
	ratelimit.RegisterSteps(ctx, tc)

	// Register registry steps (PRD-003 citizen/sanctions lookups)
	registry.RegisterSteps(ctx, tc)

	// Register VC steps (PRD-004 credential issuance)
	vc.RegisterSteps(ctx, tc)

	// Register decision steps (PRD-005 decision rules)
	decision.RegisterSteps(ctx, tc)
}
