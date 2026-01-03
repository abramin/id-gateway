package e2e

import (
	"context"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/cucumber/godog"
	"github.com/cucumber/godog/colors"
)

var opts = godog.Options{
	Paths:  []string{"features"},
	Format: "pretty,cucumber:reports/cucumber.json",
	Output: colors.Colored(os.Stdout),
}

// sharedClientID stores the client_id created during setup, shared across all scenarios
var sharedClientID string
var sharedTenantID string

func init() {
	godog.BindCommandLineFlags("godog.", &opts)
}

func TestMain(m *testing.M) {
	flag.Parse()

	// Set tags from environment variable if provided
	if tags := os.Getenv("GODOG_TAGS"); tags != "" {
		opts.Tags = tags
	} else if os.Getenv("DISABLE_RATE_LIMITING") == "true" {
		// Exclude simulation and pending tests when rate limiting is disabled
		opts.Tags = "~@simulation && ~@pending"
	} else {
		// By default, exclude pending scenarios (not yet implemented)
		opts.Tags = "~@pending"
	}

	// Set up tenant and client once before all tests
	if err := setupTestInfrastructure(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to set up test infrastructure: %v\n", err)
		os.Exit(1)
	}

	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options:             &opts,
	}

	// Run Godog
	status := suite.Run()

	// Run any normal Go tests
	if st := m.Run(); st > status {
		status = st
	}

	os.Exit(status)
}

// setupTestInfrastructure creates a tenant and client via admin API before tests run
func setupTestInfrastructure() error {
	tc := NewTestContext()
	if err := tc.EnsureTestClient(); err != nil {
		return err
	}
	sharedClientID = tc.ClientID
	sharedTenantID = tc.TenantID
	fmt.Printf("Test infrastructure ready: tenant_id=%s, client_id=%s\n", sharedTenantID, sharedClientID)
	return nil
}

func InitializeScenario(sc *godog.ScenarioContext) {
	tc := NewTestContext()
	tc.ClientID = sharedClientID
	tc.TenantID = sharedTenantID

	sc.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		tc = NewTestContext()
		tc.ClientID = sharedClientID
		tc.TenantID = sharedTenantID
		return ctx, nil
	})

	sc.After(func(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		if err != nil {
			fmt.Printf("Scenario failed: %s\nLast Response: %s\n", sc.Name, string(tc.LastResponseBody))
		}
		return ctx, nil
	})

	RegisterSteps(sc, tc)
}
