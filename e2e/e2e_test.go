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

func init() {
	godog.BindCommandLineFlags("godog.", &opts)
}

func TestMain(m *testing.M) {
	flag.Parse()

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

func InitializeScenario(sc *godog.ScenarioContext) {
	tc := NewTestContext()

	sc.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		tc = NewTestContext()
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
