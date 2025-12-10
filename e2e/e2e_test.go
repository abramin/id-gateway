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
	Output: colors.Colored(os.Stdout),
	Format: "pretty",
}

func init() {
	godog.BindCommandLineFlags("godog.", &opts)
}

func TestFeatures(t *testing.T) {
	flag.Parse()
	opts.TestingT = t

	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options:             &opts,
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
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
