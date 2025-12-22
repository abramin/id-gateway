package quota

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"
)

type InMemoryQuotaStoreSuite struct {
	suite.Suite
	store *InMemoryQuotaStore
	ctx   context.Context
}

func TestInMemoryQuotaStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemoryQuotaStoreSuite))
}

func (s *InMemoryQuotaStoreSuite) SetupTest() {
	s.store = New()
	s.ctx = context.Background()
}

func (s *InMemoryQuotaStoreSuite) TestGetQuota() {
	// TODO: verify missing API key returns (nil, nil) to preserve "not found" contract.
	// TODO: verify existing quota is returned without mutating usage or period boundaries.
	s.T().Skip("TODO: add contract-focused tests for missing and existing quota records")
}

func (s *InMemoryQuotaStoreSuite) TestIncrementUsage() {
	// TODO: verify new quota is created with defaults and usage increments by count.
	// TODO: use a fixed clock (or injected time) so period start/end assertions are deterministic.
	// TODO: verify subsequent increments accumulate usage without resetting period.
	s.T().Skip("TODO: add tests for default quota creation and usage increment behavior")
}
