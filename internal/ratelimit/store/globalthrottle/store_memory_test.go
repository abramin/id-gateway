package globalthrottle

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"
)

type InMemoryGlobalThrottleStoreSuite struct {
	suite.Suite
	store *InMemoryGlobalThrottleStore
	ctx   context.Context
}

func TestInMemoryGlobalThrottleStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemoryGlobalThrottleStoreSuite))
}

func (s *InMemoryGlobalThrottleStoreSuite) SetupTest() {
	s.store = New()
	s.ctx = context.Background()
}

func (s *InMemoryGlobalThrottleStoreSuite) TestIncrementGlobal() {
	// TODO: verify count increments monotonically and limitExceeded remains false for in-memory store.
	// TODO: verify multiple increments return expected counts and do not error.
	s.T().Skip("TODO: add contract-focused tests for global increment behavior")
}

func (s *InMemoryGlobalThrottleStoreSuite) TestGetGlobalCount() {
	// TODO: verify initial count is zero and reflects increments accurately.
	s.T().Skip("TODO: add contract-focused tests for reading global count")
}
