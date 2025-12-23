package globalthrottle

import "context"

type InMemoryGlobalThrottleStore struct {
	count int
}

func New() *InMemoryGlobalThrottleStore {
	return &InMemoryGlobalThrottleStore{
		count: 0,
	}

}

func (s *InMemoryGlobalThrottleStore) IncrementGlobal(_ context.Context) (count int, blocked bool, err error) {
	s.count++
	// For in-memory store, we assume no global limit breach
	return s.count, false, nil
}

func (s *InMemoryGlobalThrottleStore) GetGlobalCount(_ context.Context) (count int, err error) {
	return s.count, nil
}
