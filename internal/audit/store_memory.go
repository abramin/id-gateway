package audit

import (
	"context"
	"sync"
)

type InMemoryStore struct {
	mu     sync.RWMutex
	events map[string][]Event
}

func (s *InMemoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = make(map[string][]Event)
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{events: make(map[string][]Event)}
}

func (s *InMemoryStore) Append(_ context.Context, event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events[event.UserID] = append(s.events[event.UserID], event)
	return nil
}

func (s *InMemoryStore) ListByUser(_ context.Context, userID string) ([]Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Event{}, s.events[userID]...), nil
}
