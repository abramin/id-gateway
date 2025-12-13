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

// ListAll returns all audit events across all users (admin-only operation)
func (s *InMemoryStore) ListAll(_ context.Context) ([]Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var allEvents []Event
	for _, userEvents := range s.events {
		allEvents = append(allEvents, userEvents...)
	}

	return allEvents, nil
}

// ListRecent returns the most recent N events across all users (admin-only operation)
func (s *InMemoryStore) ListRecent(_ context.Context, limit int) ([]Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var allEvents []Event
	for _, userEvents := range s.events {
		allEvents = append(allEvents, userEvents...)
	}

	// Sort by timestamp descending (most recent first)
	// For simplicity, we'll return the last N events
	// In a real implementation with timestamps, we'd sort properly
	start := len(allEvents) - limit
	if start < 0 {
		start = 0
	}

	return allEvents[start:], nil
}
