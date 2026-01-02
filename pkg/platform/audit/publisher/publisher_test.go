package publisher

import (
	"context"
	"errors"
	"testing"
	"time"

	id "credo/pkg/domain"
	audit "credo/pkg/platform/audit"
	"credo/pkg/platform/audit/store/memory"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingStore struct {
	err error
}

func (s *failingStore) Append(_ context.Context, _ audit.Event) error {
	return s.err
}

func (s *failingStore) ListByUser(_ context.Context, _ id.UserID) ([]audit.Event, error) {
	return nil, nil
}

func (s *failingStore) ListAll(_ context.Context) ([]audit.Event, error) {
	return nil, nil
}

func (s *failingStore) ListRecent(_ context.Context, _ int) ([]audit.Event, error) {
	return nil, nil
}

func TestPublisher_EmitStoresEvent(t *testing.T) {
	store := memory.NewInMemoryStore()
	pub := NewPublisher(store)

	userID := id.UserID(uuid.New())
	event := audit.Event{
		UserID: userID,
		Action: string(audit.EventUserCreated),
	}

	err := pub.Emit(context.Background(), event)
	require.NoError(t, err)

	events, err := pub.List(context.Background(), userID)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, string(audit.EventUserCreated), events[0].Action)
}

func TestPublisher_SetsTimestamp(t *testing.T) {
	store := memory.NewInMemoryStore()
	pub := NewPublisher(store)

	userID := id.UserID(uuid.New())
	event := audit.Event{
		UserID: userID,
		Action: string(audit.EventUserCreated),
		// Timestamp not set
	}

	before := time.Now()
	err := pub.Emit(context.Background(), event)
	require.NoError(t, err)
	after := time.Now()

	events, err := pub.List(context.Background(), userID)
	require.NoError(t, err)
	require.Len(t, events, 1)

	assert.True(t, !events[0].Timestamp.Before(before), "timestamp should be >= before")
	assert.True(t, !events[0].Timestamp.After(after), "timestamp should be <= after")
}

func TestPublisher_PreservesExistingTimestamp(t *testing.T) {
	store := memory.NewInMemoryStore()
	pub := NewPublisher(store)

	userID := id.UserID(uuid.New())
	customTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	event := audit.Event{
		UserID:    userID,
		Action:    string(audit.EventUserCreated),
		Timestamp: customTime,
	}

	err := pub.Emit(context.Background(), event)
	require.NoError(t, err)

	events, err := pub.List(context.Background(), userID)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, customTime, events[0].Timestamp)
}

func TestPublisher_EmitReturnsError(t *testing.T) {
	storeErr := errors.New("append failed")
	pub := NewPublisher(&failingStore{err: storeErr})

	err := pub.Emit(context.Background(), audit.Event{Action: string(audit.EventUserCreated)})
	require.ErrorIs(t, err, storeErr)
}
