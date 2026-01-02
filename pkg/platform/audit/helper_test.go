package audit

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"credo/pkg/requestcontext"

	"github.com/stretchr/testify/suite"
)

// mockEmitter is a test double for the Emitter interface.
type mockEmitter struct {
	events    []Event
	shouldErr bool
}

func (m *mockEmitter) Emit(_ context.Context, event Event) error {
	if m.shouldErr {
		return errors.New("emit failed")
	}
	m.events = append(m.events, event)
	return nil
}

// LoggerSuite tests the audit Logger helper.
//
// Justification: The Logger has conditional enrichment (request_id from context)
// and error handling paths that are unreachable via feature tests.
type LoggerSuite struct {
	suite.Suite
	emitter *mockEmitter
	logger  *Logger
}

func TestLoggerSuite(t *testing.T) {
	suite.Run(t, new(LoggerSuite))
}

func (s *LoggerSuite) SetupTest() {
	s.emitter = &mockEmitter{}
	textLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	s.logger = NewLogger(textLogger, s.emitter)
}

func (s *LoggerSuite) TestLogEnrichesWithRequestID() {
	ctx := requestcontext.WithRequestID(context.Background(), "req-12345")

	s.logger.Log(ctx, "user_created", "user_id", "test-user-id")

	s.Require().Len(s.emitter.events, 1)
	s.Equal("req-12345", s.emitter.events[0].RequestID)
}

func (s *LoggerSuite) TestLogExtractsUserID() {
	ctx := context.Background()

	s.logger.Log(ctx, "user_created", "user_id", "550e8400-e29b-41d4-a716-446655440001")

	s.Require().Len(s.emitter.events, 1)
	s.Equal("550e8400-e29b-41d4-a716-446655440001", s.emitter.events[0].Subject)
}

func (s *LoggerSuite) TestLogExtractsEmail() {
	ctx := context.Background()

	s.logger.Log(ctx, "user_created", "user_id", "test-id", "email", "test@example.com")

	s.Require().Len(s.emitter.events, 1)
	s.Equal("test@example.com", s.emitter.events[0].Email)
}

func (s *LoggerSuite) TestLogHandlesEmitError() {
	s.emitter.shouldErr = true
	ctx := context.Background()

	// Should not panic, error is logged but not propagated
	s.NotPanics(func() {
		s.logger.Log(ctx, "user_created", "user_id", "test-id")
	})

	// No events stored because emit failed
	s.Empty(s.emitter.events)
}

func (s *LoggerSuite) TestLogSkipsNilEmitter() {
	textLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	loggerWithoutEmitter := NewLogger(textLogger, nil)

	// Should not panic when emitter is nil
	s.NotPanics(func() {
		loggerWithoutEmitter.Log(context.Background(), "user_created", "user_id", "test-id")
	})
}

func (s *LoggerSuite) TestLogSkipsNilTextLogger() {
	emitter := &mockEmitter{}
	loggerWithoutText := NewLogger(nil, emitter)

	// Should not panic when text logger is nil
	s.NotPanics(func() {
		loggerWithoutText.Log(context.Background(), "user_created", "user_id", "test-id")
	})

	// But emit should still work
	s.Len(emitter.events, 1)
}

func (s *LoggerSuite) TestLogHandlesInvalidUserID() {
	ctx := context.Background()

	// Invalid UUID should not panic, just result in nil UserID
	s.NotPanics(func() {
		s.logger.Log(ctx, "user_created", "user_id", "not-a-valid-uuid")
	})

	s.Require().Len(s.emitter.events, 1)
	s.True(s.emitter.events[0].UserID.IsNil())
	s.Equal("not-a-valid-uuid", s.emitter.events[0].Subject) // Subject still set
}

func (s *LoggerSuite) TestLogWithoutRequestID() {
	ctx := context.Background() // No request ID in context

	s.logger.Log(ctx, "user_created", "user_id", "test-id")

	s.Require().Len(s.emitter.events, 1)
	s.Empty(s.emitter.events[0].RequestID)
}
