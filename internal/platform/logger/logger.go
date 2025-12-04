package logger

import (
	"log/slog"
	"os"
)

// New returns a structured JSON logger using slog.
func New() *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	handler := slog.NewJSONHandler(os.Stdout, opts)
	return slog.New(handler)
}
