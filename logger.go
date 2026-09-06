package middleware

import (
	"log/slog"
)

// Logger is a type alias to *slog.Logger for backwards compatibility.
type Logger = *slog.Logger

// NewSlogLogger returns the provided *slog.Logger.
func NewSlogLogger(l *slog.Logger) *slog.Logger {
	return l
}
