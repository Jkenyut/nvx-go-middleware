package middleware

import (
	"github.com/rs/zerolog"
)

// Logger is the logging interface used by the middleware manager.
// Implement this to use a custom logging backend (e.g., slog, logrus, zap).
type Logger interface {
	// Error returns an event builder for error-level logging.
	Error() LogEvent
	// Info returns an event builder for info-level logging.
	Info() LogEvent
}

// LogEvent is a builder for a single log entry.
// It follows a fluent API pattern.
type LogEvent interface {
	Str(key, val string) LogEvent
	Err(err error) LogEvent
	Interface(key string, val any) LogEvent
	Msgf(format string, args ...any)
	Msg(msg string)
}

// zerologAdapter wraps *zerolog.Logger to implement the Logger interface.
type zerologAdapter struct {
	l *zerolog.Logger
}

// zerologEventAdapter wraps *zerolog.Event to implement the LogEvent interface.
type zerologEventAdapter struct {
	e *zerolog.Event
}

func (a *zerologEventAdapter) Str(key, val string) LogEvent {
	a.e = a.e.Str(key, val)
	return a
}

func (a *zerologEventAdapter) Err(err error) LogEvent {
	a.e = a.e.Err(err)
	return a
}

func (a *zerologEventAdapter) Interface(key string, val any) LogEvent {
	a.e = a.e.Interface(key, val)
	return a
}

func (a *zerologEventAdapter) Msgf(format string, args ...any) {
	a.e.Msgf(format, args...)
}

func (a *zerologEventAdapter) Msg(msg string) {
	a.e.Msg(msg)
}

func (a *zerologAdapter) Error() LogEvent {
	return &zerologEventAdapter{e: a.l.Error()}
}

func (a *zerologAdapter) Info() LogEvent {
	return &zerologEventAdapter{e: a.l.Info()}
}

// NewZerologLogger wraps a *zerolog.Logger into the Logger interface.
func NewZerologLogger(l *zerolog.Logger) Logger {
	return &zerologAdapter{l: l}
}
