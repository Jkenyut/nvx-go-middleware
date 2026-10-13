package middleware

import (
	"context"
	"errors"

	"github.com/Jkenyut/nvx-go-middleware/model"
)

// LogStore defines the interface for persisting audit log entries.
// Implement this to store logs in a database, message queue, or any backend.
type LogStore interface {
	// Save persists an audit log entry. ctx carries request-scoped values.
	Save(ctx context.Context, entry *model.AuditLog) error
}

// ConsoleStore is the default LogStore implementation that writes structured
// log entries to stdout via the configured Logger.
type ConsoleStore struct {
	logger Logger
}

// NewConsoleStore creates a new ConsoleStore with the specified logger.
func NewConsoleStore(logger Logger) *ConsoleStore {
	return &ConsoleStore{logger: logger}
}

// Save writes the audit log entry to the configured logger.
func (c *ConsoleStore) Save(_ context.Context, entry *model.AuditLog) error {
	if c == nil || c.logger == nil || entry == nil {
		return nil
	}
	c.logger.Info().
		Str("service_name", entry.ServiceName).
		Str("method", entry.Method).
		Str("full_url", entry.FullURL).
		Interface("status", entry.StatusCode).
		Interface("latency_ms", entry.LatencyMS).
		Str("client_ip", entry.IP).
		Str("ip_origin", entry.IPOrigin).
		Str("correlation_id", entry.CorrelationID).
		Interface("created_by", entry.CreatedBy).
		Interface("created_at", entry.CreatedAt).
		Interface("request_headers", entry.RequestHeaders).
		Interface("response_headers", entry.ResponseHeaders).
		Interface("request_body", entry.RequestBody).
		Interface("response_body", entry.ResponseBody).
		Str("protocol", entry.Protocol).
		Str("user_agent", entry.UserAgent).
		Str("error_message", entry.ErrorMessage).
		Str("request_id", entry.RequestID).
		Msg("Audit Log")
	return nil
}

// multiLogStore wraps multiple LogStore implementations into one.
type multiLogStore struct {
	stores []LogStore
}

// MultiLogStore combines multiple LogStore instances into a single LogStore.
// It filters out any nil stores, flattens nested MultiLogStore instances,
// and returns the store directly if only one valid store is provided.
func MultiLogStore(stores ...LogStore) LogStore {
	valid := make([]LogStore, 0, len(stores))
	for _, s := range stores {
		if s == nil {
			continue
		}
		if multi, ok := s.(*multiLogStore); ok {
			valid = append(valid, multi.stores...)
		} else {
			valid = append(valid, s)
		}
	}
	if len(valid) == 0 {
		return &multiLogStore{}
	}
	if len(valid) == 1 {
		return valid[0]
	}
	return &multiLogStore{stores: valid}
}

// Save broadcasts the audit log entry to all configured stores sequentially.
func (m *multiLogStore) Save(ctx context.Context, entry *model.AuditLog) error {
	if m == nil || len(m.stores) == 0 || entry == nil {
		return nil
	}
	var errs []error
	for _, s := range m.stores {
		if err := s.Save(ctx, entry); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
