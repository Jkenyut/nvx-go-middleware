package middleware

import (
	"context"

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

// Save writes the audit log entry to the configured logger.
func (c *ConsoleStore) Save(_ context.Context, entry *model.AuditLog) error {
	c.logger.Info().
		Str("method", entry.Method).
		Str("url", entry.FullURL).
		Interface("status", entry.StatusCode).
		Interface("latency_ms", entry.LatencyMS).
		Str("client_ip", entry.ClientIP).
		Str("transaction_id", entry.TransactionID).
		Interface("created_by", entry.CreatedBy).
		Interface("created_at", entry.CreatedAt).
		Interface("request_headers", entry.RequestHeaders).
		Interface("response_headers", entry.ResponseHeaders).
		Interface("request_body", entry.RequestBody).
		Interface("response_body", entry.ResponseBody).
		Msg(entry.Protocol)
	return nil
}
