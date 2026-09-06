package middleware

import (
	"context"
	"log/slog"

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
	logger *slog.Logger
}

// Save writes the audit log entry to the configured logger.
func (c *ConsoleStore) Save(ctx context.Context, entry *model.AuditLog) error {
	if c.logger == nil {
		return nil
	}
	c.logger.LogAttrs(ctx, slog.LevelInfo, "Audit Log",
		slog.String("service_name", entry.ServiceName),
		slog.String("method", entry.Method),
		slog.String("full_url", entry.FullURL),
		slog.Int("status", entry.StatusCode),
		slog.Int64("latency_ms", entry.LatencyMS),
		slog.String("client_ip", entry.IP),
		slog.String("ip_origin", entry.IPOrigin),
		slog.String("transaction_id", entry.TransactionID),
		slog.Int64("created_by", entry.CreatedBy),
		slog.Time("created_at", entry.CreatedAt),
		slog.Any("request_headers", entry.RequestHeaders),
		slog.Any("response_headers", entry.ResponseHeaders),
		slog.Any("request_body", entry.RequestBody),
		slog.Any("response_body", entry.ResponseBody),
		slog.String("protocol", entry.Protocol),
		slog.String("user_agent", entry.UserAgent),
		slog.String("error_message", entry.ErrorMessage),
		slog.String("request_id", entry.RequestID),
	)
	return nil
}
