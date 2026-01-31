package middleware

import (
	"github.com/Jkenyut/nvx-go-middleware/model"
	"github.com/rs/zerolog"
)

// LogStore defines the interface for storing log entries.
type LogStore interface {
	Save(entry model.AuditLog) error
}

// ConsoleStore is a default implementation of LogStore that writes to the console.
type ConsoleStore struct {
	logger *zerolog.Logger
}

// Save writes the audit log entry to the configured logger or stdout.
func (c *ConsoleStore) Save(entry model.AuditLog) error {
	// Log structured data using zerolog
	c.logger.Info().
		Str("method", entry.Method).
		Str("url", entry.FullURL).
		Int("status", entry.StatusCode).
		Int("latency_ms", entry.LatencyMS).
		Str("client_ip", entry.ClientIP).
		Str("transaction_id", entry.TransactionID).
		Str("api_key", entry.APIKey).
		Int64("created_by", entry.CreatedBy).
		Time("created_at", entry.CreatedAt).
		Interface("request_headers", entry.RequestHeaders).
		Interface("response_headers", entry.ResponseHeaders).
		Interface("request_body", entry.RequestBody).
		Interface("response_body", entry.ResponseBody).
		Msg("HTTP Request")

	return nil
}
