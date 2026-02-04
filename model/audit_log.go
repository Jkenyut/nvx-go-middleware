package model

import (
	"encoding/json"
	"time"
)

// AuditLog represents a log entry for an HTTP request.
// It contains detailed information about the request, response, and execution context.
type AuditLog struct {
	// ID is the unique identifier for the log entry.
	ID int64 `json:"id"`
	// Method is the HTTP method (GET, POST, etc.).
	Method string `json:"method"`
	// FullURL is the complete URL requested.
	FullURL string `json:"full_url"`
	// StatusCode is the HTTP response status code.
	StatusCode int `json:"status_code"`
	// LatencyMS is the time taken to process the request in milliseconds.
	LatencyMS int `json:"latency_ms"`
	// APIKey is the API Key used for the request.
	APIKey string `json:"api_key"`
	// ClientIP is the IP address of the client.
	ClientIP string `json:"client_ip"`
	// RequestID is the unique request identifier.
	RequestID string `json:"request_id"`
	// TransactionID is the unique transaction identifier used for tracing.
	TransactionID string `json:"transaction_id"`
	// RequestHeaders captures the headers sent in the request.
	RequestHeaders json.RawMessage `json:"request_headers"`
	// ResponseHeaders captures the headers sent in the response.
	ResponseHeaders json.RawMessage `json:"response_headers"`
	// RequestBody captures the body sent in the request (if logging is enabled).
	RequestBody any `json:"request_body"`
	// ResponseBody captures the body sent in the response (if logging is enabled).
	ResponseBody any `json:"response_body"`
	// CreatedBy is the user ID who initiated the request (if authenticated).
	CreatedBy int64 `json:"created_by"`
	// CreatedAt is the timestamp when the log entry was created.
	CreatedAt time.Time `json:"created_at"`
}
