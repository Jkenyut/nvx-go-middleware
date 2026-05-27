package model

import (
	"encoding/json"
	"time"
)

// AuditLog represents a log entry for an HTTP request.
// It contains detailed information about the request, response, and execution context.
type AuditLog struct {
	// ID is the unique identifier for the log entry.
	ID string `json:"id"`
	// Method is the HTTP method (GET, POST, etc.).
	Method string `json:"method"`
	// Full URL is the complete URL requested.
	FullURL string `json:"full_url"`
	// Status Code is the HTTP response status code.
	StatusCode int `json:"status_code"`
	// Latency MS is the time taken to process the request in milliseconds.
	LatencyMS int `json:"latency_ms"`
	// Client IP is the IP address of the client.
	ClientIP string `json:"client_ip"`
	// Request ID is the unique request identifier.
	RequestID string `json:"request_id"`
	// Transaction ID is the unique transaction identifier used for tracing.
	TransactionID string `json:"transaction_id"`
	// Request Headers captures the headers sent in the request.
	RequestHeaders json.RawMessage `json:"request_headers"`
	// Response Headers captures the headers sent in the response.
	ResponseHeaders json.RawMessage `json:"response_headers"`
	// Request Body captures the body sent in the request (if logging is enabled).
	RequestBody any `json:"request_body"`
	// Response Body captures the body sent in the response (if logging is enabled).
	ResponseBody any `json:"response_body"`
	// Created By is the user ID who initiated the request (if authenticated).
	CreatedBy int64 `json:"created_by"`
	// Created At is the timestamp when the log entry was created.
	CreatedAt time.Time `json:"created_at"`
	Protocol  string    `json:"protocol"`
	// ServiceName identifies the microservice emitting this log.
	ServiceName string `json:"service_name"`
	// UserAgent is the client's user agent string.
	UserAgent string `json:"user_agent"`
	// ErrorMessage captures explicit error messages or panics (if any).
	ErrorMessage string `json:"error_message,omitempty"`
}
