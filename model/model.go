package model

import (
	"time"
)

// AuditLog represents the structure of an audit log entry.
type AuditLog struct {
	// ID is the unique identifier for the log entry.
	ID int64 `json:"al_id"`
	// TransactionID is a unique ID for the entire transaction flow.
	TransactionID string `json:"al_transaction_id"`
	// RequestID is a unique ID for the specific HTTP request.
	RequestID string `json:"al_request_id"`
	// MerchantKey identifies the merchant making the request.
	MerchantKey string `json:"al_merchant_key"`
	// ClientIP is the IP address of the client making the request.
	ClientIP string `json:"al_client_ip"`
	// Method is the HTTP method used (GET, POST, etc.).
	Method string `json:"al_method"`
	// FullURL is the complete URL requested.
	FullURL string `json:"al_full_url"`
	// RequestHeaders contains the JSON-encoded request headers.
	RequestHeaders string `json:"al_request_headers"`
	// ResponseHeaders contains the JSON-encoded response headers.
	ResponseHeaders string `json:"al_response_headers"`
	// RequestBody contains the request body content.
	RequestBody string `json:"al_request_body"`
	// ResponseBody contains the response body content.
	ResponseBody string `json:"al_response_body"`
	// StatusCode is the HTTP status code returned.
	StatusCode int `json:"al_status_code"`
	// LatencyMS is the time taken to process the request in milliseconds.
	LatencyMS int `json:"al_latency_ms"`
	// CreatedBy is the ID of the user who initiated the request.
	CreatedBy int64 `json:"al_created_by"`
	// CreatedAt is the timestamp when the log entry was created.
	CreatedAt time.Time `json:"al_created_at"`
}
