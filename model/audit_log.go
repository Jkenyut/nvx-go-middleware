package model

import "time"

// AuditLog represents a log entry for HTTP requests
type AuditLog struct {
	ID              int64     `json:"id"`
	Method          string    `json:"method"`
	FullURL         string    `json:"full_url"`
	StatusCode      int       `json:"status_code"`
	LatencyMS       int       `json:"latency_ms"`
	MerchantKey     string    `json:"merchant_key"`
	ClientIP        string    `json:"client_ip"`
	RequestID       string    `json:"request_id"`
	TransactionID   string    `json:"transaction_id"`
	RequestHeaders  string    `json:"request_headers"`
	ResponseHeaders string    `json:"response_headers"`
	RequestBody     string    `json:"request_body"`
	ResponseBody    string    `json:"response_body"`
	CreatedBy       int64     `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
}
