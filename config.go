package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

// Config holds the configuration for the middleware manager.
// It includes core settings, logging configuration, security parameters, and header requirements.
type Config struct {
	// Core settings
	// LogStore is the storage implementation for audit logs.
	LogStore LogStore
	// Logger is the zerolog instance used for application logging.
	Logger *zerolog.Logger
	// Env specifies the environment (e.g., "development", "production").
	Env string

	// Timeout & Limits
	// RequestTimeout is the default duration to wait for a request to complete.
	RequestTimeout time.Duration
	// RequestBodyLimitSize is the maximum allowed size for request bodies.
	RequestBodyLimitSize int64
	// RequestBodyNonFileLimitSize is the maximum allowed size for non-file request bodies.
	RequestBodyNonFileLimitSize int64

	// Logging
	// LogRequestBodies indicates whether to log the request body.
	LogRequestBodies bool
	// LogResponseBodies indicates whether to log the response body.
	LogResponseBodies bool
	// ResponseBodyLogLimitSize is the maximum size of response bodies to log.
	ResponseBodyLogLimitSize int64

	// Security
	// PublicKeySignature is the public key used for verifying signatures.
	PublicKeySignature string
	// PrivateKeySignature is the private key used for generating signatures.
	PrivateKeySignature string
	// TrustedProxies is a list of trusted proxy IP addresses or CIDR ranges.
	TrustedProxies []string
	// AllowedOrigins is a list of allowed origins for CORS.
	AllowedOrigins []string
	// AllowedContentTypes is a list of allowed Content-Type headers.
	AllowedContentTypes []string
	// AllowedHeaders is a list of allowed headers for CORS.
	AllowedHeaders []string
	// HeadersToRemove is a list of headers to remove from the response.
	HeadersToRemove []string
	// SecurityHeaders is a map of security headers to add to the response.
	SecurityHeaders map[string]string
	// SignatureTimestampExpired is the duration after which a signature is considered expired.
	SignatureTimestampExpired int64

	// Required Headers
	// RequiredPublicAuthHeaders is a list of headers required for generic authenticated requests.
	RequiredPublicAuthHeaders []string
	// RequiredPublicHeaders is a list of headers required for public requests.
	RequiredPublicHeaders []string
	// RequiredInternalHeaders is a list of headers required for internal service requests.
	RequiredInternalHeaders []string
	// RequiredPublicAPIkeyHeaders is a list of headers required for public requests with API key.
	RequiredPublicAPIKeyHeaders []string
	// RequiredSignaturePublicHeaders is the list of headers included in the signature for public requests.
	RequiredSignaturePublicHeaders []string
	// RequiredSignatureInternalHeaders is the list of headers included in the signature for internal requests.
	RequiredSignatureInternalHeaders []string

	// Custom Context Injector
	// ContextInjector is a custom function to modify the request context before processing.
	ContextInjector func(r *http.Request) *http.Request
	// ServiceName is the name of the service using this middleware.
	ServiceName string
}

// Validate checks if the config object has all necessary required fields.
// It returns an error if any required configuration is missing.
func (c *Config) Validate() error {
	if c.PublicKeySignature == "" || c.PrivateKeySignature == "" {
		return ErrMissingKeys
	}
	if len(c.AllowedOrigins) == 0 {
		return ErrMissingOrigins
	}
	return nil
}

var (
	// ErrMissingKeys is returned when PublicKeySignature or PrivateKeySignature are missing.
	ErrMissingKeys = fmt.Errorf("PublicKey and PrivateKey are required")
	// ErrMissingOrigins is returned when AllowedOrigins is missing.
	ErrMissingOrigins = fmt.Errorf("AllowedOrigins is required")
)
