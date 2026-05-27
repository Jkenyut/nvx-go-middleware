package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Jkenyut/nvx-go-helper/activity"
	"github.com/rs/zerolog"
)

// Config holds the configuration for the middleware manager.
// It includes core settings, logging configuration, security parameters, and header requirements.
type Config struct {
	// Core settings

	// LogStore is the storage implementation for audit logs.
	LogStore LogStore
	// Logger is used for internal middleware logging. Defaults to a zerolog console logger.
	// Use NewZerologLogger() to wrap a *zerolog.Logger, or implement the Logger interface directly.
	Logger Logger
	// Env specifies the environment ("development", "production", "prod").
	// Error details are suppressed in production.
	Env string

	// Timeout & Limits

	// RequestTimeout is the default duration to wait for a request to complete.
	RequestTimeout time.Duration
	// RequestBodyLimitSize is the maximum allowed size for request bodies (including file uploads).
	RequestBodyLimitSize int64
	// RequestBodyNonFileLimitSize is the maximum allowed size for non-file (JSON/form) request bodies.
	RequestBodyNonFileLimitSize int64

	// Logging

	// LogRequestBodies enables capturing the request body in audit logs.
	LogRequestBodies bool
	// LogResponseBodies enables capturing the response body in audit logs.
	LogResponseBodies bool
	// ResponseBodyLogLimitSize caps the response body size (bytes) stored in audit logs.
	ResponseBodyLogLimitSize int64

	// Security

	// PublicKeySignature is the HMAC key used for verifying public request signatures.
	PublicKeySignature string
	// PrivateKeySignature is the HMAC key used for verifying internal request signatures.
	PrivateKeySignature string
	// TrustedProxies is a list of trusted proxy IP addresses or CIDR ranges.
	// The real client IP is extracted from X-Forwarded-For only when the proxy is trusted.
	TrustedProxies []string
	// AllowedOrigins is a list of allowed CORS origins. Use ["*"] to allow all.
	AllowedOrigins []string
	// AllowedContentTypes is a list of allowed Content-Type values (substring match).
	AllowedContentTypes []string
	// AllowedHeaders is a list of allowed CORS request headers.
	AllowedHeaders []string
	// HeadersToRemove is a list of response headers to strip before sending to the client.
	HeadersToRemove []string
	// SecurityHeaders is a map of security-related response headers to add automatically.
	SecurityHeaders map[string]string
	// SignatureTimestampExpired is the allowed clock skew in seconds for signature timestamp validation.
	SignatureTimestampExpired int64

	// Required Headers — override defaults from constants package if needed.

	// RequiredPublicAuthHeaders are headers required for authenticated public requests.
	RequiredPublicAuthHeaders []string
	// RequiredPublicHeaders are headers required for unauthenticated public requests.
	RequiredPublicHeaders []string
	// RequiredInternalHeaders are headers required for internal service-to-service requests.
	RequiredInternalHeaders []string
	// RequiredPublicAPIKeyHeaders are headers required for API-key authenticated requests.
	RequiredPublicAPIKeyHeaders []string
	// RequiredSignaturePublicHeaders are the headers whose values are included in the public signature.
	RequiredSignaturePublicHeaders []string
	// RequiredSignatureInternalHeaders are the headers whose values are included in the internal signature.
	RequiredSignatureInternalHeaders []string

	// Extensions

	// ContextInjector is an optional function to inject additional values into the request context.
	ContextInjector func(r *http.Request) *http.Request
	// ServiceName is the name of the service, used in log fields.
	ServiceName string
}

// Validate checks that required Config fields are present.
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
	// ErrMissingKeys is returned when PublicKeySignature or PrivateKeySignature are empty.
	ErrMissingKeys = fmt.Errorf("PublicKeySignature and PrivateKeySignature are required")
	// ErrMissingOrigins is returned when AllowedOrigins is empty.
	ErrMissingOrigins = fmt.Errorf("AllowedOrigins must not be empty")
)

// newLegacyZerologConfig is a helper to accept a raw *zerolog.Logger for backward compat.
// Used only by tests that set cfg.Logger directly as *zerolog.Logger before the interface change.
func newLegacyZerologConfig(l *zerolog.Logger) Logger {
	return NewZerologLogger(l)
}

// WithActivityContext injects standard NVX context values from request headers.
// Exported so protocol-specific adapters (WebSocket, gRPC) can reuse it.
func WithActivityContext(r *http.Request) *http.Request {
	h := r.Header
	ctx := r.Context()
	ctx = activity.WithTransactionID(ctx, h.Get("NVX-Transaction-ID"))
	ctx = activity.WithAPIKey(ctx, h.Get("NVX-API-Key"))
	ctx = activity.WithUserID(ctx, h.Get("NVX-User-ID"))
	ctx = activity.WithUserIP(ctx, h.Get("NVX-IP"))
	ctx = activity.WithUserType(ctx, h.Get("NVX-User-Type"))
	ctx = activity.WithRequestID(ctx, h.Get("NVX-Request-ID"))
	return r.WithContext(ctx)
}
