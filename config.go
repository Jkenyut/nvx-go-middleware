package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

// Config holds the configuration for the middleware manager.
type Config struct {
	// Core settings
	LogStore LogStore
	Logger   *zerolog.Logger
	Env      string

	// Timeout & Limits
	RequestTimeout              time.Duration
	RequestBodyLimitSize        int64
	RequestBodyNonFileLimitSize int64

	// Logging
	LogRequestBodies         bool
	LogResponseBodies        bool
	ResponseBodyLogLimitSize int64

	// Security
	PublicKeySignature        string
	PrivateKeySignature       string
	TrustedProxies            []string
	AllowedOrigins            []string
	AllowedContentTypes       []string
	AllowedHeaders            []string
	HeadersToRemove           []string
	SecurityHeaders           map[string]string
	SignatureTimestampExpired int64

	// Required Headers
	RequiredCommonHeaders              []string
	RequiredPublicAuthHeaders          []string
	RequiredPublicHeaders              []string
	RequiredSignatureHeadersPublicAuth []string
	RequiredSignatureHeadersPublic     []string

	// Custom Context Injector
	ContextInjector func(r *http.Request) *http.Request
	ServiceName     string
}

// Validate checks if the config is valid
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
	ErrMissingKeys    = fmt.Errorf("PublicKey and PrivateKey are required")
	ErrMissingOrigins = fmt.Errorf("AllowedOrigins is required")
)
