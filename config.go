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
	RequestTimeout   time.Duration
	RequestBodyLimit int64

	// Logging
	LogRequestBodies  bool
	LogResponseBodies bool

	// Security
	PublicKeySignature  string
	PrivateKeySignature string
	TrustedProxies      []string
	AllowedOrigins      []string
	AllowedHeaders      []string
	HeadersToRemove     []string
	SecurityHeaders     map[string]string

	// Required Headers
	RequiredCommonHeaders           []string
	RequiredAuthHeaders             []string
	RequiredPublicAuthHeaders       []string
	RequiredSignatureAuthHeaders    []string
	RequiredSignatureMessageHeaders []string
	RequiredSignaturePublicHeaders  []string

	// Custom Context Injector
	ContextInjector func(r *http.Request) *http.Request
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
