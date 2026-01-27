package middleware

import (
	"fmt"
	"net/http"
	"os"
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

	// Security
	PublicKeySignature  string
	PrivateKeySignature string
	TrustedProxies      []string
	AllowedOrigins      []string
	SecurityHeaders     map[string]string

	// Required Headers
	RequiredCommonHeaders            []string
	RequiredAuthHeaders              []string
	RequiredPublicAuthHeaders        []string
	RequiredSignatureAuthHeaders     []string
	RequiredSignatureMessageHeaders  []string
	RequiredSignaturePublicHeaders   []string

	// Custom Context Injector
	ContextInjector func(r *http.Request) *http.Request
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()

	return Config{
		Logger:           &logger,
		LogStore:         &ConsoleStore{logger: &logger},
		Env:              "development",
		RequestTimeout:   60 * time.Second,
		RequestBodyLimit: 3 * 1024 * 1024, // 3MB
		SecurityHeaders:  defaultSecurityHeaders(),
		TrustedProxies:   []string{},
		AllowedOrigins:   []string{"*"},
	}
}

func defaultSecurityHeaders() map[string]string {
	return map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}
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
