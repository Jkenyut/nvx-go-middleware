package middleware

import (
	"fmt"
	"os"
	"time"

	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/go-chi/httprate"
	"github.com/rs/zerolog"
)

// Manager holds the middleware configuration and provides middleware methods.
// It is the central entry point for creating and managing middleware chains.
type Manager struct {
	cfg     Config
	counter httprate.LimitCounter
}

// New creates a new Middleware Manager with the given configuration.
// It initializes required fields, sets default values for missing configuration using safe defaults,
// and validates the configuration. Panics if validation fails.
func New(cfg Config) *Manager {
	// Set default logger if not set
	if cfg.Logger == nil {
		l := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()
		cfg.Logger = &l
	}

	// Set default LogStore if nil
	if cfg.LogStore == nil {
		cfg.LogStore = &ConsoleStore{
			logger: cfg.Logger,
		}
	}

	// Set default RequestTimeout if not set
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 60 * time.Second
	}
	// Set default RequestBodyLimit if not set (2GB)
	if cfg.RequestBodyLimitSize == 0 {
		cfg.RequestBodyLimitSize = constants.RequestBodyLimitSize
	}
	// Set default RequestBodyNonFileLimit if not set (3 MB)
	if cfg.RequestBodyNonFileLimitSize == 0 {
		cfg.RequestBodyNonFileLimitSize = constants.RequestBodyNonFileLimitSize
	}

	// Set default ResponseBodyLogLimit (5 MB) if not set
	if cfg.ResponseBodyLogLimitSize == 0 {
		cfg.ResponseBodyLogLimitSize = constants.ResponseBodyLogLimitSize
	}

	if cfg.ServiceName == "" {
		cfg.ServiceName = "unknown-service"
	}

	// Set default env if not set
	if cfg.Env == "" {
		cfg.Env = "development"
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		panic(fmt.Sprintf("middleware configuration error: %v", err))
	}

	// Set default RequiredPublicAuthHeaders if not set
	if len(cfg.RequiredPublicAuthHeaders) == 0 {
		cfg.RequiredPublicAuthHeaders = constants.RequiredPublicAuthHeaders
	}

	// Set default RequiredPublicHeaders if not set
	if len(cfg.RequiredPublicHeaders) == 0 {
		cfg.RequiredPublicHeaders = constants.RequiredPublicHeaders
	}

	// Set default RequiredInternalHeaders if not set
	if len(cfg.RequiredInternalHeaders) == 0 {
		cfg.RequiredInternalHeaders = constants.RequiredInternalHeaders
	}

	// Set default RequiredSignatureHeadersPublicAuth if not set
	if len(cfg.RequiredSignatureHeadersPublicAuth) == 0 {
		cfg.RequiredSignatureHeadersPublicAuth = constants.RequiredSignatureHeadersPublicAuth
	}

	// Set default RequiredSignatureHeadersPublic if not set
	if len(cfg.RequiredSignatureHeadersPublic) == 0 {
		cfg.RequiredSignatureHeadersPublic = constants.RequiredSignatureHeadersPublic
	}

	// Set default RequiredSignatureHeadersInternal if not set
	if len(cfg.RequiredSignatureHeadersInternal) == 0 {
		cfg.RequiredSignatureHeadersInternal = constants.RequiredSignatureHeadersInternal
	}

	// Set default SecurityHeaders if not set
	if cfg.SecurityHeaders == nil {
		cfg.SecurityHeaders = constants.SecurityHeaders
	}

	// Set default TrustedProxies if not set
	if len(cfg.TrustedProxies) == 0 {
		cfg.TrustedProxies = []string{}
	}

	// Set default AllowedOrigins if not set
	if len(cfg.AllowedOrigins) == 0 {
		cfg.AllowedOrigins = []string{"*"}
	}

	// Set default AllowedContentTypes if not set
	if len(cfg.AllowedContentTypes) == 0 {
		cfg.AllowedContentTypes = []string{"application/json", "multipart/form-data"}
	}

	// Set default AllowedHeaders if not set
	if len(cfg.AllowedHeaders) == 0 {
		cfg.AllowedHeaders = append(cfg.AllowedHeaders, "Accept", "Authorization", "Content-Type")
		cfg.AllowedHeaders = append(cfg.AllowedHeaders, cfg.RequiredPublicAuthHeaders...)
		cfg.AllowedHeaders = append(cfg.AllowedHeaders, cfg.RequiredPublicHeaders...)
		cfg.AllowedHeaders = append(cfg.AllowedHeaders, cfg.RequiredInternalHeaders...)
	}

	// Set default HeadersToRemove if not set
	if len(cfg.HeadersToRemove) == 0 {
		cfg.HeadersToRemove = []string{}
	}

	// Set default SignatureTimestampExpired if not set
	if cfg.SignatureTimestampExpired == 0 {
		cfg.SignatureTimestampExpired = constants.TimestampExpired
	}

	return &Manager{cfg: cfg}
}

// Config returns a copy of the manager's configuration.
// This is useful for inspecting the current configuration state.
func (m *Manager) Config() Config {
	return m.cfg
}

func (m *Manager) envProd() bool {
	return m.cfg.Env == "prod" || m.cfg.Env == "production"
}
