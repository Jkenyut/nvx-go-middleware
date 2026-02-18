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

	// Set default RequiredPublicAPIKeyHeaders if not set
	if len(cfg.RequiredPublicAPIKeyHeaders) == 0 {
		cfg.RequiredPublicAPIKeyHeaders = constants.RequiredPublicAPIKeyHeaders
	}

	// Set default RequiredSignaturePublicHeaders if not set
	if len(cfg.RequiredSignaturePublicHeaders) == 0 {
		cfg.RequiredSignaturePublicHeaders = constants.RequiredSignaturePublicHeaders
	}

	// Set default RequiredSignatureInternalHeaders if not set
	if len(cfg.RequiredSignatureInternalHeaders) == 0 {
		cfg.RequiredSignatureInternalHeaders = constants.RequiredSignatureInternalHeaders
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
		cfg.AllowedHeaders = uniqueStrings(
			[]string{"Accept", "Authorization", "Content-Type"},
			cfg.RequiredPublicAuthHeaders,
			cfg.RequiredPublicHeaders,
			cfg.RequiredInternalHeaders,
			cfg.RequiredPublicAPIKeyHeaders,
		)
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

func uniqueStrings(items ...[]string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)

	for _, list := range items {
		for _, v := range list {
			if _, ok := seen[v]; !ok {
				seen[v] = struct{}{}
				out = append(out, v)
			}
		}
	}

	return out
}
