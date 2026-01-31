package middleware

import (
	"fmt"
	"os"
	"time"

	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/rs/zerolog"
)

// Manager holds the middleware configuration and provides middleware methods.
type Manager struct {
	cfg Config
}

// New creates a new Middleware Manager with the given configuration.
// It initializes required fields and sets default values if they are missing.
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
	if cfg.RequestBodyLimit == 0 {
		cfg.RequestBodyLimit = constants.RequestBodyLimit
	}
	// Set default RequestBodyNonFileLimit if not set (3 MB)
	if cfg.RequestBodyNonFileLimit == 0 {
		cfg.RequestBodyNonFileLimit = constants.RequestBodyNonFileLimit
	}

	// Set default ResponseBodyLogLimit (5 MB) if not set
	if cfg.ResponseBodyLogLimit == 0 {
		cfg.ResponseBodyLogLimit = constants.ResponseBodyLogLimit
	}

	// Set default env if not set
	if cfg.Env == "" {
		cfg.Env = "development"
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		panic(fmt.Sprintf("middleware configuration error: %v", err))
	}

	// Set default RequiredCommonHeaders if not set
	if len(cfg.RequiredCommonHeaders) == 0 {
		cfg.RequiredCommonHeaders = constants.RequiredCommonHeaders
	}

	// Set default RequiredAuthHeaders if not set
	if len(cfg.RequiredAuthHeaders) == 0 {
		cfg.RequiredAuthHeaders = constants.RequiredAuthHeaders
	}

	// Set default RequiredPublicHeaders if not set
	if len(cfg.RequiredPublicHeaders) == 0 {
		cfg.RequiredPublicHeaders = constants.RequiredPublicHeaders
	}

	// Set default RequiredSignatureHeadersAuth if not set
	if len(cfg.RequiredSignatureHeadersAuth) == 0 {
		cfg.RequiredSignatureHeadersAuth = constants.RequiredSignatureHeadersAuth
	}

	// Set default RequiredSignatureHeadersPublic if not set
	if len(cfg.RequiredSignatureHeadersPublic) == 0 {
		cfg.RequiredSignatureHeadersPublic = constants.RequiredSignatureHeadersPublic
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
		cfg.AllowedHeaders = append(cfg.AllowedHeaders, cfg.RequiredCommonHeaders...)
		cfg.AllowedHeaders = append(cfg.AllowedHeaders, cfg.RequiredAuthHeaders...)
		cfg.AllowedHeaders = append(cfg.AllowedHeaders, cfg.RequiredPublicHeaders...)
	}


	// Set default HeadersToRemove if not set
	if len(cfg.HeadersToRemove) == 0 {
		cfg.HeadersToRemove = []string{}
	}

	return &Manager{cfg: cfg}
}

// Config returns a copy of the manager's configuration
func (m *Manager) Config() Config {
	return m.cfg
}

func (m *Manager) envProd() bool {
	return m.cfg.Env == "prod" || m.cfg.Env == "production"
}
