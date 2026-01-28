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
	// Set default RequestBodyLimit if not set (3MB)
	if cfg.RequestBodyLimit == 0 {
		cfg.RequestBodyLimit = 3 * 1024 * 1024 // 3 MB
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

	// Set default RequiredPublicAuthHeaders if not set
	if len(cfg.RequiredPublicAuthHeaders) == 0 {
		cfg.RequiredPublicAuthHeaders = constants.RequiredPublicAuthHeaders
	}

	// Set default RequiredSignatureAuthHeaders if not set
	if len(cfg.RequiredSignatureAuthHeaders) == 0 {
		cfg.RequiredSignatureAuthHeaders = constants.RequiredSignatureAuthHeaders
	}

	// Set default RequiredSignaturePublicHeaders if not set
	if len(cfg.RequiredSignaturePublicHeaders) == 0 {
		cfg.RequiredSignaturePublicHeaders = constants.RequiredSignaturePublicHeaders
	}

	// Set default RequiredSignatureMessageHeaders if not set
	if len(cfg.RequiredSignatureMessageHeaders) == 0 {
		cfg.RequiredSignatureMessageHeaders = constants.RequiredSignatureMessagePublicHeaders
	}

	// Set default SecurityHeaders if not set
	if cfg.SecurityHeaders == nil {
		cfg.SecurityHeaders = constants.SecurityHeaders
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
