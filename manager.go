package middleware

import (
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/diode"
)

// Manager holds the middleware configuration and provides middleware methods.
// It is the central entry point for creating and managing middleware chains.
type Manager struct {
	cfg       Config
	logCloser io.Closer
}

// NewWithError creates a new Middleware Manager, returning an error instead of panicking
// if the configuration is invalid. Prefer this over New for production use.
func NewWithError(cfg *Config) (*Manager, error) {
	// Validate required fields BEFORE applying defaults that might mask missing values.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	closer := applyDefaults(cfg)
	return &Manager{cfg: *cfg, logCloser: closer}, nil
}

// applyDefaults fills in all missing Config fields with safe defaults.
// It returns an io.Closer if it created any resources that need to be closed.
func applyDefaults(cfg *Config) io.Closer {
	var logCloser io.Closer

	if cfg.Logger == nil {
		env := cfg.Core.Env // defaults to "development" if empty

		var writer io.Writer
		isProd := env == "production" || env == "prod"

		if isProd {
			// JSON output for log aggregation systems
			writer = os.Stdout
		} else {
			// Pretty, colored output for local development and staging
			writer = zerolog.ConsoleWriter{
				Out:     os.Stderr,
				NoColor: false,
			}
		}

		// Use RFC3339 seconds internally, but display in human format via ConsoleWriter
		zerolog.TimeFieldFormat = time.RFC3339

		// Respect LOG_LEVEL environment variable if set
		if levelStr := os.Getenv("LOG_LEVEL"); levelStr != "" {
			if level, err := zerolog.ParseLevel(levelStr); err == nil {
				zerolog.SetGlobalLevel(level)
			}
		} else {
			// Default level based on environment
			if isProd {
				zerolog.SetGlobalLevel(zerolog.InfoLevel)
			} else {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}
		}

		wr := diode.NewWriter(writer, 1000, 10*time.Millisecond, func(_ int) {})
		logCloser = wr
		logContext := zerolog.New(wr).
			With().
			Timestamp().
			Str("service", cfg.Core.ServiceName)

		// Caller is expensive. Only enable it in non-production environments.
		if !isProd {
			logContext = logContext.Caller()
		}

		log := logContext.Logger()
		zerolog.DefaultContextLogger = &log
		cfg.Logger = NewZerologLogger(&log)
	}

	if cfg.LogStore == nil {
		cfg.LogStore = &ConsoleStore{logger: cfg.Logger}
	}

	if cfg.Limits.RequestTimeout == 0 {
		cfg.Limits.RequestTimeout = 60
	}
	if cfg.Limits.RequestBodyLimitSize == 0 {
		cfg.Limits.RequestBodyLimitSize = constants.RequestBodyLimitSize
	}
	if cfg.Limits.RequestBodyNonFileLimitSize == 0 {
		cfg.Limits.RequestBodyNonFileLimitSize = constants.RequestBodyNonFileLimitSize
	}
	if cfg.Logging.ResponseBodyLogLimitSize == 0 {
		cfg.Logging.ResponseBodyLogLimitSize = constants.ResponseBodyLogLimitSize
	}
	if cfg.Core.ServiceName == "" {
		cfg.Core.ServiceName = "unknown-service"
	}
	if cfg.Core.Env == "" {
		cfg.Core.Env = "development"
	}

	if len(cfg.Headers.RequiredPublicAuthHeaders) == 0 {
		cfg.Headers.RequiredPublicAuthHeaders = constants.RequiredPublicAuthHeaders
	}
	if len(cfg.Headers.RequiredPublicHeaders) == 0 {
		cfg.Headers.RequiredPublicHeaders = constants.RequiredPublicHeaders
	}
	if len(cfg.Headers.RequiredInternalHeaders) == 0 {
		cfg.Headers.RequiredInternalHeaders = constants.RequiredInternalHeaders
	}
	if len(cfg.Headers.RequiredPublicAPIKeyHeaders) == 0 {
		cfg.Headers.RequiredPublicAPIKeyHeaders = constants.RequiredPublicAPIKeyHeaders
	}
	if len(cfg.Headers.RequiredSignaturePublicHeaders) == 0 {
		cfg.Headers.RequiredSignaturePublicHeaders = constants.RequiredSignaturePublicHeaders
	}
	if len(cfg.Headers.RequiredSignatureInternalHeaders) == 0 {
		cfg.Headers.RequiredSignatureInternalHeaders = constants.RequiredSignatureInternalHeaders
	}
	if cfg.Security.SecurityHeaders == nil {
		cfg.Security.SecurityHeaders = constants.SecurityHeaders
	}
	if len(cfg.Security.TrustedProxies) == 0 {
		cfg.Security.TrustedProxies = []string{}
	}
	if len(cfg.Security.AllowedOrigins) == 0 {
		cfg.Security.AllowedOrigins = []string{"*"}
	}
	if len(cfg.Security.AllowedContentTypes) == 0 {
		cfg.Security.AllowedContentTypes = []string{"application/json", "multipart/form-data"}
	}
	if len(cfg.Security.AllowedHeaders) == 0 {
		cfg.Security.AllowedHeaders = uniqueStrings(
			[]string{"Accept", "Authorization", "Content-Type"},
			cfg.Headers.RequiredPublicAuthHeaders,
			cfg.Headers.RequiredPublicHeaders,
			cfg.Headers.RequiredInternalHeaders,
			cfg.Headers.RequiredPublicAPIKeyHeaders,
		)
	}
	if len(cfg.Security.HeadersToRemove) == 0 {
		cfg.Security.HeadersToRemove = []string{}
	}
	if cfg.Security.SignatureTimestampExpired == 0 {
		cfg.Security.SignatureTimestampExpired = constants.TimestampExpired
	}

	return logCloser
}

// Config returns a copy of the manager's configuration.
func (m *Manager) Config() Config {
	return m.cfg
}

// Close cleans up any resources created by the Manager (e.g. background logger).
// Call this during graceful shutdown to prevent log loss.
func (m *Manager) Close() error {
	if m.logCloser != nil {
		return m.logCloser.Close()
	}
	return nil
}

func (m *Manager) envProd() bool {
	return m.cfg.Core.Env == "prod" || m.cfg.Core.Env == "production"
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

// SetHeaderAuthType sets the NVX-Auth-Type header to identify the authentication context.
func (m *Manager) SetHeaderAuthType(next http.Handler, authType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(constants.HeaderAuthType, authType)
		next.ServeHTTP(w, r)
	})
}
