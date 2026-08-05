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
		env := cfg.Env // defaults to "development" if empty

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
			Str("service", cfg.ServiceName)

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

	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 60 * time.Second
	}
	if cfg.RequestBodyLimitSize == 0 {
		cfg.RequestBodyLimitSize = constants.RequestBodyLimitSize
	}
	if cfg.RequestBodyNonFileLimitSize == 0 {
		cfg.RequestBodyNonFileLimitSize = constants.RequestBodyNonFileLimitSize
	}
	if cfg.ResponseBodyLogLimitSize == 0 {
		cfg.ResponseBodyLogLimitSize = constants.ResponseBodyLogLimitSize
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "unknown-service"
	}
	if cfg.Env == "" {
		cfg.Env = "development"
	}

	if len(cfg.RequiredPublicAuthHeaders) == 0 {
		cfg.RequiredPublicAuthHeaders = constants.RequiredPublicAuthHeaders
	}
	if len(cfg.RequiredPublicHeaders) == 0 {
		cfg.RequiredPublicHeaders = constants.RequiredPublicHeaders
	}
	if len(cfg.RequiredInternalHeaders) == 0 {
		cfg.RequiredInternalHeaders = constants.RequiredInternalHeaders
	}
	if len(cfg.RequiredPublicAPIKeyHeaders) == 0 {
		cfg.RequiredPublicAPIKeyHeaders = constants.RequiredPublicAPIKeyHeaders
	}
	if len(cfg.RequiredSignaturePublicHeaders) == 0 {
		cfg.RequiredSignaturePublicHeaders = constants.RequiredSignaturePublicHeaders
	}
	if len(cfg.RequiredSignatureInternalHeaders) == 0 {
		cfg.RequiredSignatureInternalHeaders = constants.RequiredSignatureInternalHeaders
	}
	if cfg.SecurityHeaders == nil {
		cfg.SecurityHeaders = constants.SecurityHeaders
	}
	if len(cfg.TrustedProxies) == 0 {
		cfg.TrustedProxies = []string{}
	}
	if len(cfg.AllowedOrigins) == 0 {
		cfg.AllowedOrigins = []string{"*"}
	}
	if len(cfg.AllowedContentTypes) == 0 {
		cfg.AllowedContentTypes = []string{"application/json", "multipart/form-data"}
	}
	if len(cfg.AllowedHeaders) == 0 {
		cfg.AllowedHeaders = uniqueStrings(
			[]string{"Accept", "Authorization", "Content-Type"},
			cfg.RequiredPublicAuthHeaders,
			cfg.RequiredPublicHeaders,
			cfg.RequiredInternalHeaders,
			cfg.RequiredPublicAPIKeyHeaders,
		)
	}
	if len(cfg.HeadersToRemove) == 0 {
		cfg.HeadersToRemove = []string{}
	}
	if cfg.SignatureTimestampExpired == 0 {
		cfg.SignatureTimestampExpired = constants.TimestampExpired
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

// SetHeaderAuthType sets the NVX-Auth-Type header to identify the authentication context.
func (m *Manager) SetHeaderAuthType(next http.Handler, authType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(constants.HeaderAuthType, authType)
		next.ServeHTTP(w, r)
	})
}
