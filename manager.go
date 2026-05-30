package middleware

import (
	"net/http"
	"os"
	"time"

	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/rs/zerolog"
)

// Manager holds the middleware configuration and provides middleware methods.
// It is the central entry point for creating and managing middleware chains.
type Manager struct {
	cfg Config
}

// NewWithError creates a new Middleware Manager, returning an error instead of panicking
// if the configuration is invalid. Prefer this over New for production use.
func NewWithError(cfg Config) (*Manager, error) {
	// Validate required fields BEFORE applying defaults that might mask missing values.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = applyDefaults(cfg)
	return &Manager{cfg: cfg}, nil
}

// applyDefaults fills in all missing Config fields with safe defaults.
func applyDefaults(cfg Config) Config {
	if cfg.Logger == nil {
		l := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()
		cfg.Logger = NewZerologLogger(&l)
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

	return cfg
}

// Config returns a copy of the manager's configuration.
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

// SetHeaderAuthType sets the NVX-Auth-Type header to identify the authentication context.
func (m *Manager) SetHeaderAuthType(next http.Handler, authType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(constants.HeaderAuthType, authType)
		next.ServeHTTP(w, r)
	})
}
