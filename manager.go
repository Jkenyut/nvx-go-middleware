package middleware

import (
	"cmp"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/Jkenyut/nvx-go-helper/format"
	appLogger "github.com/Jkenyut/nvx-go-helper/logger"
	"github.com/Jkenyut/nvx-go-helper/sliceutil"
	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/Jkenyut/nvx-go-middleware/model"
)

// Manager holds the middleware configuration and provides middleware methods.
// It is the central entry point for creating and managing middleware chains.
type Manager struct {
	cfg           Config
	logCloser     io.Closer
	trustedIPs    map[netip.Addr]struct{}
	trustedNets   []netip.Prefix
	serverMetrics *ServerMetrics
}

// New creates a new Middleware Manager using functional options.
// Safe defaults are applied for any unconfigured fields.
func New(opts ...Option) (*Manager, error) {
	var m Manager
	for _, opt := range opts {
		if opt != nil {
			if err := opt(&m); err != nil {
				return nil, err
			}
		}
	}
	closer := applyDefaults(&m.cfg)
	m.logCloser = closer
	m.initTrustedProxies()
	if m.cfg.Core.EnableTelemetry {
		m.serverMetrics, _ = NewServerMetrics(m.cfg.Core.ServiceName)
	}
	return &m, nil
}

// NewWithError creates a new Middleware Manager from a Config struct.
// It validates that required fields (like HMAC signature keys) are set.
func NewWithError(cfg *Config) (*Manager, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}
	// Validate required fields BEFORE applying defaults that might mask missing values.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return New(WithConfig(*cfg))
}

// applyDefaults fills in all missing Config fields with safe defaults.
// It returns an io.Closer if it created any resources that need to be closed.
func applyDefaults(cfg *Config) io.Closer {
	cfg.Core.ServiceName = cmp.Or(cfg.Core.ServiceName, "unknown-service")
	cfg.Core.Env = cmp.Or(cfg.Core.Env, "development")

	if cfg.Logger == nil {
		subLog := appLogger.L().With().
			Str("service", cfg.Core.ServiceName).
			Str("env", cfg.Core.Env).
			Logger()
		cfg.Logger = NewZerologLogger(&subLog)
	}

	if cfg.LogStore == nil {
		cfg.LogStore = &ConsoleStore{logger: cfg.Logger}
	}

	cfg.Limits.RequestTimeoutMs = cmp.Or(cfg.Limits.RequestTimeoutMs, int64(constants.RequestTimeoutMs))
	cfg.Limits.RequestBodyLimitSize = cmp.Or(cfg.Limits.RequestBodyLimitSize, int64(constants.RequestBodyLimitSize))
	cfg.Limits.RequestBodyNonFileLimitSize = cmp.Or(cfg.Limits.RequestBodyNonFileLimitSize, int64(constants.RequestBodyNonFileLimitSize))
	cfg.Logging.ResponseBodyLogLimitSize = cmp.Or(cfg.Logging.ResponseBodyLogLimitSize, int64(constants.ResponseBodyLogLimitSize))
	cfg.Logging.LogStoreTimeoutMs = cmp.Or(cfg.Logging.LogStoreTimeoutMs, int64(constants.DefaultLogStoreTimeoutMs))

	if len(cfg.Headers.RequiredPublicAuthHeaders) == 0 {
		cfg.Headers.RequiredPublicAuthHeaders = slices.Clone(constants.RequiredPublicAuthHeaders)
	}
	if len(cfg.Headers.RequiredPublicHeaders) == 0 {
		cfg.Headers.RequiredPublicHeaders = slices.Clone(constants.RequiredPublicHeaders)
	}
	if len(cfg.Headers.RequiredInternalHeaders) == 0 {
		cfg.Headers.RequiredInternalHeaders = slices.Clone(constants.RequiredInternalHeaders)
	}
	if len(cfg.Headers.RequiredPublicAPIKeyHeaders) == 0 {
		cfg.Headers.RequiredPublicAPIKeyHeaders = slices.Clone(constants.RequiredPublicAPIKeyHeaders)
	}
	if len(cfg.Headers.RequiredSignaturePublicHeaders) == 0 {
		cfg.Headers.RequiredSignaturePublicHeaders = slices.Clone(constants.RequiredSignaturePublicHeaders)
	}
	if len(cfg.Headers.RequiredSignatureInternalHeaders) == 0 {
		cfg.Headers.RequiredSignatureInternalHeaders = slices.Clone(constants.RequiredSignatureInternalHeaders)
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
		cfg.Security.AllowedHeaders = sliceutil.Unique(sliceutil.Flatten([][]string{
			{"Accept", "Authorization", "Content-Type"},
			cfg.Headers.RequiredPublicAuthHeaders,
			cfg.Headers.RequiredPublicHeaders,
			cfg.Headers.RequiredInternalHeaders,
			cfg.Headers.RequiredPublicAPIKeyHeaders,
		}))
	}
	cfg.Headers.Keys.RequestID = cmp.Or(cfg.Headers.Keys.RequestID, constants.HeaderRequestID)
	cfg.Headers.Keys.CorrelationID = cmp.Or(cfg.Headers.Keys.CorrelationID, constants.HeaderCorrelationID)
	cfg.Headers.Keys.IP = cmp.Or(cfg.Headers.Keys.IP, constants.HeaderIP)
	cfg.Headers.Keys.IPOrigin = cmp.Or(cfg.Headers.Keys.IPOrigin, constants.HeaderIPOrigin)
	cfg.Headers.Keys.UserID = cmp.Or(cfg.Headers.Keys.UserID, constants.HeaderUserID)
	cfg.Headers.Keys.APIKey = cmp.Or(cfg.Headers.Keys.APIKey, constants.HeaderAPIKey)
	cfg.Headers.Keys.AuthType = cmp.Or(cfg.Headers.Keys.AuthType, constants.HeaderAuthType)
	if len(cfg.Security.HeadersToRemove) == 0 {
		cfg.Security.HeadersToRemove = []string{}
	}
	cfg.Security.SignatureTimestampExpiredMs = cmp.Or(cfg.Security.SignatureTimestampExpiredMs, int64(constants.TimestampExpiredMs))

	if len(cfg.Logging.LogHeaders) == 0 {
		cfg.Logging.LogHeaders = []string{
			cfg.Headers.Keys.RequestID,
			cfg.Headers.Keys.CorrelationID,
			cfg.Headers.Keys.IP,
			cfg.Headers.Keys.IPOrigin,
			cfg.Headers.Keys.UserID,
		}
	}

	if len(cfg.Logging.MaskKeywords) == 0 {
		cfg.Logging.MaskKeywords = slices.Clone(format.DefaultMaskKeywords)
	} else {
		cfg.Logging.MaskKeywords = sliceutil.Unique(
			sliceutil.Flatten([][]string{format.DefaultMaskKeywords, cfg.Logging.MaskKeywords}),
		)
	}

	return nil
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

func (m *Manager) initTrustedProxies() {
	if len(m.cfg.Security.TrustedProxies) == 0 {
		return
	}
	m.trustedIPs = make(map[netip.Addr]struct{}, len(m.cfg.Security.TrustedProxies))
	m.trustedNets = make([]netip.Prefix, 0, len(m.cfg.Security.TrustedProxies))
	for _, proxy := range m.cfg.Security.TrustedProxies {
		if prefix, err := netip.ParsePrefix(proxy); err == nil {
			m.trustedNets = append(m.trustedNets, prefix)
		} else if addr, err := netip.ParseAddr(proxy); err == nil {
			m.trustedIPs[addr] = struct{}{}
		}
	}
}

func (m *Manager) saveAuditLog(ctx context.Context, entry *model.AuditLog) error {
	if m.cfg.LogStore == nil || entry == nil {
		return nil
	}
	timeoutMs := m.cfg.Logging.LogStoreTimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = constants.DefaultLogStoreTimeoutMs
	}
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	return m.cfg.LogStore.Save(saveCtx, entry)
}

// SetHeaderAuthType sets the Auth-Type header to identify the authentication context.
func (m *Manager) SetHeaderAuthType(next http.Handler, authType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(m.cfg.Headers.Keys.AuthType, authType)
		next.ServeHTTP(w, r)
	})
}

// addLogHeaders dynamically adds headers to the log context based on the LogHeaders config.
func (m *Manager) addLogHeaders(event LogEvent, r *http.Request) LogEvent {
	for _, h := range m.cfg.Logging.LogHeaders {
		if val := r.Header.Get(h); val != "" {
			event = event.Str(h, val)
		}
	}
	return event
}

// ServerMetrics returns an HTTP middleware that measures server request durations and counts.
func (m *Manager) ServerMetrics() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if m.serverMetrics == nil {
			return next
		}
		return m.serverMetrics.Middleware(next)
	}
}
