package middleware

import (
	"net/http"
)

// Option defines a functional option for configuring a Manager.
type Option func(*Manager) error

// WithServiceName sets the service name for telemetry and logging.
func WithServiceName(name string) Option {
	return func(m *Manager) error {
		m.cfg.Core.ServiceName = name
		return nil
	}
}

// WithEnv sets the environment (e.g. "development", "staging", "production").
func WithEnv(env string) Option {
	return func(m *Manager) error {
		m.cfg.Core.Env = env
		return nil
	}
}

// WithTelemetry enables or disables OpenTelemetry tracing.
func WithTelemetry(enable bool) Option {
	return func(m *Manager) error {
		m.cfg.Core.EnableTelemetry = enable
		return nil
	}
}

// WithCore sets the entire Core config.
func WithCore(core ConfigCore) Option {
	return func(m *Manager) error {
		m.cfg.Core = core
		return nil
	}
}

// WithLogger sets a custom Logger instance.
func WithLogger(l Logger) Option {
	return func(m *Manager) error {
		m.cfg.Logger = l
		return nil
	}
}

// WithLogStore sets a custom audit LogStore.
func WithLogStore(store LogStore) Option {
	return func(m *Manager) error {
		m.cfg.LogStore = store
		return nil
	}
}

// WithLogHeaders configures which headers are logged with each event.
func WithLogHeaders(headers ...string) Option {
	return func(m *Manager) error {
		m.cfg.Logging.LogHeaders = headers
		return nil
	}
}

// WithBodyLogging toggles logging of request and response bodies.
func WithBodyLogging(logRequest, logResponse bool) Option {
	return func(m *Manager) error {
		m.cfg.Logging.LogRequestBodies = logRequest
		m.cfg.Logging.LogResponseBodies = logResponse
		return nil
	}
}

// WithMaskKeywords sets keywords to be masked in logs.
func WithMaskKeywords(keywords ...string) Option {
	return func(m *Manager) error {
		m.cfg.Logging.MaskKeywords = keywords
		return nil
	}
}

// WithResponseBodyLogLimit sets the maximum size (in bytes) of response body recorded in logs.
func WithResponseBodyLogLimit(limit int64) Option {
	return func(m *Manager) error {
		m.cfg.Logging.ResponseBodyLogLimitSize = limit
		return nil
	}
}

// WithLogging sets the entire Logging config.
func WithLogging(logging ConfigLogging) Option {
	return func(m *Manager) error {
		m.cfg.Logging = logging
		return nil
	}
}

// WithRequestTimeoutMs sets request timeout in milliseconds.
func WithRequestTimeoutMs(ms int64) Option {
	return func(m *Manager) error {
		m.cfg.Limits.RequestTimeoutMs = ms
		return nil
	}
}

// WithRequestTimeout sets request timeout in seconds.
// Deprecated: Use WithRequestTimeoutMs instead.
func WithRequestTimeout(seconds int) Option {
	return WithRequestTimeoutMs(int64(seconds) * 1000)
}

// WithRequestBodyLimitSize sets maximum overall request body size (e.g. for multipart).
func WithRequestBodyLimitSize(limit int64) Option {
	return func(m *Manager) error {
		m.cfg.Limits.RequestBodyLimitSize = limit
		return nil
	}
}

// WithRequestBodyNonFileLimitSize sets maximum non-file request body size.
func WithRequestBodyNonFileLimitSize(limit int64) Option {
	return func(m *Manager) error {
		m.cfg.Limits.RequestBodyNonFileLimitSize = limit
		return nil
	}
}

// WithLimits sets the entire Limits config.
func WithLimits(limits ConfigLimits) Option {
	return func(m *Manager) error {
		m.cfg.Limits = limits
		return nil
	}
}

// WithSecurityKeys sets the HMAC public and private signature keys.
func WithSecurityKeys(publicKey, privateKey string) Option {
	return func(m *Manager) error {
		m.cfg.Security.PublicKeySignature = publicKey
		m.cfg.Security.PrivateKeySignature = privateKey
		return nil
	}
}

// WithTrustedProxies sets trusted proxy IP addresses or CIDRs.
func WithTrustedProxies(proxies ...string) Option {
	return func(m *Manager) error {
		m.cfg.Security.TrustedProxies = proxies
		return nil
	}
}

// WithAllowedOrigins sets allowed CORS origins.
func WithAllowedOrigins(origins ...string) Option {
	return func(m *Manager) error {
		m.cfg.Security.AllowedOrigins = origins
		return nil
	}
}

// WithAllowedContentTypes sets allowed request Content-Types.
func WithAllowedContentTypes(types ...string) Option {
	return func(m *Manager) error {
		m.cfg.Security.AllowedContentTypes = types
		return nil
	}
}

// WithAllowedHeaders sets allowed CORS headers.
func WithAllowedHeaders(headers ...string) Option {
	return func(m *Manager) error {
		m.cfg.Security.AllowedHeaders = headers
		return nil
	}
}

// WithHeadersToRemove sets response headers to strip before sending to client.
func WithHeadersToRemove(headers ...string) Option {
	return func(m *Manager) error {
		m.cfg.Security.HeadersToRemove = headers
		return nil
	}
}

// WithSignatureTimestampExpiredMs sets timestamp skew expiration for signatures in milliseconds.
func WithSignatureTimestampExpiredMs(ms int64) Option {
	return func(m *Manager) error {
		m.cfg.Security.SignatureTimestampExpiredMs = ms
		return nil
	}
}

// WithSignatureTimestampExpired sets timestamp skew expiration for signatures in seconds.
// Deprecated: Use WithSignatureTimestampExpiredMs instead.
func WithSignatureTimestampExpired(seconds int64) Option {
	return WithSignatureTimestampExpiredMs(seconds * 1000)
}

// WithSecurity sets the entire Security config.
func WithSecurity(sec ConfigSecurity) Option {
	return func(m *Manager) error {
		m.cfg.Security = sec
		return nil
	}
}

// WithHeaderKeys sets the header key mappings used by the middleware.
func WithHeaderKeys(keys HeaderKeys) Option {
	return func(m *Manager) error {
		m.cfg.Headers.Keys = keys
		return nil
	}
}

// WithHeaders sets the entire Headers config.
func WithHeaders(headers ConfigHeaders) Option {
	return func(m *Manager) error {
		m.cfg.Headers = headers
		return nil
	}
}

// WithContextInjector sets a custom function to inject values into the request context.
func WithContextInjector(injector func(r *http.Request) *http.Request) Option {
	return func(m *Manager) error {
		m.cfg.ContextInjector = injector
		return nil
	}
}

// WithConfig merges an existing Config struct into the Manager.
// Useful when loading configuration from YAML, JSON, or environment maps.
func WithConfig(cfg Config) Option {
	return func(m *Manager) error {
		m.cfg = cfg
		return nil
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain Options
// ─────────────────────────────────────────────────────────────────────────────

// ChainOption configures a middleware chain (ChainConfig).
type ChainOption func(*ChainConfig)

// WithChainConfig overrides the entire ChainConfig.
func WithChainConfig(cfg ChainConfig) ChainOption {
	return func(c *ChainConfig) {
		*c = cfg
	}
}

// WithChiCompress enables or disables Chi compression middleware.
func WithChiCompress(enable bool, level ...int) ChainOption {
	return func(c *ChainConfig) {
		c.Features.UseChiCompress = enable
		if len(level) > 0 {
			c.Compression.CompressionLevel = level[0]
		}
	}
}

// WithChiTimeout enables or disables Chi timeout middleware.
func WithChiTimeout(enable bool) ChainOption {
	return func(c *ChainConfig) {
		c.Features.UseChiTimeout = enable
	}
}

// WithChiThrottleMs enables or disables Chi throttle middleware with timeout in milliseconds.
func WithChiThrottleMs(enable bool, limit, backlog int, timeoutMs int64) ChainOption {
	return func(c *ChainConfig) {
		c.Features.UseChiThrottle = enable
		if limit > 0 {
			c.Throttle.ThrottleLimit = limit
		}
		if backlog > 0 {
			c.Throttle.ThrottleBacklog = backlog
		}
		if timeoutMs > 0 {
			c.Throttle.ThrottleTimeoutMs = timeoutMs
		}
	}
}

// WithChiThrottle enables or disables Chi throttle middleware with timeout in seconds.
// Deprecated: Use WithChiThrottleMs instead.
func WithChiThrottle(enable bool, limit, backlog, timeoutSec int) ChainOption {
	return WithChiThrottleMs(enable, limit, backlog, int64(timeoutSec)*1000)
}

// WithChiStripSlashes enables or disables Chi strip slashes middleware.
func WithChiStripSlashes(enable bool) ChainOption {
	return func(c *ChainConfig) {
		c.Features.UseChiStripSlashes = enable
	}
}

// WithRateLimitPublic enables or disables public rate limiting in the chain.
func WithRateLimitPublic(enable bool) ChainOption {
	return func(c *ChainConfig) {
		c.Features.UseChiRateLimitPublic = enable
	}
}

// WithRateLimitAuth enables or disables authenticated rate limiting in the chain.
func WithRateLimitAuth(enable bool) ChainOption {
	return func(c *ChainConfig) {
		c.Features.UseChiRateLimitAuth = enable
	}
}

// WithRateLimitConfigMs configures rate limiting thresholds (requests per window milliseconds).
func WithRateLimitConfigMs(requests int, windowMs int64) ChainOption {
	return func(c *ChainConfig) {
		if requests > 0 {
			c.Limiter.RateLimitRequests = requests
		}
		if windowMs > 0 {
			c.Limiter.RateLimitWindowMs = windowMs
		}
	}
}

// WithRateLimitConfig configures rate limiting thresholds (requests per window minutes).
// Deprecated: Use WithRateLimitConfigMs instead.
func WithRateLimitConfig(requests, windowMinutes int) ChainOption {
	return WithRateLimitConfigMs(requests, int64(windowMinutes)*60*1000)
}

// WithLimiter sets the entire ConfigLimiter for the chain.
func WithLimiter(limiter ConfigLimiter) ChainOption {
	return func(c *ChainConfig) {
		c.Limiter = limiter
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CORS Options
// ─────────────────────────────────────────────────────────────────────────────

// CORSConfig holds options for the CORS middleware.
type CORSConfig struct {
	AllowedOrigins []string
	AllowedHeaders []string
}

// CORSOption configures CORS middleware per route.
type CORSOption func(*CORSConfig)

// WithCORSOrigins sets allowed origins for CORS.
func WithCORSOrigins(origins ...string) CORSOption {
	return func(c *CORSConfig) {
		c.AllowedOrigins = origins
	}
}

// WithCORSHeaders sets allowed headers for CORS.
func WithCORSHeaders(headers ...string) CORSOption {
	return func(c *CORSConfig) {
		c.AllowedHeaders = headers
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Body Size Options
// ─────────────────────────────────────────────────────────────────────────────

// BodySizeConfig holds custom limits for MaxBodySize middleware.
type BodySizeConfig struct {
	BodyLimit        int64
	NonFileLimit     int64
	AllowedTypes     []string
}

// BodySizeOption configures MaxBodySize middleware.
type BodySizeOption func(*BodySizeConfig)

// WithCustomBodyLimit overrides the max request body size.
func WithCustomBodyLimit(size int64) BodySizeOption {
	return func(c *BodySizeConfig) {
		c.BodyLimit = size
	}
}

// WithCustomNonFileBodyLimit overrides the max non-file request body size.
func WithCustomNonFileBodyLimit(size int64) BodySizeOption {
	return func(c *BodySizeConfig) {
		c.NonFileLimit = size
	}
}

// WithCustomAllowedContentTypes overrides allowed Content-Types.
func WithCustomAllowedContentTypes(types ...string) BodySizeOption {
	return func(c *BodySizeConfig) {
		c.AllowedTypes = types
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphQL & WebSocket Options
// ─────────────────────────────────────────────────────────────────────────────

// GraphQLConfig holds options for GraphQLChain.
type GraphQLConfig struct {
	MaxDepth int
}

// GraphQLOption configures GraphQLChain.
type GraphQLOption func(*GraphQLConfig)

// WithGraphQLMaxDepth sets maximum nesting depth for GraphQL queries (0 = unlimited).
func WithGraphQLMaxDepth(depth int) GraphQLOption {
	return func(c *GraphQLConfig) {
		c.MaxDepth = depth
	}
}

// WebSocketConfig holds options for WebSocketChain.
type WebSocketConfig struct {
	Authenticator func(r *http.Request) bool
}

// WebSocketOption configures WebSocketChain.
type WebSocketOption func(*WebSocketConfig)

// WithWSAuthenticator sets the authentication function for WebSocket connections.
func WithWSAuthenticator(authFn func(r *http.Request) bool) WebSocketOption {
	return func(c *WebSocketConfig) {
		c.Authenticator = authFn
	}
}
