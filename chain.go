package middleware

import (
	"net/http"
	"time"

	"github.com/Jkenyut/nvx-go-middleware/constants"
)

// ChainConfig configures which middleware to use in a middleware chain.
// It allows toggling specific Chi middleware and configuring parameters like compression, throttling, and rate limiting.
type ChainConfig struct {
	// UseChiRealIP enables the Chi RealIP middleware, which sets the X-Real-IP header.
	// Defaults to false in DefaultChainConfig in favor of secure TrustProxy.
	UseChiRealIP bool
	// UseChiCompress enables the Chi Compress middleware for response compression.
	UseChiCompress bool
	// UseChiTimeout enables the Chi Timeout middleware to set a request processing timeout.
	UseChiTimeout bool
	// UseChiThrottle enables the Chi Throttle middleware to limit concurrent requests.
	UseChiThrottle bool
	// UseChiRateLimitAuth enables rate limiting for authenticated routes.
	UseChiRateLimitAuth bool
	// UseChiRateLimitPublic enables rate limiting for public routes.
	UseChiRateLimitPublic bool
	// UseChiStripSlashes enables the Chi StripSlashes middleware to handle trailing slashes.
	UseChiStripSlashes bool

	// CompressionLevel sets the compression level (1-9) if UseChiCompress is true.
	CompressionLevel int

	// ThrottleLimit sets the maximum number of concurrent requests if UseChiThrottle is true.
	ThrottleLimit int

	// ThrottleTimeout sets the max duration to wait for a slot if UseChiThrottle is true.
	ThrottleTimeout time.Duration

	// ThrottleBacklog sets the maximum size of the backlog queue for throttled requests.
	ThrottleBacklog int
	// LimiterConfig holds the configuration for the custom rate limiter.
	LimiterConfig ConfigLimiter
}

// DefaultChainConfig returns a ChainConfig with recommended default values.
// It sets up reasonable defaults for compression, throttling, and rate limiting,
// and enables specific middleware like Compress and StripSlashes.
func DefaultChainConfig() ChainConfig {
	return ChainConfig{

		UseChiRealIP:       false, // Disabled in favor of secure TrustProxy
		UseChiCompress:     true,
		UseChiTimeout:      true,            // User-requested: specific Chi timeout
		UseChiThrottle:     false,           // Enable per route
		UseChiStripSlashes: true,            // User-requested: specific Chi strip slashes
		CompressionLevel:   5,               // User-requested: specific Chi compression level
		ThrottleLimit:      100,             // User-requested: specific Chi throttle limit
		ThrottleTimeout:    1 * time.Minute, // User-requested: specific Chi throttle timeout

		ThrottleBacklog:       50,    // User-requested: specific Chi throttle backlog
		UseChiRateLimitAuth:   false, // Enabled by default
		UseChiRateLimitPublic: false, // Enabled by default
		LimiterConfig: ConfigLimiter{
			RateLimitRequests: 60,              // User-requested: specific Chi rate limit requests
			RateLimitWindow:   1 * time.Minute, // User-requested: specific Chi rate limit window
			PreRequestOnBeforeLimiter: func(w http.ResponseWriter, r *http.Request) bool {
				return true // TODO: implement pre request on before limiter
			},
			PreRequestOnAfterLimiter: func(w http.ResponseWriter, r *http.Request) bool {
				return true // TODO: implement pre request on after limiter
			},
			Counter:     nil,
			LimiterHook: nil,
		},
	}
}

// GlobalChain creates a middleware chain suitable for application-wide use.
// It applies common headers, base middleware stacks (logging, recovery, security),
// and configured Chi middleware.
func (m *Manager) GlobalChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		// Ensure Common Headers (specific to GlobalChain)
		handler = m.EnsureCommonHeaders(handler)

		// Apply Base Middleware
		handler = m.applyBaseMiddleware(handler, cfg)

		return handler
	}
}

// applyBaseMiddleware applies the core set of middleware common to most chains.
// This includes timeouts, body size limits, header management, recovery, logging,
// compression, trust proxy, and throttling based on the provided configuration.
func (m *Manager) applyBaseMiddleware(handler http.Handler, cfg ChainConfig) http.Handler {

	// Apply Chi middleware
	if cfg.UseChiTimeout {
		handler = m.ChiTimeout(m.cfg.RequestTimeout)(handler)
	}

	// Apply custom middleware (inner to outer)
	handler = m.RemoveHeaders(handler)

	// Note: header validation is applied by the caller (GlobalChain vs PreSignChain)
	handler = m.Logger(handler)

	// Apply Chi strip slashes
	if cfg.UseChiStripSlashes {
		handler = m.ChiStripSlashes(handler)
	}

	// Apply Chi real IP
	if cfg.UseChiRealIP {
		handler = m.ChiRealIP(handler)
	}

	// Always apply TrustProxy to populate NVX-IP safely
	handler = m.TrustProxy(handler)

	// Apply Chi throttle
	if cfg.UseChiThrottle {
		handler = m.ChiThrottleBacklog(cfg.ThrottleLimit, cfg.ThrottleBacklog, cfg.ThrottleTimeout)(handler)
	}

	return handler
}

// PublicChain creates a middleware chain for public routes that do not require user authentication.
// It ensures the request is treated as public, runs the global chain, applies public rate limits,
// sets the auth type to public, and handles CORS.
func (m *Manager) PublicChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		handler = m.EnsurePublic(handler)

		handler = m.GlobalChain(cfg)(handler)

		// Apply Auth Rate Limit
		if cfg.UseChiRateLimitPublic {
			// Apply Chi rate limit
			handler = RateLimit(cfg.LimiterConfig, m.cfg.PublicKeySignature)(handler)
		}

		handler = m.SetHeaderAuthType(handler, constants.AuthTypePublic)
		handler = m.MaxBodySize()(handler)
		handler = m.SecureHeaders(handler)
		// Apply Chi compression
		if cfg.UseChiCompress {
			handler = m.ChiCompress(cfg.CompressionLevel)(handler)
		}
		handler = m.Recoverer(handler)
		// Apply CORS (Outer) - Ensures 429s/503s get CORS headers
		handler = m.CORS(handler, m.cfg.AllowedOrigins, m.cfg.AllowedHeaders)
		return handler
	}
}

// PublicAuthChain creates a middleware chain for public routes that require authentication (e.g., user login).
// It ensures public auth requirements, runs the global chain, applies authenticated rate limits,
// sets the auth type to public-auth, and handles CORS.
func (m *Manager) PublicAuthChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		handler = m.EnsurePublicAuth(handler)

		handler = m.GlobalChain(cfg)(handler)

		// Apply Auth Rate Limit
		if cfg.UseChiRateLimitAuth {
			handler = RateLimit(cfg.LimiterConfig, m.cfg.PrivateKeySignature)(handler)
		}
		handler = m.SetHeaderAuthType(handler, constants.AuthTypePublicAuth)
		handler = m.MaxBodySize()(handler)
		handler = m.SecureHeaders(handler)
		// Apply Chi compression
		if cfg.UseChiCompress {
			handler = m.ChiCompress(cfg.CompressionLevel)(handler)
		}
		handler = m.Recoverer(handler)
		// Apply CORS (Outer) - Ensures 429s/503s get CORS headers
		handler = m.CORS(handler, m.cfg.AllowedOrigins, m.cfg.AllowedHeaders)
		return handler
	}
}

// InternalChain creates a middleware chain for internal service-to-service routes.
// It ensures internal request requirements, runs the global chain, sets the auth type to internal,
// and helps manage CORS for internal communication.
func (m *Manager) InternalChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		handler = m.EnsureInternal(handler)

		handler = m.GlobalChain(cfg)(handler)

		handler = m.SetHeaderAuthType(handler, constants.AuthTypeInternal)
		handler = m.MaxBodySize()(handler)
		handler = m.SecureHeaders(handler)
		// Apply Chi compression
		if cfg.UseChiCompress {
			handler = m.ChiCompress(cfg.CompressionLevel)(handler)
		}
		handler = m.Recoverer(handler)
		// Apply CORS (Outer) - Ensures 429s/503s get CORS headers
		handler = m.CORS(handler, m.cfg.AllowedOrigins, m.cfg.AllowedHeaders)
		return handler
	}
}

// AdminChain creates a middleware chain for admin routes.
// It builds upon the InternalChain and adds an additional adminCheck middleware
// for specific administrative authorization.
func (m *Manager) AdminChain(cfg ChainConfig, adminCheck func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return m.InternalChain(cfg)(
			adminCheck(next),
		)
	}
}

// ApplyMiddleware applies a list of middleware to a handler.
// The middleware are applied in reverse order so that the first middleware in the list
// is the first one to process the request (outermost).
func ApplyMiddleware(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

// Heartbeat creates a simple heartbeat/health-check middleware handler.
// It intercepts requests to the specified path and returns a 200 OK "OK" plain text response,
// bypassing subsequent middleware.
func Heartbeat(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}
}

// PreSignChain creates a middleware chain specifically for pre-signed requests.
// It handles pre-sign specific headers, applies base middleware, and enforces public rate limits.
func (m *Manager) PreSignChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		// Ensure PreSign Headers (specific to PreSignChain)
		handler = m.EnsurePreSignHeaders(handler)

		// Apply Base Middleware
		handler = m.applyBaseMiddleware(handler, cfg)

		// Apply Chi rate limit
		// Note: PreSignChain uses public rate limit settings in the original code, preserved here.
		if cfg.UseChiRateLimitPublic {
			handler = RateLimit(cfg.LimiterConfig, m.cfg.PublicKeySignature)(handler)
		}
		handler = m.SetHeaderAuthType(handler, constants.AuthTypePublic)
		handler = m.MaxBodySize()(handler)
		handler = m.SecureHeaders(handler)
		// Apply Chi compression
		if cfg.UseChiCompress {
			handler = m.ChiCompress(cfg.CompressionLevel)(handler)
		}
		handler = m.Recoverer(handler)
		// Apply CORS (Outer) - Ensures 429s/503s get CORS headers
		handler = m.CORS(handler, m.cfg.AllowedOrigins, m.cfg.AllowedHeaders)
		return handler
	}
}

// WebhookChain creates a middleware chain specialized for handling webhooks.
// It focuses on processing reliability and logging, applying timeouts, body limits,
// header cleanup, recovery, logging, and compression, while trusting proxies.
func (m *Manager) WebhookChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		// Apply Chi middleware
		if cfg.UseChiTimeout {
			handler = m.ChiTimeout(m.cfg.RequestTimeout)(handler)
		}

		// Apply custom middleware (inner to outer)
		handler = m.MaxBodySize()(handler)
		handler = m.RemoveHeaders(handler)
		// Note: header validation is applied by the caller if needed, typically webhooks trust the source via signature
		handler = m.Recoverer(handler)
		handler = m.Logger(handler)

		// Apply Chi compression
		if cfg.UseChiCompress {
			handler = m.ChiCompress(cfg.CompressionLevel)(handler)
		}

		// Apply Chi strip slashes
		if cfg.UseChiStripSlashes {
			handler = m.ChiStripSlashes(handler)
		}

		// Always apply TrustProxy to populate NVX-IP safely
		handler = m.TrustProxy(handler)

		return handler
	}
}
