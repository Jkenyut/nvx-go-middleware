package middleware

import (
	"net/http"
	"time"

	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/go-chi/httprate"
)

// ChainConfig configures which middleware to use
type ChainConfig struct {
	// Chi middleware toggles
	UseChiRealIP          bool
	UseChiCompress        bool
	UseChiTimeout         bool
	UseChiThrottle        bool
	UseChiRateLimit       bool
	UseChiRateLimitAuth   bool
	UseChiRateLimitPublic bool
	UseChiStripSlashes    bool

	// Compression level (1-9)
	CompressionLevel int

	// Throttle limit (concurrent requests)
	ThrottleLimit int

	// Throttle timeout (duration)
	ThrottleTimeout time.Duration

	// Throttle backlog (max queue size)
	ThrottleBacklog int

	// Rate limit configuration
	RateLimitRequests int
	RateLimitWindow   time.Duration

	// PreSignChain middleware toggles
	preRequestOnBeforeLimiter func(w http.ResponseWriter, r *http.Request) bool
	preRequestOnAfterLimiter  func(w http.ResponseWriter, r *http.Request) bool
}

// DefaultChainConfig returns recommended chain configuration
func DefaultChainConfig() ChainConfig {
	return ChainConfig{

		UseChiRealIP:       false, // Disabled in favor of secure TrustProxy
		UseChiCompress:     true,
		UseChiTimeout:      true,            // User-requested: specific Chi timeout
		UseChiThrottle:     false,           // Enable per route
		UseChiStripSlashes: true,            // User-requested: specific Chi strip slashes
		CompressionLevel:   5,               // User-requested: specific Chi compression level
		ThrottleLimit:      50,              // User-requested: specific Chi throttle limit
		ThrottleTimeout:    1 * time.Minute, // User-requested: specific Chi throttle timeout

		ThrottleBacklog:       50,              // User-requested: specific Chi throttle backlog
		UseChiRateLimit:       true,            // Enabled by default
		UseChiRateLimitAuth:   true,            // Enabled by default
		UseChiRateLimitPublic: true,            // Enabled by default
		RateLimitRequests:     120,             // User-requested: specific Chi rate limit requests
		RateLimitWindow:       1 * time.Minute, // User-requested: specific Chi rate limit window
	}
}

// GlobalChain creates a middleware chain with both custom and Chi middleware
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

// applyBaseMiddleware applies the core middleware stack common to most chains
func (m *Manager) applyBaseMiddleware(handler http.Handler, cfg ChainConfig) http.Handler {

	// Apply Chi middleware
	if cfg.UseChiTimeout {
		handler = m.ChiTimeout(m.cfg.RequestTimeout)(handler)
	}

	// Apply custom middleware (inner to outer)
	handler = m.MaxBodySize()(handler)
	handler = m.RemoveHeaders(handler)
	handler = m.SecureHeaders(handler)
	// Note: header validation is applied by the caller (GlobalChain vs PreSignChain)
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

// PublicChain creates a chain for public routes (with device validation)
func (m *Manager) PublicChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		handler = m.EnsurePublic(handler)

		handler = m.GlobalChain(cfg)(handler)

		// Apply Auth Rate Limit
		if cfg.UseChiRateLimitPublic {

			opts := []httprate.KeyFunc{
				httprate.Key(m.cfg.ServiceName),
				httprate.KeyByIP,
				httprate.KeyByEndpoint,
				KeyByHeaderSignature(m.cfg.PrivateKeySignature, constants.HeaderUserAgent),
				KeyByHeader(constants.HeaderAPIKey),
			}
			// Apply Chi rate limit
			handler = RateLimit(cfg.RateLimitRequests, cfg.RateLimitWindow, nil, cfg.preRequestOnBeforeLimiter, cfg.preRequestOnAfterLimiter, opts...)(handler)
		}

		// Apply CORS (Outer) - Ensures 429s/503s get CORS headers
		handler = m.CORS(handler, m.cfg.AllowedOrigins, m.cfg.AllowedHeaders)

		return handler
	}
}

// PublicAuthChain creates a chain for authenticated public routes
func (m *Manager) PublicAuthChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		handler = m.EnsurePublicAuth(handler)

		handler = m.GlobalChain(cfg)(handler)

		// Apply Auth Rate Limit
		if cfg.UseChiRateLimitAuth {
			opts := []httprate.KeyFunc{
				httprate.Key(m.cfg.ServiceName),
				httprate.KeyByIP,
				httprate.KeyByEndpoint,
				KeyByHeaderSignature(m.cfg.PrivateKeySignature, constants.HeaderUserAgent),
				KeyByHeader(constants.HeaderUserID),
				KeyByHeader(constants.HeaderUserType),
				KeyByHeader(constants.HeaderAPIKey),
			}

			handler = RateLimit(cfg.RateLimitRequests, cfg.RateLimitWindow, nil, cfg.preRequestOnBeforeLimiter, cfg.preRequestOnAfterLimiter, opts...)(handler)
		}

		// Apply CORS (Outer) - Ensures 429s/503s get CORS headers
		handler = m.CORS(handler, m.cfg.AllowedOrigins, m.cfg.AllowedHeaders)

		return handler
	}
}

// InternalChain creates a chain for internal routes
func (m *Manager) InternalChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		handler = m.EnsureInternal(handler)

		handler = m.GlobalChain(cfg)(handler)

		// Apply CORS (Outer) - Ensures 429s/503s get CORS headers
		handler = m.CORS(handler, m.cfg.AllowedOrigins, m.cfg.AllowedHeaders)

		return handler
	}
}

// AdminChain creates a chain for admin routes
func (m *Manager) AdminChain(cfg ChainConfig, adminCheck func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return m.InternalChain(cfg)(
			adminCheck(next),
		)
	}
}

// ApplyMiddleware applies multiple middleware in order (left to right)
func ApplyMiddleware(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

// Heartbeat creates a simple health check endpoint
func Heartbeat(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
	}
}

// PreSignChain creates a middleware chain with both custom and Chi middleware
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
			opts := []httprate.KeyFunc{
				httprate.Key(m.cfg.ServiceName),
				httprate.KeyByIP,
				httprate.KeyByEndpoint,
				KeyByHeaderSignature(m.cfg.PrivateKeySignature, constants.HeaderUserAgent),
				KeyByHeader(constants.HeaderAPIKey),
			}

			handler = RateLimit(cfg.RateLimitRequests, cfg.RateLimitWindow, nil, cfg.preRequestOnBeforeLimiter, cfg.preRequestOnAfterLimiter, opts...)(handler)
		}

		// Apply CORS (Outer) - Ensures 429s/503s get CORS headers
		handler = m.CORS(handler, m.cfg.AllowedOrigins, m.cfg.AllowedHeaders)

		return handler
	}
}

// WebhookChain creates a chain for webhook routes
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
