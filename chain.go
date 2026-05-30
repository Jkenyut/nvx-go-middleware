// Package middleware provides HTTP middleware for NVX applications.
package middleware

import (
	"net/http"
	"time"

	"github.com/Jkenyut/nvx-go-middleware/constants"
)

// ChainConfig configures which middleware to use in a middleware chain.
// It allows toggling specific Chi middleware and configuring parameters like compression, throttling, and rate limiting.
type ChainConfig struct {
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
func DefaultChainConfig() ChainConfig {
	return ChainConfig{
		UseChiCompress:        true,
		UseChiTimeout:         true,
		UseChiThrottle:        false,
		UseChiStripSlashes:    true,
		CompressionLevel:      5,
		ThrottleLimit:         100,
		ThrottleTimeout:       1 * time.Minute,
		ThrottleBacklog:       50,
		UseChiRateLimitAuth:   false,
		UseChiRateLimitPublic: false,
		LimiterConfig: ConfigLimiter{
			RateLimitRequests: 30,
			RateLimitWindow:   1 * time.Minute,
			PreRequestOnBeforeLimiter: func(_ http.ResponseWriter, _ *http.Request) bool {
				return true
			},
			PreRequestOnAfterLimiter: func(_ http.ResponseWriter, _ *http.Request) bool {
				return true
			},
			Counter:     nil,
			LimiterHook: nil,
		},
	}
}

// buildInnerChain applies the innermost core middleware.
// Because it sits inside the Rate Limiter and Auth Validator, the Logger will ONLY
// record requests that successfully passed DDoS protection and authentication.
func (m *Manager) buildInnerChain(cfg ChainConfig, next http.Handler) http.Handler {
	handler := next

	handler = m.MaxBodySize()(handler)
	if cfg.UseChiStripSlashes {
		handler = m.ChiStripSlashes(handler)
	}
	handler = m.RemoveHeaders(handler)
	handler = m.SecureHeaders(handler)

	if cfg.UseChiCompress {
		handler = m.ChiCompress(cfg.CompressionLevel)(handler)
	}

	// Logger only records requests that survived Outer layers (DDoS, Bad Auth)
	handler = m.Logger(handler)

	return handler
}

// buildOuterChain applies the outermost core middleware.
// This executes BEFORE validation, logging, and application logic.
func (m *Manager) buildOuterChain(cfg ChainConfig, handler http.Handler) http.Handler {
	// TrustProxy MUST run before RateLimit and Validation to resolve Real IP accurately.
	handler = m.TrustProxy(handler)

	if cfg.UseChiTimeout {
		handler = m.ChiTimeout(m.cfg.RequestTimeout)(handler)
	}
	if cfg.UseChiThrottle {
		handler = m.ChiThrottleBacklog(cfg.ThrottleLimit, cfg.ThrottleBacklog, cfg.ThrottleTimeout)(handler)
	}

	handler = m.Recoverer(handler)
	handler = m.CORS(handler, m.cfg.AllowedOrigins, m.cfg.AllowedHeaders)

	return handler
}

// PublicChain creates a middleware chain for public routes that do not require user authentication.
// Execution Order: TrustProxy -> EnsurePublic -> RateLimit -> Logger -> App
func (m *Manager) PublicChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := m.buildInnerChain(cfg, next)

		if cfg.UseChiRateLimitPublic {
			handler = RateLimit(cfg.LimiterConfig, m.cfg.PublicKeySignature)(handler)
		}
		handler = m.SetHeaderAuthType(handler, constants.AuthTypePublic)
		handler = m.EnsurePublic(handler) // Rejects bad signatures before RateLimit processes them

		return m.buildOuterChain(cfg, handler)
	}
}

// PublicAuthChain creates a middleware chain for public routes that require authentication.
func (m *Manager) PublicAuthChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := m.buildInnerChain(cfg, next)

		if cfg.UseChiRateLimitAuth {
			handler = RateLimit(cfg.LimiterConfig, m.cfg.PrivateKeySignature)(handler)
		}
		handler = m.SetHeaderAuthType(handler, constants.AuthTypePublicAuth)
		handler = m.EnsurePublicAuth(handler)

		return m.buildOuterChain(cfg, handler)
	}
}

// PublicAPIKeyChain creates a middleware chain for public routes using API Key authentication.
func (m *Manager) PublicAPIKeyChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := m.buildInnerChain(cfg, next)

		if cfg.UseChiRateLimitPublic {
			handler = RateLimit(cfg.LimiterConfig, m.cfg.PublicKeySignature)(handler)
		}
		handler = m.SetHeaderAuthType(handler, constants.AuthTypePublicAPIKey)
		handler = m.EnsurePublicAPIKey(handler)

		return m.buildOuterChain(cfg, handler)
	}
}

// InternalChain creates a middleware chain for internal service-to-service routes.
func (m *Manager) InternalChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := m.buildInnerChain(cfg, next)

		handler = m.SetHeaderAuthType(handler, constants.AuthTypeInternal)
		handler = m.EnsureInternal(handler)

		return m.buildOuterChain(cfg, handler)
	}
}

// AdminChain creates a middleware chain for admin routes.
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

// Heartbeat returns a handler that responds to the given path with 200 OK "OK".
func Heartbeat(path string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == path {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// PreSignChain creates a middleware chain specifically for pre-signed requests.
func (m *Manager) PreSignChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := m.buildInnerChain(cfg, next)

		if cfg.UseChiRateLimitPublic {
			handler = RateLimit(cfg.LimiterConfig, m.cfg.PublicKeySignature)(handler)
		}
		handler = m.SetHeaderAuthType(handler, constants.AuthTypePublic)
		handler = m.EnsurePreSignHeaders(handler)

		return m.buildOuterChain(cfg, handler)
	}
}

// WebhookChain creates a middleware chain specialized for handling webhooks.
func (m *Manager) WebhookChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := m.buildInnerChain(cfg, next)
		return m.buildOuterChain(cfg, handler)
	}
}
