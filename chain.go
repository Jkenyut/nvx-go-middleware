// Package middleware provides HTTP middleware for NVX applications.
package middleware

import (
	"net/http"
	"time"

	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// ChainFeatures configures which middleware to use in a middleware chain.
// It allows toggling specific Chi middleware and configuring parameters like compression, throttling, and rate limiting.
// ChainFeatures configures which middleware features are enabled.
type ChainFeatures struct {
	UseChiCompress        bool `yaml:"useChiCompress" default:"true"`
	UseChiTimeout         bool `yaml:"useChiTimeout" default:"false"`
	UseChiThrottle        bool `yaml:"useChiThrottle" default:"false"`
	UseChiRateLimitAuth   bool `yaml:"useChiRateLimitAuth" default:"false"`
	UseChiRateLimitPublic bool `yaml:"useChiRateLimitPublic" default:"false"`
	UseChiStripSlashes    bool `yaml:"useChiStripSlashes" default:"true"`
}

// ChainCompression configures response compression.
type ChainCompression struct {
	CompressionLevel int `yaml:"compressionLevel" default:"5"`
}

// ChainThrottle configures concurrent request throttling.
type ChainThrottle struct {
	ThrottleLimit   int `yaml:"throttleLimit" default:"100"`
	ThrottleTimeout int `yaml:"throttleTimeout" default:"30"` // seconds
	ThrottleBacklog int `yaml:"throttleBacklog" default:"100"`
}

// ChainConfig holds the configuration for the middleware chain.
type ChainConfig struct {
	Features    ChainFeatures    `yaml:"features"`
	Compression ChainCompression `yaml:"compression"`
	Throttle    ChainThrottle    `yaml:"throttle"`
	Limiter     ConfigLimiter    `yaml:"limiter"`
}

// ApplyDefaults applies default values to the ChainConfig if they are not already set.
// Note: Boolean fields (like Features) are not overridden because Go cannot distinguish
// between an intentionally set 'false' and an unset boolean.
func (c *ChainConfig) ApplyDefaults() {
	if c.Compression.CompressionLevel == 0 {
		c.Compression.CompressionLevel = constants.DefaultCompressionLevel
	}
	if c.Throttle.ThrottleLimit == 0 {
		c.Throttle.ThrottleLimit = constants.DefaultThrottleLimit
	}
	if c.Throttle.ThrottleTimeout == 0 {
		c.Throttle.ThrottleTimeout = constants.DefaultThrottleTimeout
	}
	if c.Throttle.ThrottleBacklog == 0 {
		c.Throttle.ThrottleBacklog = constants.DefaultThrottleBacklog
	}
	if c.Limiter.RateLimitRequests == 0 {
		c.Limiter.RateLimitRequests = constants.DefaultRateLimitRequests
	}
	if c.Limiter.RateLimitWindow == 0 {
		c.Limiter.RateLimitWindow = constants.DefaultRateLimitWindow
	}
	if c.Limiter.PreRequestOnBeforeLimiter == nil {
		c.Limiter.PreRequestOnBeforeLimiter = func(_ http.ResponseWriter, _ *http.Request) bool {
			return true
		}
	}
	if c.Limiter.PreRequestOnAfterLimiter == nil {
		c.Limiter.PreRequestOnAfterLimiter = func(_ http.ResponseWriter, _ *http.Request) bool {
			return true
		}
	}
}

// buildInnerChain applies the innermost core middleware.
// Because it sits inside the Rate Limiter and Auth Validator, the Logger will ONLY
// record requests that successfully passed DDoS protection and authentication.
func (m *Manager) buildInnerChain(cfg *ChainConfig, next http.Handler) http.Handler {
	handler := next

	handler = m.MaxBodySize()(handler)
	if cfg.Features.UseChiStripSlashes {
		handler = m.ChiStripSlashes(handler)
	}
	handler = m.RemoveHeaders(handler)

	// Logger only records requests that survived Outer layers (DDoS, Bad Auth)
	// Placing Logger inside ChiCompress ensures it captures uncompressed plaintext bodies.
	handler = m.Logger(handler)

	if cfg.Features.UseChiCompress {
		handler = m.ChiCompress(cfg.Compression.CompressionLevel)(handler)
	}

	return handler
}

// buildOuterChain applies the outermost core middleware.
// This executes BEFORE validation, logging, and application logic.
func (m *Manager) buildOuterChain(cfg *ChainConfig, handler http.Handler) http.Handler {
	// TrustProxy MUST run before RateLimit and Validation to resolve Real IP accurately.
	handler = m.TrustProxy(handler)

	if m.cfg.Core.EnableTelemetry {
		handler = otelhttp.NewMiddleware(m.cfg.Core.ServiceName)(handler)
	}

	if cfg.Features.UseChiTimeout {
		handler = m.ChiTimeout(time.Duration(m.cfg.Limits.RequestTimeout) * time.Second)(handler)
	}
	if cfg.Features.UseChiThrottle {
		handler = m.ChiThrottleBacklog(cfg.Throttle.ThrottleLimit, cfg.Throttle.ThrottleBacklog, time.Duration(cfg.Throttle.ThrottleTimeout)*time.Second)(handler)
	}

	handler = m.Recoverer(handler)

	return handler
}

// BaseChain handles basic REST configuration
func (m *Manager) BaseChain(cfg *ChainConfig, setupRoute func(r chi.Router)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		r := chi.NewRouter()

		if m.cfg.Core.EnableTelemetry {
			r.Use(otelhttp.NewMiddleware(m.cfg.Core.ServiceName))
		}

		if cfg.Features.UseChiStripSlashes {
			r.Use(chimiddleware.StripSlashes)
		}

		r.Use(m.TrustProxy)

		r.Use(m.Recoverer)

		if cfg.Features.UseChiTimeout {
			r.Use(chimiddleware.Timeout(time.Duration(m.cfg.Limits.RequestTimeout) * time.Second))
		}

		if cfg.Features.UseChiCompress {
			r.Use(chimiddleware.Compress(cfg.Compression.CompressionLevel))
		}

		if cfg.Features.UseChiThrottle {
			r.Use(m.ChiThrottleBacklog(cfg.Throttle.ThrottleLimit, cfg.Throttle.ThrottleBacklog, time.Duration(cfg.Throttle.ThrottleTimeout)*time.Second))
		}

		// structured logging
		r.Use(m.Logger)

		if setupRoute != nil {
			setupRoute(r)
		}

		r.Mount("/", next)
		return r
	}
}

// PublicChain creates a middleware chain for public routes that do not require user authentication.
// Execution Order: TrustProxy -> EnsurePublic -> RateLimit -> Logger -> App
func (m *Manager) PublicChain(cfg *ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := m.buildInnerChain(cfg, next)
		if cfg.Features.UseChiRateLimitPublic {
			handler = RateLimit(cfg.Limiter, m.cfg.Security.PublicKeySignature)(handler)
		}
		handler = m.EnsurePublic(handler)
		handler = m.SetHeaderAuthType(handler, constants.AuthTypePublic)
		return m.buildOuterChain(cfg, handler)
	}
}

// PublicRateLimitChain returns a middleware chain configured for public (unauthenticated) endpoints.
func (m *Manager) PublicRateLimitChain(cfg *ChainConfig) func(http.Handler) http.Handler {
	return m.BaseChain(cfg, func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return m.SetHeaderAuthType(next, constants.AuthTypePublic)
		})
		if cfg.Features.UseChiRateLimitPublic {
			r.Use(RateLimit(cfg.Limiter, m.cfg.Security.PublicKeySignature))
		}
	})
}

// ProtectedRateLimitChain returns a middleware chain configured for authenticated endpoints.
func (m *Manager) ProtectedRateLimitChain(cfg *ChainConfig) func(http.Handler) http.Handler {
	return m.BaseChain(cfg, func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return m.SetHeaderAuthType(next, constants.AuthTypePublicAuth)
		})
		if cfg.Features.UseChiRateLimitAuth {
			r.Use(RateLimit(cfg.Limiter, m.cfg.Security.PublicKeySignature))
		}
	})
}

// PublicAuthChain creates a middleware chain for public routes that require authentication.
func (m *Manager) PublicAuthChain(cfg *ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := m.buildInnerChain(cfg, next)
		if cfg.Features.UseChiRateLimitAuth {
			handler = RateLimit(cfg.Limiter, m.cfg.Security.PublicKeySignature)(handler)
		}
		handler = m.EnsurePublicAuth(handler)
		handler = m.SetHeaderAuthType(handler, constants.AuthTypePublicAuth)
		return m.buildOuterChain(cfg, handler)
	}
}

// PublicAPIKeyChain creates a middleware chain for public routes using API Key authentication.
func (m *Manager) PublicAPIKeyChain(cfg *ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := m.buildInnerChain(cfg, next)
		if cfg.Features.UseChiRateLimitAuth {
			handler = RateLimit(cfg.Limiter, m.cfg.Security.PublicKeySignature)(handler)
		}
		handler = m.EnsurePublicAPIKey(handler)
		handler = m.SetHeaderAuthType(handler, constants.AuthTypePublicAPIKey)
		return m.buildOuterChain(cfg, handler)
	}
}

// InternalChain creates a middleware chain for internal service-to-service routes.
func (m *Manager) InternalChain(cfg *ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := m.buildInnerChain(cfg, next)
		handler = m.EnsureInternal(handler)
		handler = m.SetHeaderAuthType(handler, constants.AuthTypeInternal)
		return m.buildOuterChain(cfg, handler)
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

// WebhookChain creates a middleware chain specialized for handling webhooks.
func (m *Manager) WebhookChain(cfg *ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := m.buildInnerChain(cfg, next)
		return m.buildOuterChain(cfg, handler)
	}
}
