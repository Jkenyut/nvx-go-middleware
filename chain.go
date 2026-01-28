package middleware

import (
	"net/http"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// ChainConfig configures which middleware to use
type ChainConfig struct {
	// Chi middleware toggles
	UseChiRealIP       bool
	UseChiCompress     bool
	UseChiTimeout      bool
	UseChiThrottle     bool
	UseChiStripSlashes bool

	// Compression level (1-9)
	CompressionLevel int

	// Throttle limit (concurrent requests)
	ThrottleLimit int
}

// DefaultChainConfig returns recommended chain configuration
func DefaultChainConfig() ChainConfig {
	return ChainConfig{
		UseChiRealIP:       false, // Disabled in favor of secure TrustProxy
		UseChiCompress:     true,
		UseChiTimeout:      true,  // User-requested: specific Chi timeout
		UseChiThrottle:     false, // Enable per route
		UseChiStripSlashes: true,
		CompressionLevel:   5,
		ThrottleLimit:      100,
	}
}

// GlobalChain creates a middleware chain with both custom and Chi middleware
func (m *Manager) GlobalChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		// Apply custom middleware (inner to outer)
		handler = m.MaxBodySize(m.cfg.RequestBodyLimit)(handler)
		handler = m.SecureHeaders(handler)
		handler = m.EnsureCommonHeaders(handler)
		handler = m.Recoverer(handler)
		handler = m.Logger(handler)

		// Apply Chi middleware
		if cfg.UseChiTimeout {
			handler = chimiddleware.Timeout(m.cfg.RequestTimeout)(handler)
		}

		if cfg.UseChiCompress {
			handler = chimiddleware.Compress(cfg.CompressionLevel)(handler)
		}

		if cfg.UseChiStripSlashes {
			handler = chimiddleware.StripSlashes(handler)
		}

		if cfg.UseChiRealIP {
			handler = chimiddleware.RealIP(handler)
		}

		// Always apply TrustProxy to populate NVX-IP safely
		handler = m.TrustProxy(handler)

		// Add CORS
		handler = m.CORS(handler, m.cfg.AllowedOrigins)

		return handler
	}
}

// PublicChain creates a chain for public routes (with device validation)
func (m *Manager) PublicChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return m.GlobalChain(cfg)(
			m.EnsurePublicAuth(next),
		)
	}
}

// AuthChain creates a chain for authenticated routes
func (m *Manager) AuthChain(cfg ChainConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		handler := next

		// Add throttling for auth routes
		if cfg.UseChiThrottle {
			handler = chimiddleware.Throttle(cfg.ThrottleLimit)(handler)
		}

		return m.GlobalChain(cfg)(
			m.EnsureAuth(handler),
		)
	}
}

// AdminChain creates a chain for admin routes
func (m *Manager) AdminChain(cfg ChainConfig, adminCheck func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return m.AuthChain(cfg)(
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
