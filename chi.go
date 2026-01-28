package middleware

import (
	"net/http"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// ChiRealIP wraps Chi's RealIP middleware
func (m *Manager) ChiRealIP(next http.Handler) http.Handler {
	return chimiddleware.RealIP(next)
}

// ChiCompress wraps Chi's Compress middleware
func (m *Manager) ChiCompress(level int) func(http.Handler) http.Handler {
	return chimiddleware.Compress(level)
}

// ChiTimeout wraps Chi's Timeout middleware
func (m *Manager) ChiTimeout(timeout time.Duration) func(http.Handler) http.Handler {
	return chimiddleware.Timeout(timeout)
}

// ChiThrottle wraps Chi's Throttle middleware
func (m *Manager) ChiThrottle(limit int) func(http.Handler) http.Handler {
	return chimiddleware.Throttle(limit)
}

// ChiStripSlashes wraps Chi's StripSlashes middleware
func (m *Manager) ChiStripSlashes(next http.Handler) http.Handler {
	return chimiddleware.StripSlashes(next)
}

// ChiNoCache wraps Chi's NoCache middleware
func (m *Manager) ChiNoCache(next http.Handler) http.Handler {
	return chimiddleware.NoCache(next)
}

// ChiHeartbeat wraps Chi's Heartbeat middleware
func (m *Manager) ChiHeartbeat(endpoint string) func(http.Handler) http.Handler {
	return chimiddleware.Heartbeat(endpoint)
}

// ChiProfiler wraps Chi's Profiler middleware (for debugging)
func (m *Manager) ChiProfiler() http.Handler {
	return chimiddleware.Profiler()
}

// WrapWithChiWriter wraps response writer with Chi's WrapResponseWriter
// This is useful for compatibility with Chi middleware
func WrapWithChiWriter(w http.ResponseWriter, r *http.Request) chimiddleware.WrapResponseWriter {
	return chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
}
