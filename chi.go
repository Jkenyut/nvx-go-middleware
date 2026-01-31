package middleware

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Jkenyut/nvx-go-helper/response"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
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
func (m *Manager) WrapWithChiWriter(w http.ResponseWriter, r *http.Request) chimiddleware.WrapResponseWriter {
	return chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
}

// ChiThrottleBacklog wraps Chi's ThrottleBacklog middleware
func (m *Manager) ChiThrottleBacklog(limit int, backlog int, backlogTimeout time.Duration) func(http.Handler) http.Handler {
	return chimiddleware.ThrottleBacklog(limit, backlog, backlogTimeout)
}

func RateLimit(
	requestLimit int,
	window time.Duration,
	counter httprate.LimitCounter,
	keyFuncs ...httprate.KeyFunc,
) func(http.Handler) http.Handler {

	opts := []httprate.Option{
		httprate.WithKeyFuncs(keyFuncs...),
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(response.TooManyRequests(r.Context(), "Too Many Requests"))
		}),
	}

	if counter != nil {
		opts = append(opts, httprate.WithLimitCounter(counter))
	}

	limiter := httprate.Limit(requestLimit, window, opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip valid OPTIONS requests from rate limiting
			// This prevents preflight requests from using up quota or failing on strict limits
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			limiter(next).ServeHTTP(w, r)
		})
	}
}

// KeyByHeader returns a key function that returns the value of the specified header
func KeyByHeader(header string) httprate.KeyFunc {
	return func(r *http.Request) (string, error) {
		return r.Header.Get(header), nil
	}
}

// KeyByName returns a key function that returns the value of the specified header
func KeyByName(name string) httprate.KeyFunc {
	return func(r *http.Request) (string, error) {
		return name, nil
	}
}
