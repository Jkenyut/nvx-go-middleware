package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-helper/response"
	"github.com/Jkenyut/nvx-go-middleware/constants"
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

// Rate limit configuration
type configLimiter struct {
	RateLimitRequests         int
	RateLimitWindow           time.Duration
	Counter                   httprate.LimitCounter
	PreRequestOnBeforeLimiter func(w http.ResponseWriter, r *http.Request) bool
	PreRequestOnAfterLimiter  func(w http.ResponseWriter, r *http.Request) bool
}

// RateLimit is a middleware that limits the rate of requests to a handler.
func RateLimit(
	cfg configLimiter,
	signatureSecret string,
) func(http.Handler) http.Handler {

	opts := []httprate.Option{
		httprate.WithKeyFuncs(keyByHeaderAuthType),
		httprate.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPreconditionRequired)
			json.NewEncoder(w).Encode(response.PreconditionRequired(r.Context(), "precondition required"))
		}),
		httprate.WithResponseHeaders(httprate.ResponseHeaders{
			Limit:      "NVX-RateLimit-Limit",
			Remaining:  "NVX-RateLimit-Remaining",
			Increment:  "NVX-RateLimit-Increment",
			Reset:      "NVX-RateLimit-Reset",
			RetryAfter: "NVX-Retry-After",
		}),
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(response.TooManyRequests(r.Context(), "too many requests"))
		}),
	}

	if cfg.Counter != nil {
		opts = append(opts, httprate.WithLimitCounter(cfg.Counter))
	}

	limiter := httprate.Limit(cfg.RateLimitRequests, cfg.RateLimitWindow, opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ========================================
			// LAYER 6 (OUTERMOST): OPTIONS Check
			// ========================================
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r) // Bypass
				return
			}

			// ========================================
			// LAYER 5: Before Limiter Hook
			// ========================================
			if cfg.PreRequestOnBeforeLimiter != nil {
				if !cfg.PreRequestOnBeforeLimiter(w, r) {
					return // Stop
				}
			}

			// ========================================
			// BUILD NESTED HANDLERS (Inside to Outside)
			// ========================================

			// LAYER 1 (INNERMOST): Your Handler
			handlerLayer1 := next

			// LAYER 2: After Limiter Hook
			handlerLayer2 := http.HandlerFunc(func(w2 http.ResponseWriter, r2 *http.Request) {
				if cfg.PreRequestOnAfterLimiter != nil {
					if !cfg.PreRequestOnAfterLimiter(w2, r2) {
						return // Stop
					}
				}
				handlerLayer1.ServeHTTP(w2, r2) // Call Layer 1
			})

			// LAYER 3: Rate Limiter
			handlerLayer3 := limiter(handlerLayer2) // Limiter wraps Layer 2

			// LAYER 4: Rate Key Injector
			handlerLayer4 := rateKeyInjector(signatureSecret)(handlerLayer3) // Inject wraps Layer 3

			// ========================================
			// EXECUTE LAYER 4 (which calls 3 → 2 → 1)
			// ========================================
			handlerLayer4.ServeHTTP(w, r)
		})
	}
}

func keyByHeaderAuthType(r *http.Request) (string, error) {
	return keyByHeader(r, constants.HeaderAuthType)
}

// KeyByHeader returns a key function that returns the value of the specified header
func keyByHeader(r *http.Request, header string) (string, error) {
	headerName := r.Header.Get(header)
	if headerName == "" {
		headerName = "unknown"
	}
	return headerName, nil
}

func keyByHeaderSignature(r *http.Request, secret, name string) (string, error) {
	headerName := r.Header.Get(name)
	if headerName == "" {
		headerName = "unknown"
	}
	return cryptoutil.Signature(secret, headerName), nil
}

func buildRateKeyPublic(r *http.Request, zone string, signature string) string {
	ip, _ := httprate.KeyByIP(r)
	endpoint, _ := httprate.KeyByEndpoint(r)
	userAgent, _ := keyByHeaderSignature(r, signature, constants.HeaderUserAgent)
	apiKey, _ := keyByHeader(r, constants.HeaderAPIKey)
	return fmt.Sprintf("zone:%s:ip:%s:endpoint:%s:useragent:%s:apikey:%s", zone, ip, endpoint, userAgent, apiKey)
}

func buildRateKeyPublicAuth(r *http.Request, zone string, signature string) string {
	ip, _ := httprate.KeyByIP(r)
	endpoint, _ := httprate.KeyByEndpoint(r)
	userAgent, _ := keyByHeaderSignature(r, signature, constants.HeaderUserAgent)
	userID, _ := keyByHeader(r, constants.HeaderUserID)
	userType, _ := keyByHeader(r, constants.HeaderUserType)
	apiKey, _ := keyByHeader(r, constants.HeaderAPIKey)
	return fmt.Sprintf("zone:%s:ip:%s:endpoint:%s:useragent:%s:userid:%s:usertype:%s:apikey:%s", zone, ip, endpoint, userAgent, userID, userType, apiKey)
}

func rateKeyInjector(signature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Header.Get(constants.HeaderAuthType) {
			case constants.AuthTypePublic:
				key := buildRateKeyPublic(r, constants.AuthTypePublic, signature)
				r.Header.Set("NVX-Rate-Key", key)
			case constants.AuthTypePublicAuth:
				key := buildRateKeyPublicAuth(r, constants.AuthTypePublicAuth, signature)
				r.Header.Set("NVX-Rate-Key", key)
			}
			next.ServeHTTP(w, r)
		})
	}
}
