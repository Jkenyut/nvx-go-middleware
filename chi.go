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

// ChiRealIP wraps Chi's RealIP middleware.
// It sets a http.Handler that puts the X-Real-IP and X-Forwarded-For headers into the context.
func (m *Manager) ChiRealIP(next http.Handler) http.Handler {
	return chimiddleware.RealIP(next)
}

// ChiCompress wraps Chi's Compress middleware.
// It returns a middleware that compresses the response body based on the client's Accept-Encoding header.
// Level is the compression level (1-9).
func (m *Manager) ChiCompress(level int) func(http.Handler) http.Handler {
	return chimiddleware.Compress(level)
}

// ChiTimeout wraps Chi's Timeout middleware.
// It returns a middleware that cancels the context after the given timeout.
func (m *Manager) ChiTimeout(timeout time.Duration) func(http.Handler) http.Handler {
	return chimiddleware.Timeout(timeout)
}

// ChiThrottle wraps Chi's Throttle middleware.
// It returns a middleware that limits the number of concurrent requests to the handler.
func (m *Manager) ChiThrottle(limit int) func(http.Handler) http.Handler {
	return chimiddleware.Throttle(limit)
}

// ChiStripSlashes wraps Chi's StripSlashes middleware.
// It returns a middleware that will match a request against a path without a trailing slash
// if the original request had one and no handler was found.
func (m *Manager) ChiStripSlashes(next http.Handler) http.Handler {
	return chimiddleware.StripSlashes(next)
}

// ChiNoCache wraps Chi's NoCache middleware.
// It returns a middleware that sets headers to prevent caching of the response.
func (m *Manager) ChiNoCache(next http.Handler) http.Handler {
	return chimiddleware.NoCache(next)
}

// ChiHeartbeat wraps Chi's Heartbeat middleware.
// It returns a middleware that responds to a specific path with a 200 OK status.
func (m *Manager) ChiHeartbeat(endpoint string) func(http.Handler) http.Handler {
	return chimiddleware.Heartbeat(endpoint)
}

// ChiProfiler wraps Chi's Profiler middleware.
// It returns a middleware that mounts pprof endpoints at /debug/pprof.
// This is strictly for debugging and should not be enabled in production public endpoints.
func (m *Manager) ChiProfiler() http.Handler {
	return chimiddleware.Profiler()
}

// WrapWithChiWriter wraps a standard http.ResponseWriter with Chi's WrapResponseWriter.
// This provides additional functionality like capturing the status code and bytes written,
// which is useful for logging and other middleware that need to inspect the response.
func (m *Manager) WrapWithChiWriter(w http.ResponseWriter, r *http.Request) chimiddleware.WrapResponseWriter {
	return chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
}

// ChiThrottleBacklog wraps Chi's ThrottleBacklog middleware.
// It returns a middleware that limits concurrent requests and maintains a backlog of requests
// waiting for a slot, with a timeout for how long they can wait in the queue.
func (m *Manager) ChiThrottleBacklog(limit int, backlog int, backlogTimeout time.Duration) func(http.Handler) http.Handler {
	return chimiddleware.ThrottleBacklog(limit, backlog, backlogTimeout)
}

// ConfigLimiter holds configuration for the custom rate limiter.
type ConfigLimiter struct {
	// RateLimitRequests is the number of requests allowed per window.
	RateLimitRequests int
	// RateLimitWindow is the duration of the rate limit window.
	RateLimitWindow time.Duration
	// Counter is the backend storage for the rate limiter limits (e.g., memory, redis).
	Counter httprate.LimitCounter
	// PreRequestOnBeforeLimiter is a hook executed before the rate limiter check.
	// Return false to abort the request.
	PreRequestOnBeforeLimiter func(w http.ResponseWriter, r *http.Request) bool
	// PreRequestOnAfterLimiter is a hook executed after the rate limiter check but before the handler.
	// Return false to abort the request.
	PreRequestOnAfterLimiter func(w http.ResponseWriter, r *http.Request) bool
	// LimiterFunc is the rate limiter function to use.
	LimiterFunc func(http.Handler) http.Handler
}

// RateLimit creates a rate limiting middleware based on the provided configuration.
// It supports per-header keying (e.g., by IP, API Key, User ID) and custom limiter hooks.
// It adds standard rate limit headers to the response (X-RateLimit-Limit, etc.).
func RateLimit(
	cfg ConfigLimiter,
	signatureSecret string,
	limiterFunc func(http.Handler) http.Handler,
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

			var handlerLayer3 http.Handler
			// LAYER 3: Rate Limiter
			if limiterFunc != nil {
				handlerLayer3 = limiterFunc(handlerLayer2) // Limiter wraps Layer 2
			} else {
				handlerLayer3 = limiter(handlerLayer2)
			}

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
	return keyByHeader(r, constants.HeaderRateKey)
}

// KeyByHeader returns a keying function that keys requests by the value of a specific header.
// If the header is missing, it returns "unknown".
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

// RateKeyInjector injects a rate key into the request header based on the authentication type.
func rateKeyInjector(signature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Header.Get(constants.HeaderAuthType) {
			case constants.AuthTypePublic:
				key := buildRateKeyPublic(r, constants.AuthTypePublic, signature)
				r.Header.Set(constants.HeaderRateKey, key)
			case constants.AuthTypePublicAuth:
				key := buildRateKeyPublicAuth(r, constants.AuthTypePublicAuth, signature)
				r.Header.Set(constants.HeaderRateKey, key)
			case constants.AuthTypeInternal:
				key := buildRateKeyPublicAuth(r, constants.AuthTypeInternal, signature)
				r.Header.Set(constants.HeaderRateKey, key)
			}
			next.ServeHTTP(w, r)
		})
	}
}
