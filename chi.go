package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-helper/response"
	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/bytedance/sonic"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
)

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
func (m *Manager) ChiThrottleBacklog(limit, backlog int, backlogTimeout time.Duration) func(http.Handler) http.Handler {
	return chimiddleware.ThrottleBacklog(limit, backlog, backlogTimeout)
}

// ConfigLimiter holds configuration for the custom rate limiter.
type ConfigLimiter struct {
	// RateLimitRequests is the number of requests allowed per window.
	RateLimitRequests int `yaml:"rateLimitRequests" default:"100"`
	// RateLimitWindowMs is the duration of the rate limit window in milliseconds.
	RateLimitWindowMs int64 `yaml:"rateLimitWindowMs" default:"60000"` // milliseconds
	// Counter is the backend storage for the rate limiter limits (e.g., memory, redis).
	Counter httprate.LimitCounter `yaml:"-"`
	// PreRequestOnBeforeLimiter is a hook executed before the rate limiter check.
	// Return false to abort the request.
	PreRequestOnBeforeLimiter func(w http.ResponseWriter, r *http.Request) bool `yaml:"-"`
	// PreRequestOnAfterLimiter is a hook executed after the rate limiter check but before the handler.
	// Return false to abort the request.
	PreRequestOnAfterLimiter func(w http.ResponseWriter, r *http.Request) bool `yaml:"-"`
	// LimiterHook is the rate limiter function to use.
	LimiterHook func(http.Handler) http.Handler `yaml:"-"`
}

// RateLimit creates a rate limiting middleware based on the provided configuration.
// It supports per-header keying (e.g., by IP, API Key, User ID) and custom limiter hooks.
// It adds standard rate limit headers to the response (X-RateLimit-Limit, etc.).
func RateLimit(
	cfg ConfigLimiter,
	signatureSecret string,
) func(http.Handler) http.Handler {
	opts := []httprate.Option{
		httprate.WithKeyFuncs(keyByHeaderAuthType),
		httprate.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, _ error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPreconditionRequired)
			_ = sonic.ConfigDefault.NewEncoder(w).Encode(response.PreconditionRequired(r.Context(), "precondition required"))
		}),
		httprate.WithResponseHeaders(httprate.ResponseHeaders{
			Limit:      "RateLimit-Limit",
			Remaining:  "RateLimit-Remaining",
			Reset:      "RateLimit-Reset",
			RetryAfter: "Retry-After",
			Increment:  "",
		}),
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = sonic.ConfigDefault.NewEncoder(w).Encode(response.TooManyRequests(r.Context(), "too many requests"))
		}),
	}

	if cfg.Counter != nil {
		opts = append(opts, httprate.WithLimitCounter(cfg.Counter))
	}

	limiter := httprate.LimitBy(cfg.RateLimitRequests, time.Duration(cfg.RateLimitWindowMs)*time.Millisecond, keyByHeaderAuthType, opts...)

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
			if cfg.LimiterHook != nil {
				handlerLayer3 = cfg.LimiterHook(handlerLayer2) // Limiter wraps Layer 2
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

func detectProtocol(r *http.Request) string {
	if r.Header.Get("Upgrade") == "websocket" {
		return "websocket"
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		return "grpc"
	}
	if strings.Contains(r.URL.Path, "graphql") {
		return "graphql"
	}
	return "rest"
}

type routePatternContextKey struct{}

// WithRoutePattern injects a route pattern into the request context for rate limiter keying.
// Example: r = r.WithContext(mw.WithRoutePattern(r.Context(), route.Path))
func WithRoutePattern(ctx context.Context, pattern string) context.Context {
	return context.WithValue(ctx, routePatternContextKey{}, pattern)
}

// RoutePatternFromContext retrieves the route pattern from context if injected.
func RoutePatternFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	val, ok := ctx.Value(routePatternContextKey{}).(string)
	return val, ok
}

// resolveEndpoint resolves endpoint from context pattern first, falling back to httprate.KeyByEndpoint.
func resolveEndpoint(r *http.Request) string {
	if pattern, ok := RoutePatternFromContext(r.Context()); ok && pattern != "" {
		return pattern
	}
	endpoint, _ := httprate.KeyByEndpoint(r)
	return endpoint
}

func resolveRateEndpoint(r *http.Request) string {
	endpoint := resolveEndpoint(r)
	if detectProtocol(r) == "graphql" {
		if op := ResolveGraphQLOperation(r); op != "anonymous" {
			endpoint = endpoint + ":" + op
		}
	}
	return endpoint
}

func buildRateKey(r *http.Request, authType, signature string) string {
	endpoint := resolveRateEndpoint(r)
	appID, _ := keyByHeader(r, constants.HeaderAppID)
	protocol := detectProtocol(r)

	var payload string
	switch authType {
	case constants.AuthTypePublicAPIKey:
		apiKey, _ := keyByHeader(r, constants.HeaderAPIKey)
		payload = fmt.Sprintf("zone:%s:protocol:%s:method:%s:endpoint:%s:apikey:%s:appid:%s", authType, protocol, r.Method, endpoint, apiKey, appID)
	case constants.AuthTypePublicAuth:
		tokenKey, _ := keyByHeader(r, constants.HeaderToken)
		payload = fmt.Sprintf("zone:%s:protocol:%s:method:%s:endpoint:%s:token:%s:appid:%s", authType, protocol, r.Method, endpoint, tokenKey, appID)
	default:
		ip, _ := keyByHeader(r, constants.HeaderIP)
		userAgent, _ := keyByHeader(r, constants.HeaderUserAgent)
		payload = fmt.Sprintf("zone:%s:protocol:%s:method:%s:ip:%s:endpoint:%s:useragent:%s:appid:%s", constants.AuthTypePublic, protocol, r.Method, ip, endpoint, userAgent, appID)
	}

	return cryptoutil.Signature(signature, payload)
}

// RateKeyInjector injects a rate key into the request header based on the authentication type.
func rateKeyInjector(signature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authType := r.Header.Get(constants.HeaderAuthType)
			r.Header.Set(constants.HeaderRateKey, buildRateKey(r, authType, signature))
			next.ServeHTTP(w, r)
		})
	}
}
