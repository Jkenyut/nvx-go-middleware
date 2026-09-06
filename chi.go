package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-helper/response"
	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/bytedance/sonic"
	chi "github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
)

type routePatternContextKey struct{}

// WithRoutePattern injects the matched canonical route pattern/template (e.g. "/api/v1/users/{id}") into the context.
func WithRoutePattern(ctx context.Context, pattern string) context.Context {
	return context.WithValue(ctx, routePatternContextKey{}, pattern)
}

// RoutePatternFromContext retrieves the canonical route pattern/template from context, if set.
func RoutePatternFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	pattern, ok := ctx.Value(routePatternContextKey{}).(string)
	return pattern, ok && pattern != ""
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
	// RateLimitWindow is the duration of the rate limit window.
	RateLimitWindow int `yaml:"rateLimitWindow" default:"1"` // minutes
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
	// EndpointFunc optionally customizes how the endpoint identifier is extracted for rate limiting.
	// If nil, defaults to canonical route pattern detection (RoutePatternFromContext, Chi, ServeMux) with fallback to URL Path.
	EndpointFunc func(r *http.Request) string `yaml:"-"`
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

	limiter := httprate.LimitBy(cfg.RateLimitRequests, time.Duration(cfg.RateLimitWindow)*time.Minute, keyByHeaderAuthType, opts...)

	return func(next http.Handler) http.Handler {
		// Compile nested pipeline once at route attachment to avoid closure allocations per request.
		// LAYER 2: After Limiter Hook
		afterLimiter := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.PreRequestOnAfterLimiter != nil {
				if !cfg.PreRequestOnAfterLimiter(w, r) {
					return // Stop
				}
			}
			next.ServeHTTP(w, r) // Call innermost handler
		})

		// LAYER 3: Rate Limiter
		var limitedHandler http.Handler
		if cfg.LimiterHook != nil {
			limitedHandler = cfg.LimiterHook(afterLimiter)
		} else {
			limitedHandler = limiter(afterLimiter)
		}

		// LAYER 4: Rate Key Injector
		injectedHandler := rateKeyInjector(signatureSecret, cfg.EndpointFunc)(limitedHandler)

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// LAYER 6 (OUTERMOST): OPTIONS Check
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r) // Bypass
				return
			}

			// LAYER 5: Before Limiter Hook
			if cfg.PreRequestOnBeforeLimiter != nil {
				if !cfg.PreRequestOnBeforeLimiter(w, r) {
					return // Stop
				}
			}

			// EXECUTE LAYER 4 (which calls 3 → 2 → 1)
			injectedHandler.ServeHTTP(w, r)
		})
	}
}

func keyByHeaderAuthType(r *http.Request) (string, error) {
	return keyByHeader(r, constants.HeaderRateKey)
}

// keyByHeader extracts the specified header value from the request, or returns "unknown" if empty.
func keyByHeader(r *http.Request, header string) (string, error) {
	val := r.Header.Get(header)
	if val == "" {
		return "unknown", nil
	}
	return val, nil
}

func detectProtocol(r *http.Request) string {
	if isWebSocketUpgrade(r) {
		return "websocket"
	}
	if ct := strings.TrimSpace(r.Header.Get("Content-Type")); len(ct) >= 16 && strings.EqualFold(ct[:16], "application/grpc") {
		return "grpc"
	}
	if strings.Contains(r.URL.Path, "graphql") {
		return "graphql"
	}
	return "rest"
}

func resolveRateLimitEndpoint(r *http.Request, protocol string, customEndpointFunc ...func(*http.Request) string) string {
	var endpoint string
	if len(customEndpointFunc) > 0 && customEndpointFunc[0] != nil {
		endpoint = customEndpointFunc[0](r)
	}
	if endpoint == "" {
		endpoint = extractRoutePattern(r)
	}
	if protocol == "graphql" {
		if op := ResolveGraphQLOperation(r); op != "anonymous" {
			return endpoint + ":" + op
		}
	}
	return endpoint
}

func extractRoutePattern(r *http.Request) string {
	if pattern, ok := RoutePatternFromContext(r.Context()); ok {
		return pattern
	}
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		if pattern := rctx.RoutePattern(); pattern != "" {
			return pattern
		}
	}
	if r.Pattern != "" {
		parts := strings.SplitN(r.Pattern, " ", 2)
		if len(parts) == 2 {
			return parts[1]
		}
		return r.Pattern
	}
	endpoint, _ := httprate.KeyByEndpoint(r)
	return endpoint
}

func buildRateKeyPublic(r *http.Request, zone, signature string, endpointFunc ...func(*http.Request) string) string {
	ip, _ := keyByHeader(r, constants.HeaderIP)
	userAgent, _ := keyByHeader(r, constants.HeaderUserAgent)
	protocol := detectProtocol(r)
	endpoint := resolveRateLimitEndpoint(r, protocol, endpointFunc...)
	return cryptoutil.Signature(signature, "zone:"+zone+":protocol:"+protocol+":method:"+r.Method+":ip:"+ip+":endpoint:"+endpoint+":useragent:"+userAgent)
}

func buildRateKeyPublicAPIKey(r *http.Request, zone, signature string, endpointFunc ...func(*http.Request) string) string {
	apiKey, _ := keyByHeader(r, constants.HeaderAPIKey)
	protocol := detectProtocol(r)
	endpoint := resolveRateLimitEndpoint(r, protocol, endpointFunc...)
	return cryptoutil.Signature(signature, "zone:"+zone+":protocol:"+protocol+":method:"+r.Method+":endpoint:"+endpoint+":apikey:"+apiKey)
}

func buildRateKeyPublicAuth(r *http.Request, zone, signature string, endpointFunc ...func(*http.Request) string) string {
	tokenKey, _ := keyByHeader(r, constants.HeaderToken)
	protocol := detectProtocol(r)
	endpoint := resolveRateLimitEndpoint(r, protocol, endpointFunc...)
	return cryptoutil.Signature(signature, "zone:"+zone+":protocol:"+protocol+":method:"+r.Method+":endpoint:"+endpoint+":token:"+tokenKey)
}

// RateKeyInjector injects a rate key into the request header based on the authentication type.
func rateKeyInjector(signature string, endpointFunc ...func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var key string
			switch r.Header.Get(constants.HeaderAuthType) {
			case constants.AuthTypePublicAPIKey:
				key = buildRateKeyPublicAPIKey(r, constants.AuthTypePublicAPIKey, signature, endpointFunc...)
			case constants.AuthTypePublicAuth:
				key = buildRateKeyPublicAuth(r, constants.AuthTypePublicAuth, signature, endpointFunc...)
			default:
				key = buildRateKeyPublic(r, constants.AuthTypePublic, signature, endpointFunc...)
			}
			r.Header.Set(constants.HeaderRateKey, key)
			next.ServeHTTP(w, r)
		})
	}
}
