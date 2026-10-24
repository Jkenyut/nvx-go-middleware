package middleware

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// ServerMetrics holds OpenTelemetry instruments for HTTP server monitoring.
type ServerMetrics struct {
	durationHist metric.Float64Histogram
	reqCounter   metric.Int64Counter
}

// NewServerMetrics initializes HTTP server metrics instruments.
func NewServerMetrics(instrumentationName string) (*ServerMetrics, error) {
	if instrumentationName == "" {
		instrumentationName = "github.com/Jkenyut/nvx-go-middleware"
	}
	meter := otel.Meter(instrumentationName)

	durationHist, err := meter.Float64Histogram(
		"http.server.request.duration",
		metric.WithDescription("Duration of HTTP server requests in seconds"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
	)
	if err != nil {
		return nil, err
	}

	reqCounter, err := meter.Int64Counter(
		"http.server.requests.total",
		metric.WithDescription("Total number of incoming HTTP requests processed"),
	)
	if err != nil {
		return nil, err
	}

	return &ServerMetrics{
		durationHist: durationHist,
		reqCounter:   reqCounter,
	}, nil
}

// Middleware returns an HTTP middleware recording latency and request counts.
func (sm *ServerMetrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rw *responseRecorder
		isOwner := false
		if existingRw, ok := w.(*responseRecorder); ok {
			rw = existingRw
		} else {
			rw = wrapResponseWriter(w, r, 0)
			isOwner = true
		}

		start := time.Now()

		defer func() {
			duration := time.Since(start).Seconds()

			routePattern := ""
			if rCtx := chi.RouteContext(r.Context()); rCtx != nil {
				routePattern = rCtx.RoutePattern()
			}
			if routePattern == "" {
				routePattern = r.Pattern
			}
			if routePattern == "" {
				routePattern = "unmatched"
			}

			statusCode := rw.Status()
			if statusCode == 0 {
				statusCode = http.StatusOK
			}

			attrs := []attribute.KeyValue{
				attribute.String("http.request.method", r.Method),
				attribute.String("http.route", routePattern),
				attribute.Int("http.response.status_code", statusCode),
			}

			ctx := r.Context()
			if sm.durationHist != nil {
				sm.durationHist.Record(ctx, duration, metric.WithAttributes(attrs...))
			}
			if sm.reqCounter != nil {
				sm.reqCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
			}

			if isOwner && rw != nil {
				rw.Free()
			}
		}()

		if isOwner {
			next.ServeHTTP(rw, r)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}
