package middleware

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Jkenyut/nvx-go-helper/activity"
	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-helper/format"
	"github.com/Jkenyut/nvx-go-helper/response"
	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/Jkenyut/nvx-go-middleware/model"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// wsResponseWriter wraps standard http.ResponseWriter to detect the WebSocket upgrade
// and track whether the upgrade succeeded, while preserving Hijacker and Flusher contracts.
type wsResponseWriter struct {
	http.ResponseWriter
	status   int
	hijacked bool
}

func (w *wsResponseWriter) WriteHeader(code int) {
	w.status = code
	if code == http.StatusSwitchingProtocols {
		w.hijacked = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *wsResponseWriter) Status() int {
	if w.status != 0 {
		return w.status
	}
	return 0
}

// Hijack implements http.Hijacker to allow WebSocket upgrade libraries to take over the connection.
func (w *wsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		w.hijacked = true
		return h.Hijack()
	}
	return nil, nil, errors.New("underlying ResponseWriter does not implement http.Hijacker")
}

// Flush implements http.Flusher to support streaming or flushing before/during upgrade.
func (w *wsResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap implements the Go 1.20+ ResponseController unwrap contract.
func (w *wsResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// WebSocketChain returns a middleware chain designed for WebSocket upgrade endpoints.
//
// It applies:
//   - TrustProxy (real IP extraction)
//   - Context injection (transaction ID, user ID, etc.)
//   - Panic recovery (before the upgrade)
//   - Request logging (logs the upgrade attempt and outcome)
//   - Optional per-connection auth via the provided authenticator.
//
// The authenticator receives the request before the upgrade. Return false to
// reject the connection (a 401 response is written automatically).
func (m *Manager) WebSocketChain(
	authenticator func(r *http.Request) bool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		coreHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Inject context values
			r = WithActivityContext(r, &m.cfg.Headers.Keys)

			// Generate / propagate transaction ID
			transactionID := r.Header.Get(m.cfg.Headers.Keys.TransactionID)
			if transactionID == "" {
				transactionID = cryptoutil.V7()
				r.Header.Set(m.cfg.Headers.Keys.TransactionID, transactionID)
			}
			r = r.WithContext(activity.WithTransactionID(r.Context(), transactionID))

			start := time.Now()
			ww := &wsResponseWriter{ResponseWriter: w}

			IDAuditLog := cryptoutil.V7()
			entry := model.AuditLog{
				ID:              IDAuditLog,
				Method:          r.Method,
				FullURL:         FullURL(r),
				StatusCode:      0,
				LatencyMS:       0,
				IP:              r.Header.Get(m.cfg.Headers.Keys.IP),
				IPOrigin:        r.Header.Get(m.cfg.Headers.Keys.IPOrigin),
				RequestID:       r.Header.Get(m.cfg.Headers.Keys.RequestID),
				CreatedBy:       format.ToInt64(r.Header.Get(m.cfg.Headers.Keys.UserID)),
				CreatedAt:       format.NowUTC(),
				TransactionID:   transactionID,
				RequestHeaders:  normalizeHeadersJSON(r.Header, m.cfg.Logging.MaskKeywords),
				ResponseHeaders: nil,
				RequestBody:     nil, // WebSockets upgrade requests have no body
				ResponseBody:    nil,
				Protocol:        "WebSocket",
				ServiceName:     m.cfg.Core.ServiceName,
				UserAgent:       r.UserAgent(),
				ErrorMessage:    "",
			}

			reqCtx := context.WithoutCancel(r.Context())

			defer func() {
				statusCode := http.StatusBadRequest
				if ww.hijacked {
					statusCode = http.StatusSwitchingProtocols
				} else if ww.status != 0 {
					statusCode = ww.status
				} else if sp, ok := ww.ResponseWriter.(interface{ Status() int }); ok && sp.Status() != 0 {
					statusCode = sp.Status()
				}
				if m.cfg.Core.EnableTelemetry {
					span := trace.SpanFromContext(r.Context())
					if span.SpanContext().IsValid() && statusCode >= 500 {
						span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", statusCode))
					}
				}

				entry.StatusCode = statusCode
				entry.LatencyMS = time.Since(start).Milliseconds()
				entry.ResponseHeaders = normalizeHeadersJSON(ww.Header(), m.cfg.Logging.MaskKeywords)

				if err := m.cfg.LogStore.Save(reqCtx, &entry); err != nil {
					m.cfg.Logger.Error().
						Str("service", m.cfg.Core.ServiceName).
						Str("transaction_id", transactionID).
						Str("ip", r.Header.Get(m.cfg.Headers.Keys.IP)).
						Str("ip_origin", r.Header.Get(m.cfg.Headers.Keys.IPOrigin)).
						Str("user_id", r.Header.Get(m.cfg.Headers.Keys.UserID)).
						Str("user_agent", r.UserAgent()).
						Str("protocol", "WebSocket").
						Str("request_id", r.Header.Get(m.cfg.Headers.Keys.RequestID)).
						Err(err).
						Msg("failed to save ws audit log")
				}
			}()

			// Panic guard (pre-upgrade)
			defer func() {
				if rec := recover(); rec != nil {
					if m.cfg.Core.EnableTelemetry {
						span := trace.SpanFromContext(r.Context())
						if span.SpanContext().IsValid() {
							span.RecordError(fmt.Errorf("panic: %v", rec))
							span.SetStatus(codes.Error, "panic recovered")
						}
					}
					m.cfg.Logger.Error().
						Str("service", m.cfg.Core.ServiceName).
						Str("transaction_id", transactionID).
						Str("ip", r.Header.Get(m.cfg.Headers.Keys.IP)).
						Str("ip_origin", r.Header.Get(m.cfg.Headers.Keys.IPOrigin)).
						Str("user_id", r.Header.Get(m.cfg.Headers.Keys.UserID)).
						Str("user_agent", r.UserAgent()).
						Str("protocol", "WebSocket").
						Str("request_id", r.Header.Get(m.cfg.Headers.Keys.RequestID)).
						Interface("panic", rec).
						Msg("panic in WebSocket handler")

					if !ww.hijacked {
						http.Error(ww, "Internal Server Error", http.StatusInternalServerError)
						return
					}
				}
			}()

			// Must be a WebSocket upgrade request
			if !isWebSocketUpgrade(r) {
				http.Error(ww, "expected WebSocket upgrade", http.StatusBadRequest)
				return
			}

			if m.cfg.Core.EnableTelemetry {
				span := trace.SpanFromContext(r.Context())
				if span.SpanContext().IsValid() {
					span.SetName("WebSocket Upgrade")
					span.SetAttributes(
						attribute.String("transaction_id", transactionID),
						attribute.String("request_id", r.Header.Get(m.cfg.Headers.Keys.RequestID)),
						attribute.String("ip", r.Header.Get(m.cfg.Headers.Keys.IP)),
						attribute.String("ip_origin", r.Header.Get(m.cfg.Headers.Keys.IPOrigin)),
						attribute.String("user_id", r.Header.Get(m.cfg.Headers.Keys.UserID)),
						attribute.String("user_agent", r.UserAgent()),
						attribute.String("service", m.cfg.Core.ServiceName),
						attribute.String("protocol", "WebSocket"),
						attribute.String("http.target", r.URL.Path),
					)
				}
			}

			// Authenticate
			if authenticator != nil && !authenticator(r) {
				if m.cfg.Core.EnableTelemetry {
					span := trace.SpanFromContext(r.Context())
					if span.SpanContext().IsValid() {
						span.SetStatus(codes.Error, constants.ErrMsgInvalidToken)
					}
				}
				response.WriteJSONResponse(ww, response.Unauthorized(r.Context(), constants.ErrMsgInvalidToken))
				return
			}

			next.ServeHTTP(ww, r)
		})

		var handler http.Handler = coreHandler

		if m.cfg.Core.EnableTelemetry {
			handler = otelhttp.NewMiddleware(m.cfg.Core.ServiceName)(handler)
		}

		handler = m.TrustProxy(handler)

		return handler
	}
}

// isWebSocketUpgrade reports whether the request is a valid WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}
