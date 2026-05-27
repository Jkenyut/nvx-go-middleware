package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/Jkenyut/nvx-go-helper/activity"
	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-middleware/constants"
)

// wsResponseWriter wraps http.ResponseWriter to detect the WebSocket upgrade
// and track whether the upgrade succeeded.
type wsResponseWriter struct {
	http.ResponseWriter
	hijacked bool
}

func (w *wsResponseWriter) WriteHeader(code int) {
	if code == http.StatusSwitchingProtocols {
		w.hijacked = true
	}
	w.ResponseWriter.WriteHeader(code)
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
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Must be a WebSocket upgrade request
			if !isWebSocketUpgrade(r) {
				http.Error(w, "expected WebSocket upgrade", http.StatusBadRequest)
				return
			}

			// Real IP
			realIPHandler := m.TrustProxy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			realIPHandler.ServeHTTP(w, r)

			// Inject context values
			r = WithActivityContext(r)

			// Generate / propagate transaction ID
			transactionID := r.Header.Get(constants.HeaderTransactionID)
			if transactionID == "" {
				transactionID = cryptoutil.V7()
			}
			r.Header.Set(constants.HeaderTransactionID, transactionID)
			r = r.WithContext(activity.WithTransactionID(r.Context(), transactionID))

			// Authenticate
			if authenticator != nil && !authenticator(r) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": constants.ErrMsgInvalidToken})
				return
			}

			// Panic guard (pre-upgrade)
			defer func() {
				if rec := recover(); rec != nil {
					m.cfg.Logger.Error().
						Str("service", m.cfg.ServiceName).
						Str("transaction_id", transactionID).
						Interface("panic", rec).
						Msg("panic in WebSocket handler")
				}
			}()

			start := time.Now()
			ww := &wsResponseWriter{ResponseWriter: w}

			next.ServeHTTP(ww, r)

			m.cfg.Logger.Info().
				Str("service", m.cfg.ServiceName).
				Str("transaction_id", transactionID).
				Str("remote_ip", r.Header.Get(constants.HeaderIP)).
				Str("path", r.URL.Path).
				Interface("upgraded", ww.hijacked).
				Interface("latency_ms", time.Since(start).Milliseconds()).
				Msg("WebSocket connection")
		})
	}
}

// isWebSocketUpgrade reports whether the request is a valid WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}
