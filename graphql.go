package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Jkenyut/nvx-go-helper/activity"
	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-helper/format"
	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/Jkenyut/nvx-go-middleware/model"
	"github.com/bytedance/sonic"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// graphqlRequestBody is used to extract the GraphQL operation name from the request body.
type graphqlRequestBody struct {
	OperationName string `json:"operationName"`
	Query         string `json:"query"`
}

// GraphQLChain returns a middleware chain for GraphQL endpoints.
//
// It applies (in order, outer → inner):
//   - TrustProxy
//   - Context injection (transaction ID, user ID, etc.)
//   - Panic recovery
//   - Operation name extraction (populates r.Header "X-GraphQL-Operation")
//   - Query depth limiting (returns 400 if nesting depth exceeds maxDepth; 0 = unlimited)
//   - Structured access logging
//
// Usage:
//
//	router.Handle("/graphql", mgr.GraphQLChain(20)(graphqlHandler))
func (m *Manager) GraphQLChain(maxDepth int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		coreHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ── Context injection ─────────────────────────────────────
			r = WithActivityContext(r)

			transactionID := r.Header.Get(constants.HeaderTransactionID)
			if transactionID == "" {
				transactionID = cryptoutil.V7()
			}
			r.Header.Set(constants.HeaderTransactionID, transactionID)
			r = r.WithContext(activity.WithTransactionID(r.Context(), transactionID))

			var rw *responseRecorder

			// ── Panic recovery ────────────────────────────────────────
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
						Str("request_id", r.Header.Get(constants.HeaderRequestID)).
						Str("ip", r.Header.Get(constants.HeaderIP)).
						Str("ip_origin", r.Header.Get(constants.HeaderIPOrigin)).
						Str("user_id", r.Header.Get(constants.HeaderUserID)).
						Str("user_agent", r.UserAgent()).
						Interface("panic", rec).
						Msg("panic in GraphQL handler")

					// Abort if response already started
					if rw != nil && rw.Status() != 0 {
						return
					}

					targetW := w
					if rw != nil {
						targetW = rw
					}

					writeJSON(targetW, http.StatusInternalServerError, map[string]any{
						"errors": []map[string]string{{"message": "internal server error"}},
					})
				}
			}()

			// ── Operation name extraction ─────────────────────────────
			var gqlBody graphqlRequestBody
			if r.Method == http.MethodPost {
				raw, err := ReadAndRestoreBody(r, m.cfg.Limits.RequestBodyNonFileLimitSize)
				if err == nil && len(raw) > 0 {
					_ = sonic.Unmarshal(raw, &gqlBody)
				}
			}

			operationName := ResolveGraphQLOperation(r)
			if operationName == "anonymous" && gqlBody.OperationName != "" {
				operationName = gqlBody.OperationName
			}
			r.Header.Set("X-GraphQL-Operation", operationName)

			// ── Depth limiting ────────────────────────────────────────
			if maxDepth > 0 && gqlBody.Query != "" {
				if depth := graphqlQueryDepth(gqlBody.Query); depth > maxDepth {
					writeJSON(w, http.StatusBadRequest, map[string]any{
						"errors": []map[string]string{{
							"message": fmt.Sprintf("query depth %d exceeds maximum allowed depth %d", depth, maxDepth),
						}},
					})
					return
				}
			}

			if m.cfg.Core.EnableTelemetry {
				span := trace.SpanFromContext(r.Context())
				if span.SpanContext().IsValid() {
					span.SetName("GraphQL " + operationName)
					span.SetAttributes(
						attribute.String("service", m.cfg.Core.ServiceName),
						attribute.String("transaction_id", transactionID),
						attribute.String("request_id", r.Header.Get(constants.HeaderRequestID)),
						attribute.String("ip", r.Header.Get(constants.HeaderIP)),
						attribute.String("ip_origin", r.Header.Get(constants.HeaderIPOrigin)),
						attribute.String("user_id", r.Header.Get(constants.HeaderUserID)),
						attribute.String("user_agent", r.UserAgent()),
						attribute.String("graphql.operation.name", operationName),
					)
					if gqlBody.Query != "" {
						span.SetAttributes(attribute.Int("graphql.query.depth", graphqlQueryDepth(gqlBody.Query)))
					}
				}
			}

			start := time.Now()
			rw = wrapResponseWriter(w, r, int(m.cfg.Logging.ResponseBodyLogLimitSize))

			IDAuditLog := cryptoutil.V7()
			entry := model.AuditLog{
				ID:              IDAuditLog,
				Method:          r.Method,
				FullURL:         FullURL(r),
				StatusCode:      0,
				LatencyMS:       0,
				IP:              r.Header.Get(constants.HeaderIP),
				IPOrigin:        r.Header.Get(constants.HeaderIPOrigin),
				RequestID:       r.Header.Get(constants.HeaderRequestID),
				CreatedBy:       format.ToInt64(r.Header.Get(constants.HeaderUserID)),
				CreatedAt:       format.NowUTC(),
				TransactionID:   transactionID,
				RequestHeaders:  normalizeHeadersJSON(r.Header, m.cfg.Logging.MaskKeywords),
				ResponseHeaders: nil,
				RequestBody:     gqlBody,
				ResponseBody:    nil,
				Protocol:        "GraphQL",
				ServiceName:     m.cfg.Core.ServiceName,
				UserAgent:       r.UserAgent(),
				ErrorMessage:    "",
			}

			reqCtx := context.WithoutCancel(r.Context())

			defer func() {
				status := rw.Status()
				if status == 0 {
					status = http.StatusInternalServerError
				}
				if m.cfg.Core.EnableTelemetry {
					span := trace.SpanFromContext(r.Context())
					if span.SpanContext().IsValid() && status >= 500 {
						span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", status))
					}
				}
				entry.StatusCode = status
				entry.LatencyMS = time.Since(start).Milliseconds()
				entry.ResponseHeaders = normalizeHeadersJSON(rw.Header(), m.cfg.Logging.MaskKeywords)
				if m.cfg.Logging.LogResponseBodies {
					entry.ResponseBody = normalizeBodyRaw(rw.Body(), m.cfg.Logging.MaskKeywords)
				}

				if err := m.cfg.LogStore.Save(reqCtx, &entry); err != nil {
					m.cfg.Logger.Error().
						Str("transaction_id", transactionID).
						Err(err).
						Msg("failed to save graphql audit log")
				}

				if rw != nil {
					rw.Free()
				}
			}()

			next.ServeHTTP(rw, r)
		})

		var handler http.Handler = coreHandler

		if m.cfg.Core.EnableTelemetry {
			handler = otelhttp.NewMiddleware(m.cfg.Core.ServiceName)(handler)
		}

		handler = m.TrustProxy(handler)

		return handler
	}
}

// graphqlQueryDepth returns a naive brace-depth count for the given GraphQL query string.
// It counts the maximum nesting level of `{` / `}` pairs, which is a safe approximation
// of field selection depth without full AST parsing.
func graphqlQueryDepth(query string) int {
	maxDepth, curDepth := 0, 0
	for _, ch := range query {
		switch ch {
		case '{':
			curDepth++
			if curDepth > maxDepth {
				maxDepth = curDepth
			}
		case '}':
			if curDepth > 0 {
				curDepth--
			}
		}
	}
	// Subtract 1: the outermost { } wrapper is not a field level
	return maxDepth - 1
}

// isGraphQLIntrospection reports whether the query appears to be a GraphQL introspection query.
// Useful for disabling introspection in production.
func isGraphQLIntrospection(query string) bool {
	q := strings.ToLower(strings.TrimSpace(query))
	return strings.Contains(q, "__schema") || strings.Contains(q, "__type")
}

// GraphQLBlockIntrospection is a middleware that rejects GraphQL introspection
// queries. Useful for hardening production endpoints.
func (m *Manager) GraphQLBlockIntrospection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			raw, err := ReadAndRestoreBody(r, m.cfg.Limits.RequestBodyNonFileLimitSize)
			if err == nil && len(raw) > 0 {
				var body graphqlRequestBody
				if sonic.Unmarshal(raw, &body) == nil && isGraphQLIntrospection(body.Query) {
					writeJSON(w, http.StatusForbidden, map[string]any{
						"errors": []map[string]string{{"message": "introspection disabled"}},
					})
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ResolveGraphQLOperation attempts to resolve the GraphQL operation name from
// the request header, query parameters, or body.
func ResolveGraphQLOperation(r *http.Request) string {
	if op := r.Header.Get("X-GraphQL-Operation"); op != "" {
		return op
	}
	if r.Method == http.MethodGet {
		if op := r.URL.Query().Get("operationName"); op != "" {
			return op
		}
	}
	if r.Method == http.MethodPost {
		// Limit reading to 32KB to avoid excessive overhead when parsing operation name
		raw, err := ReadAndRestoreBody(r, 32*1024)
		if err == nil && len(raw) > 0 {
			var body graphqlRequestBody
			if sonic.Unmarshal(raw, &body) == nil && body.OperationName != "" {
				return body.OperationName
			}
		}
	}
	return "anonymous"
}
