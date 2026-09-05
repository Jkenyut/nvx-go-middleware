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
	"github.com/Jkenyut/nvx-go-helper/response"
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
			r = WithActivityContext(r, &m.cfg.Headers.Keys)

			transactionID := r.Header.Get(m.cfg.Headers.Keys.TransactionID)
			if transactionID == "" {
				transactionID = cryptoutil.V7()
			}
			r.Header.Set(m.cfg.Headers.Keys.TransactionID, transactionID)
			r = r.WithContext(activity.WithTransactionID(r.Context(), transactionID))

			start := time.Now()
			rw := wrapResponseWriter(w, r, int(m.cfg.Logging.ResponseBodyLogLimitSize))

			IDAuditLog := cryptoutil.V7()
			var gqlBody graphqlRequestBody

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
				RequestBody:     nil,
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
				entry.RequestBody = gqlBody
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
						Str("request_id", r.Header.Get(m.cfg.Headers.Keys.RequestID)).
						Str("ip", r.Header.Get(m.cfg.Headers.Keys.IP)).
						Str("ip_origin", r.Header.Get(m.cfg.Headers.Keys.IPOrigin)).
						Str("user_id", r.Header.Get(m.cfg.Headers.Keys.UserID)).
						Str("user_agent", r.UserAgent()).
						Interface("panic", rec).
						Msg("panic in GraphQL handler")

					// Abort if response already started
					if rw.Status() != 0 {
						return
					}

					response.WriteJSONResponse(rw, response.InternalError(r.Context()))
				}
			}()

			// ── Operation name extraction ─────────────────────────────
			operationName := r.Header.Get("X-GraphQL-Operation")
			if r.Method == http.MethodPost {
				raw, err := ReadAndRestoreBody(r, m.cfg.Limits.RequestBodyNonFileLimitSize)
				if err == nil && len(raw) > 0 {
					_ = sonic.Unmarshal(raw, &gqlBody)
				}
				if operationName == "" && gqlBody.OperationName != "" {
					operationName = gqlBody.OperationName
				}
			} else if r.Method == http.MethodGet && operationName == "" {
				if op := r.URL.Query().Get("operationName"); op != "" {
					operationName = op
				}
			}
			if operationName == "" {
				operationName = "anonymous"
			}
			r.Header.Set("X-GraphQL-Operation", operationName)

			// ── Depth limiting (evaluate once) ────────────────────────
			queryDepth := 0
			if gqlBody.Query != "" {
				queryDepth = graphqlQueryDepth(gqlBody.Query)
				if maxDepth > 0 && queryDepth > maxDepth {
					response.WriteJSONResponse(rw, response.BadRequest(r.Context(), fmt.Sprintf("query depth %d exceeds maximum allowed depth %d", queryDepth, maxDepth)))
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
						attribute.String("request_id", r.Header.Get(m.cfg.Headers.Keys.RequestID)),
						attribute.String("ip", r.Header.Get(m.cfg.Headers.Keys.IP)),
						attribute.String("ip_origin", r.Header.Get(m.cfg.Headers.Keys.IPOrigin)),
						attribute.String("user_id", r.Header.Get(m.cfg.Headers.Keys.UserID)),
						attribute.String("user_agent", r.UserAgent()),
						attribute.String("graphql.operation.name", operationName),
					)
					if gqlBody.Query != "" {
						span.SetAttributes(attribute.Int("graphql.query.depth", queryDepth))
					}
				}
			}

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

// graphqlQueryDepth returns a brace-depth count for the given GraphQL query string.
// It counts the maximum nesting level of `{` / `}` pairs while ignoring characters
// inside string literals and single-line comments (#), providing a safe approximation
// of field selection depth without requiring full AST parsing.
func graphqlQueryDepth(query string) int {
	maxDepth, curDepth := 0, 0
	inString := false
	inComment := false
	escaped := false

	for _, ch := range query {
		if inComment {
			if ch == '\n' || ch == '\r' {
				inComment = false
			}
			continue
		}
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}

		switch ch {
		case '#':
			inComment = true
		case '"':
			inString = true
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
	if maxDepth <= 1 {
		return 0
	}
	return maxDepth - 1
}

// isGraphQLIntrospection reports whether the query appears to be a GraphQL introspection query.
// Useful for disabling introspection in production.
func isGraphQLIntrospection(query string) bool {
	q := strings.ToLower(strings.TrimSpace(query))
	return strings.Contains(q, "__schema") || strings.Contains(q, "__type")
}

// GraphQLBlockIntrospection is a middleware that rejects GraphQL introspection
// queries (both POST bodies and GET query parameters). Useful for hardening production endpoints.
func (m *Manager) GraphQLBlockIntrospection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			raw, err := ReadAndRestoreBody(r, m.cfg.Limits.RequestBodyNonFileLimitSize)
			if err == nil && len(raw) > 0 {
				var body graphqlRequestBody
				if sonic.Unmarshal(raw, &body) == nil && isGraphQLIntrospection(body.Query) {
					response.WriteJSONResponse(w, response.Forbidden(r.Context(), "introspection disabled"))
					return
				}
			}
		case http.MethodGet:
			if query := r.URL.Query().Get("query"); query != "" && isGraphQLIntrospection(query) {
				response.WriteJSONResponse(w, response.Forbidden(r.Context(), "introspection disabled"))
				return
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
