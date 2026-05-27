package middleware

import (
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
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ── TrustProxy ────────────────────────────────────────────
			m.TrustProxy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)

			// ── Context injection ─────────────────────────────────────
			r = WithActivityContext(r)

			transactionID := r.Header.Get(constants.HeaderTransactionID)
			if transactionID == "" {
				transactionID = cryptoutil.V7()
			}
			r.Header.Set(constants.HeaderTransactionID, transactionID)
			r = r.WithContext(activity.WithTransactionID(r.Context(), transactionID))

			// ── Panic recovery ────────────────────────────────────────
			defer func() {
				if rec := recover(); rec != nil {
					m.cfg.Logger.Error().
						Str("service", m.cfg.ServiceName).
						Str("transaction_id", transactionID).
						Interface("panic", rec).
						Msg("panic in GraphQL handler")
					writeJSON(w, http.StatusInternalServerError, map[string]any{
						"errors": []map[string]string{{"message": "internal server error"}},
					})
				}
			}()

			// ── Operation name extraction ─────────────────────────────
			var gqlBody graphqlRequestBody
			if r.Method == http.MethodPost {
				raw, err := ReadAndRestoreBody(r, m.cfg.RequestBodyNonFileLimitSize)
				if err == nil && len(raw) > 0 {
					_ = sonic.Unmarshal(raw, &gqlBody)
				}
			}

			operationName := gqlBody.OperationName
			if operationName == "" {
				operationName = "anonymous"
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

			start := time.Now()
			rw := wrapResponseWriter(w, r, int(m.cfg.ResponseBodyLogLimitSize))

			IDAuditLog := cryptoutil.V7()
			entry := model.AuditLog{
				ID:              IDAuditLog,
				Method:          r.Method,
				FullURL:         FullURL(r),
				StatusCode:      0,
				LatencyMS:       0,
				ClientIP:        r.Header.Get(constants.HeaderIP),
				RequestID:       r.Header.Get(constants.HeaderRequestID),
				CreatedBy:       format.ToInt64(r.Header.Get(constants.HeaderUserID)),
				CreatedAt:       format.NowUTC(),
				TransactionID:   transactionID,
				RequestHeaders:  normalizeHeadersJSON(r.Header),
				ResponseHeaders: nil,
				RequestBody:     gqlBody,
				ResponseBody:    nil,
				Protocol:        "GraphQL",
				ServiceName:     m.cfg.ServiceName,
				UserAgent:       r.UserAgent(),
				ErrorMessage:    "",
			}

			entryReq := entry
			go func() {
				defer func() {
					if rec := recover(); rec != nil {
						m.cfg.Logger.Error().Str("transaction_id", transactionID).Msg("panic in async graphql log save (request)")
					}
				}()
				_ = m.cfg.LogStore.Save(r.Context(), entryReq)
			}()

			next.ServeHTTP(rw, r)
			entry.StatusCode = rw.Status()

			entry.LatencyMS = int(time.Since(start).Milliseconds())
			entry.ResponseHeaders = normalizeHeadersJSON(rw.Header())
			if m.cfg.LogResponseBodies {
				entry.ResponseBody = normalizeBodyRaw(rw.body.Bytes())
			}

			go func() {
				defer func() {
					if rec := recover(); rec != nil {
						m.cfg.Logger.Error().Str("transaction_id", transactionID).Msg("panic in async graphql log save (response)")
					}
				}()
				_ = m.cfg.LogStore.Save(r.Context(), entry)
			}()
		})
	}
}

// graphqlQueryDepth returns a naive brace-depth count for the given GraphQL query string.
// It counts the maximum nesting level of `{` / `}` pairs, which is a safe approximation
// of field selection depth without full AST parsing.
func graphqlQueryDepth(query string) int {
	max, cur := 0, 0
	for _, ch := range query {
		switch ch {
		case '{':
			cur++
			if cur > max {
				max = cur
			}
		case '}':
			if cur > 0 {
				cur--
			}
		}
	}
	// Subtract 1: the outermost { } wrapper is not a field level
	return max - 1
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
			raw, err := ReadAndRestoreBody(r, m.cfg.RequestBodyNonFileLimitSize)
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
