package middleware

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Jkenyut/nvx-go-helper/activity"
	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-helper/format"
	"github.com/Jkenyut/nvx-go-helper/response"
	"github.com/Jkenyut/nvx-go-helper/validator"
	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/Jkenyut/nvx-go-middleware/model"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/bytedance/sonic"
)

// Recoverer recovers from panics, logs the panic with a stack trace,
// and returns HTTP 500 if a response has not yet been written.
func (m *Manager) Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = activity.WithRequestID(ctx, r.Header.Get(constants.HeaderRequestID))
		r = r.WithContext(ctx)

		defer func() {
			if rec := recover(); rec != nil {
				stack := string(debug.Stack())
				m.cfg.Logger.Error().
					Str("service", m.cfg.ServiceName).
					Str("request_id", r.Header.Get(constants.HeaderRequestID)).
					Str("error", fmt.Sprintf("%v", rec)).
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Str("remote_addr", r.RemoteAddr).
					Msgf("panic recovered:\n%s", stack)

				if m.cfg.EnableTelemetry {
					span := trace.SpanFromContext(r.Context())
					span.RecordError(fmt.Errorf("panic: %v", rec))
					span.SetStatus(codes.Error, "panic recovered")
				}

				// Abort if response already started
				if ww, ok := w.(chimiddleware.WrapResponseWriter); ok && ww.Status() != 0 {
					m.cfg.Logger.Error().
						Str("service", m.cfg.ServiceName).
						Str("request_id", r.Header.Get(constants.HeaderRequestID)).
						Msg("response already written, cannot recover")
					return
				}
				if rw, ok := w.(*responseRecorder); ok && rw.Status() != 0 {
					m.cfg.Logger.Error().
						Str("service", m.cfg.ServiceName).
						Str("request_id", r.Header.Get(constants.HeaderRequestID)).
						Msg("response already written, cannot recover")
					return
				}

				writeJSON(w, http.StatusInternalServerError, response.InternalError(r.Context()))
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// Logger logs each request and its response, capturing method, URL, status code,
// latency, headers, and optionally request/response bodies. Audit entries are
// persisted asynchronously via the configured LogStore.
func (m *Manager) Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rw *responseRecorder
		if existingRw, ok := w.(*responseRecorder); ok {
			rw = existingRw
		} else {
			rw = wrapResponseWriter(w, r, int(m.cfg.ResponseBodyLogLimitSize))
		}

		IDAuditLog := cryptoutil.V7()

		// Generate or propagate Transaction ID
		transactionID := r.Header.Get(constants.HeaderTransactionID)
		if transactionID == "" {
			transactionID = cryptoutil.V7()
			rw.Header().Set(constants.HeaderTransactionID, transactionID)
			r.Header.Set(constants.HeaderTransactionID, transactionID)
		}

		if m.cfg.EnableTelemetry {
			span := trace.SpanFromContext(r.Context())
			span.SetAttributes(
				attribute.String("nvx.transaction_id", transactionID),
				attribute.String("nvx.request_id", r.Header.Get(constants.HeaderRequestID)),
				attribute.String("nvx.client_ip", r.Header.Get(constants.HeaderIP)),
				attribute.String("nvx.user_id", r.Header.Get(constants.HeaderUserID)),
			)
		}

		// Context injection
		r = WithActivityContext(r)

		if m.cfg.ContextInjector != nil {
			r = m.cfg.ContextInjector(r)
		}

		start := time.Now()
		requestHeadersBytes := normalizeHeadersJSON(r.Header)

		var reqBodyBytes any
		if m.cfg.LogRequestBodies {
			raw, err := ReadAndRestoreBody(r, m.cfg.RequestBodyNonFileLimitSize)
			if err != nil {
				m.cfg.Logger.Error().
					Str("service", m.cfg.ServiceName).
					Str("request_id", r.Header.Get(constants.HeaderRequestID)).
					Str("transaction_id", transactionID).
					Err(err).
					Msg("failed to read request body")
				writeJSON(rw, http.StatusBadRequest, response.BadRequest(r.Context(), constants.ErrMsgUnsupportedContentType))
				if rw != nil {
					rw.Free()
				}
				return
			}
			reqBodyBytes = normalizeBodyRaw(raw)
		}

		// Ensure cleanup and logging ALWAYS happens, even on panics.
		defer func() {
			var resBodyBytes any
			if m.cfg.LogResponseBodies {
				resBodyBytes = normalizeBodyRaw(rw.Body())
			}

			// Capture status after returning from next.ServeHTTP or panicking
			status := rw.Status()
			if status == 0 {
				status = http.StatusInternalServerError
			}

			entry := model.AuditLog{
				ID:              IDAuditLog,
				Method:          r.Method,
				FullURL:         FullURL(r),
				StatusCode:      status,
				LatencyMS:       time.Since(start).Milliseconds(),
				ClientIP:        r.Header.Get(constants.HeaderIP),
				RequestID:       r.Header.Get(constants.HeaderRequestID),
				CreatedBy:       format.ToInt64(r.Header.Get(constants.HeaderUserID)),
				CreatedAt:       format.NowUTC(),
				TransactionID:   transactionID,
				RequestHeaders:  requestHeadersBytes,
				ResponseHeaders: normalizeHeadersJSON(rw.Header()),
				RequestBody:     reqBodyBytes,
				ResponseBody:    resBodyBytes,
				Protocol:        "HTTP " + r.Proto,
				ServiceName:     m.cfg.ServiceName,
				UserAgent:       r.UserAgent(),
				ErrorMessage:    "",
			}

			if err := m.cfg.LogStore.Save(r.Context(), &entry); err != nil {
				m.cfg.Logger.Error().
					Str("service", m.cfg.ServiceName).
					Str("request_id", r.Header.Get(constants.HeaderRequestID)).
					Str("transaction_id", transactionID).
					Err(err).
					Msg("failed to save audit log")
			}

			if rw != nil {
				rw.Free()
			}
		}()

		next.ServeHTTP(rw, r)
	})
}

// normalizeBodyRaw returns a JSON-parsed value for valid JSON input,
// a plain string for non-JSON input, or nil for empty input.
func normalizeBodyRaw(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	if sonic.ConfigDefault.Valid(raw) {
		var v any
		if err := sonic.ConfigDefault.Unmarshal(raw, &v); err == nil {
			return v
		}
	}
	return string(raw)
}

// normalizeHeadersJSON serializes HTTP headers to a JSON object.
// Single-value headers are stored as strings; multi-value headers as arrays.
func normalizeHeadersJSON(h http.Header) []byte {
	out := make(map[string]any, len(h))
	for k, v := range h {
		if len(v) == 1 {
			out[k] = v[0]
		} else {
			out[k] = v
		}
	}
	b, _ := sonic.ConfigDefault.Marshal(out)
	return b
}

// SecureHeaders adds a configured set of security-related response headers
// (e.g., X-Content-Type-Options, X-Frame-Options, HSTS).
func (m *Manager) SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, value := range m.cfg.SecurityHeaders {
			w.Header().Set(key, value)
		}
		next.ServeHTTP(w, r)
	})
}

// RemoveHeaders strips configured response headers before the response reaches the client.
// Useful for removing Server, X-Powered-By, and similar fingerprinting headers.
func (m *Manager) RemoveHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(m.cfg.HeadersToRemove) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		rw := &headerCleanerResponseWriter{
			ResponseWriter:  w,
			headersToRemove: m.cfg.HeadersToRemove,
		}
		next.ServeHTTP(rw, r)
	})
}

// headerCleanerResponseWriter strips specified headers when WriteHeader is called.
type headerCleanerResponseWriter struct {
	http.ResponseWriter
	headersToRemove []string
	cleaned         bool
}

func (w *headerCleanerResponseWriter) WriteHeader(statusCode int) {
	if !w.cleaned {
		for _, h := range w.headersToRemove {
			w.ResponseWriter.Header().Del(h)
		}
		w.cleaned = true
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

// EnsureInternal validates that headers required for internal service-to-service
// communication are present and that the request signature is valid.
func (m *Manager) EnsureInternal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.validateHeaders(w, r, m.cfg.RequiredInternalHeaders) {
			return
		}

		tokenString := r.Header.Get(constants.HeaderToken)
		if tokenString == "" {
			writeJSON(w, http.StatusUnauthorized, response.Unauthorized(r.Context(), constants.ErrMsgInvalidToken))
			return
		}

		if validSignature, signatureServer := m.validateSignatureInternalHeaders(r); !validSignature {
			errMsg := constants.ErrMsgInvalidSignature
			if !m.envProd() {
				errMsg = fmt.Sprintf("%s - expected: %s", constants.ErrMsgInvalidSignature, signatureServer)
			}
			writeJSON(w, http.StatusUnauthorized, response.Unauthorized(r.Context(), errMsg))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// EnsurePublicAuth validates headers required for authenticated public requests
// (e.g., a logged-in user calling a mobile app endpoint).
// It checks header presence, timestamp validity, and request signature.
func (m *Manager) EnsurePublicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.validateHeaders(w, r, m.cfg.RequiredPublicAuthHeaders) {
			return
		}
		if err := checkTimestamp(r.Header.Get(constants.HeaderTimestamp), m.cfg.SignatureTimestampExpired); err != nil {
			writeJSON(w, http.StatusBadRequest, response.BadRequest(r.Context(), constants.ErrMsgInvalidSignature))
			return
		}
		if validSignature, signatureServer := m.validateSignaturePublicHeaders(r); !validSignature {
			errMsg := constants.ErrMsgSignatureInvalid
			if !m.envProd() {
				errMsg = fmt.Sprintf("%s - expected: %s", constants.ErrMsgSignatureInvalid, signatureServer)
			}
			writeJSON(w, http.StatusUnauthorized, response.Unauthorized(r.Context(), errMsg))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// EnsurePublic validates headers required for unauthenticated public requests.
// It checks header presence, timestamp validity, and request signature.
func (m *Manager) EnsurePublic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.validateHeaders(w, r, m.cfg.RequiredPublicHeaders) {
			return
		}
		if err := checkTimestamp(r.Header.Get(constants.HeaderTimestamp), m.cfg.SignatureTimestampExpired); err != nil {
			writeJSON(w, http.StatusBadRequest, response.BadRequest(r.Context(), constants.ErrMsgInvalidSignature))
			return
		}
		if validSignature, signatureServer := m.validateSignaturePublicHeaders(r); !validSignature {
			errMsg := constants.ErrMsgSignatureInvalid
			if !m.envProd() {
				errMsg = fmt.Sprintf("%s - expected: %s", constants.ErrMsgSignatureInvalid, signatureServer)
			}
			writeJSON(w, http.StatusUnauthorized, response.Unauthorized(r.Context(), errMsg))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// EnsurePublicAPIKey validates headers required for API-key authenticated public requests.
// It checks header presence, timestamp validity, and request signature.
func (m *Manager) EnsurePublicAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.validateHeaders(w, r, m.cfg.RequiredPublicAPIKeyHeaders) {
			return
		}
		if err := checkTimestamp(r.Header.Get(constants.HeaderTimestamp), m.cfg.SignatureTimestampExpired); err != nil {
			writeJSON(w, http.StatusBadRequest, response.BadRequest(r.Context(), constants.ErrMsgInvalidSignature))
			return
		}
		if validSignature, signatureServer := m.validateSignaturePublicHeaders(r); !validSignature {
			errMsg := constants.ErrMsgSignatureInvalid
			if !m.envProd() {
				errMsg = fmt.Sprintf("%s - expected: %s", constants.ErrMsgSignatureInvalid, signatureServer)
			}
			writeJSON(w, http.StatusUnauthorized, response.Unauthorized(r.Context(), errMsg))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// validateHeaders checks that all required headers are non-empty.
// Additionally validates the NVX-Timestamp and NVX-Platform headers.
// Returns false and writes an error response if any validation fails.
func (m *Manager) validateHeaders(w http.ResponseWriter, r *http.Request, headers []string) bool {
	var missing []string
	for _, header := range headers {
		if r.Header.Get(header) == "" {
			missing = append(missing, header)
		}
	}
	if len(missing) > 0 {
		message := constants.ErrMsgMissingHeaders
		if !m.envProd() {
			message = fmt.Sprintf("%s: %s", constants.ErrMsgMissingHeaders, strings.Join(missing, ", "))
		}
		writeJSON(w, http.StatusBadRequest, response.BadRequest(r.Context(), message))
		return false
	}

	// Validate timestamp (only if the header is present — internal routes may omit it)
	if ts := r.Header.Get(constants.HeaderTimestamp); ts != "" {
		if format.StringToUnixOrZero(ts).IsZero() {
			writeJSON(w, http.StatusBadRequest, response.BadRequest(r.Context(), constants.ErrMsgInvalidTimestamp))
			return false
		}
	}

	// Validate platform
	platform := r.Header.Get(constants.HeaderPlatform)
	if platform != "" {
		valid := false
		for _, v := range constants.CheckPlatform {
			if platform == v {
				valid = true
				break
			}
		}
		if !valid {
			writeJSON(w, http.StatusBadRequest, response.BadRequest(r.Context(), constants.ErrMsgInvalidPlatform))
			return false
		}
	}

	return true
}

// validateSignatureInternalHeaders assembles the internal signature canonical string
// from the configured signature headers and delegates to validateSignatureHeaders.
func (m *Manager) validateSignatureInternalHeaders(r *http.Request) (valid bool, signature string) {
	authHeaders := make([]string, 0, len(m.cfg.RequiredSignatureInternalHeaders))
	for _, name := range m.cfg.RequiredSignatureInternalHeaders {
		authHeaders = append(authHeaders, r.Header.Get(name))
	}
	return m.validateSignatureHeaders(r, m.cfg.PrivateKeySignature, authHeaders)
}

// validateSignaturePublicHeaders assembles the public signature canonical string
// (method + URI + configured headers + body token) and delegates to validateSignatureHeaders.
func (m *Manager) validateSignaturePublicHeaders(r *http.Request) (valid bool, signature string) {
	parts := make([]string, 0, len(m.cfg.RequiredSignaturePublicHeaders)+3)
	parts = append(parts, strings.ToUpper(r.Method), r.RequestURI)
	for _, name := range m.cfg.RequiredSignaturePublicHeaders {
		parts = append(parts, r.Header.Get(name))
	}

	bodyBytes, err := ReadAndRestoreBody(r, m.cfg.RequestBodyNonFileLimitSize)
	if err != nil {
		m.cfg.Logger.Error().
			Str("service", m.cfg.ServiceName).
			Str("request_id", r.Header.Get(constants.HeaderRequestID)).
			Err(err).
			Msg("failed to read request body for signature validation")
		return false, err.Error()
	}
	parts = append(parts, ResolveBodyToken(r.Header.Get("Content-Type"), bodyBytes))

	return m.validateSignatureHeaders(r, m.cfg.PublicKeySignature, parts)
}

// validateSignatureHeaders computes the expected HMAC signature and compares it
// against the NVX-Signature header using constant-time comparison.
func (m *Manager) validateSignatureHeaders(r *http.Request, key string, values []string) (valid bool, signature string) {
	signatureServer := cryptoutil.Signature(key, values...)
	clientSignature := r.Header.Get(constants.HeaderSignature)

	if clientSignature == "" || len(clientSignature) != len(signatureServer) {
		return false, signatureServer
	}
	return subtle.ConstantTimeCompare([]byte(clientSignature), []byte(signatureServer)) == 1, signatureServer
}

// TrustProxy extracts the real client IP from X-Forwarded-For when the
// direct connection comes from a configured trusted proxy (IP or CIDR).
// It updates r.RemoteAddr and sets the NVX-IP header so downstream handlers
// see the real client address.
func (m *Manager) TrustProxy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteIP = r.RemoteAddr
		}

		isTrusted := m.isTrustedIP(remoteIP)

		clientIP := remoteIP
		if isTrusted {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				// Read from right to left to avoid IP spoofing
				for i := len(parts) - 1; i >= 0; i-- {
					ipStr := strings.TrimSpace(parts[i])
					if !m.isTrustedIP(ipStr) {
						clientIP = ipStr
						break
					}
				}
				// Fallback to leftmost if all are trusted proxies or couldn't find untrusted
				if clientIP == "" && len(parts) > 0 {
					clientIP = strings.TrimSpace(parts[0])
				}
			}
		}
		if net.ParseIP(clientIP) == nil {
			clientIP = remoteIP
		}

		r.Header.Set(constants.HeaderIP, clientIP)
		if clientIP != remoteIP {
			r.RemoteAddr = net.JoinHostPort(clientIP, "0")
		}

		next.ServeHTTP(w, r)
	})
}

// isMultipart reports whether the Content-Type indicates a multipart/form-data body.
func isMultipart(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(contentType), "multipart/")
}

// isTrustedIP checks if a given IP string is in the trusted proxies list.
func (m *Manager) isTrustedIP(ipStr string) bool {
	for _, proxy := range m.cfg.TrustedProxies {
		if proxy == ipStr {
			return true
		}
		if _, ipNet, err := net.ParseCIDR(proxy); err == nil {
			if ip := net.ParseIP(ipStr); ip != nil && ipNet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// MaxBodySize returns a middleware that limits the maximum size of the request body.
// It also restricts the allowed Content-Types based on the configuration.
// MaxBodySize returns a middleware that limits the size of the request body.
// It supports different limits for file uploads (multipart) vs regular requests.
// It also enforces allowed content types.
func (m *Manager) MaxBodySize() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contentType := r.Header.Get("Content-Type")

			// Allow bodyless requests (e.g. GET)
			if contentType == "" && r.ContentLength == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Validate Content-Type
			isAllowed := false
			for _, allowed := range m.cfg.AllowedContentTypes {
				if strings.Contains(contentType, allowed) {
					isAllowed = true
					break
				}
			}
			if !isAllowed {
				writeJSON(w, http.StatusBadRequest, response.BadRequest(r.Context(), constants.ErrMsgUnsupportedContentType))
				return
			}

			// File upload: apply overall limit only
			if isMultipart(contentType) {
				if r.ContentLength > m.cfg.RequestBodyLimitSize {
					writeJSON(w, http.StatusRequestEntityTooLarge, response.PayloadTooLarge(r.Context(), constants.ErrMsgPayloadTooLarge))
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, m.cfg.RequestBodyLimitSize)
				next.ServeHTTP(w, r)
				return
			}

			// Non-file: apply tighter non-file limit
			if r.ContentLength > m.cfg.RequestBodyNonFileLimitSize {
				writeJSON(w, http.StatusRequestEntityTooLarge, response.PayloadTooLarge(r.Context(), constants.ErrMsgPayloadTooLarge))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, m.cfg.RequestBodyNonFileLimitSize)
			next.ServeHTTP(w, r)
		})
	}
}

// CORS sets Cross-Origin Resource Sharing response headers.
// It validates the request Origin against the allowedOrigins list,
// handles OPTIONS preflight requests, and sets CORS headers accordingly.
func (m *Manager) CORS(
	next http.Handler,
	allowedOrigins []string,
	allowedHeaders []string,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		allowed := false
		for _, o := range allowedOrigins {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
		w.Header().Set("Access-Control-Max-Age", "3600")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// FullURL reconstructs the full request URL, respecting X-Forwarded-Proto and
// X-Forwarded-Host. The scheme is restricted to http/https to prevent injection.
func FullURL(r *http.Request) string {
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "https" {
		scheme = "https"
	} else if r.TLS != nil {
		scheme = "https"
	}

	host := r.Host
	if xfHost := r.Header.Get("X-Forwarded-Host"); xfHost != "" {
		// Use only the first host to guard against header injection
		host = strings.SplitN(xfHost, ",", 2)[0]
		host = strings.TrimSpace(host)
	}

	return scheme + "://" + host + r.RequestURI
}

// ReadAndRestoreBody reads the request body up to limit bytes and then restores
// it so subsequent handlers can read it again. Returns nil for nil or multipart bodies.
func ReadAndRestoreBody(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	if isMultipart(r.Header.Get("Content-Type")) {
		return nil, nil
	}

	limitReader := io.LimitReader(r.Body, limit+1)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	if int64(len(bodyBytes)) > limit {
		return nil, fmt.Errorf("request body exceeds limit of %d bytes", limit)
	}

	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes, nil
}

// MethodOnly restricts the handler to a single HTTP method.
// Requests with a different method receive 405 Method Not Allowed.
func (m *Manager) MethodOnly(method string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			writeJSON(w, http.StatusMethodNotAllowed, response.MethodNotAllowed(r.Context(), constants.ErrMsgMethodNotAllowed))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ResolveBodyToken computes a canonical body token for use in signature generation.
//   - Multipart bodies → "UNSIGNED"
//   - Empty bodies     → "EMPTY"
//   - All others       → hex-encoded SHA-256 of the raw body
func ResolveBodyToken(contentType string, body []byte) string {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if strings.HasPrefix(ct, "multipart/") {
		return "UNSIGNED"
	}
	if len(body) == 0 {
		return "EMPTY"
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// EnsurePreSignHeaders validates that the headers required for presigned request
// generation are present.
func (m *Manager) EnsurePreSignHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.validateHeaders(w, r, m.cfg.RequiredSignaturePublicHeaders) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// PreSignHandler creates a POST endpoint that generates a presigned signature
// for a described request. The caller supplies method, URI, and body hash;
// the handler returns the HMAC signature the caller should include as NVX-Signature.
func (m *Manager) PreSignHandler(cfg *ChainConfig) http.Handler {
	return m.MethodOnly("POST", m.PreSignChain(cfg)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			var req model.PresignRequest
			if err := sonic.ConfigDefault.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, response.BadRequest(r.Context(), constants.ErrMsgInvalidRequest))
				return
			}

			if err := validator.Struct(req); err != nil {
				writeJSON(w, http.StatusBadRequest, response.BadRequest(r.Context(), validator.GetErrorsFullStr(err)))
				return
			}

			if err := checkTimestamp(r.Header.Get(constants.HeaderTimestamp), m.cfg.SignatureTimestampExpired); err != nil {
				writeJSON(w, http.StatusBadRequest, response.BadRequest(r.Context(), constants.ErrMsgInvalidSignature))
				return
			}

			canonical := make([]string, 0, len(m.cfg.RequiredSignaturePublicHeaders)+3)
			canonical = append(canonical, strings.ToUpper(req.Method), req.URI)
			for _, name := range m.cfg.RequiredSignaturePublicHeaders {
				canonical = append(canonical, r.Header.Get(name))
			}
			canonical = append(canonical, req.Body)

			writeJSON(w, http.StatusOK, response.Success(r.Context(), model.PresignResponse{
				Signature: cryptoutil.Signature(m.cfg.PublicKeySignature, canonical...),
			}))
		})))
}

// checkTimestamp validates that the given Unix timestamp string is within
// ±allowedSkewSec of the current UTC time.
func checkTimestamp(timestampStr string, allowedSkewSec int64) error {
	ts := format.StringToUnixOrZero(timestampStr)
	if ts.IsZero() {
		return errors.New(constants.ErrMsgInvalidSignature)
	}
	now := format.NowUTC()
	skew := time.Duration(allowedSkewSec) * time.Second
	if ts.Before(now.Add(-skew)) || ts.After(now.Add(skew)) {
		return errors.New(constants.ErrMsgInvalidSignature)
	}
	return nil
}

// writeJSON is an internal helper that sets Content-Type, writes the status
// code, and encodes v as JSON using sonic. Encode errors are silently ignored
// because the status code has already been committed.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = sonic.ConfigDefault.NewEncoder(w).Encode(v)
}
