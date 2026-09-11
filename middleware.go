package middleware

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/Jkenyut/nvx-go-helper/activity"
	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-helper/format"
	"github.com/Jkenyut/nvx-go-helper/response"
	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/Jkenyut/nvx-go-middleware/model"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
)

// Recoverer recovers from panics, logs the panic with a stack trace,
// and returns HTTP 500 if a response has not yet been written.
func (m *Manager) Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = activity.WithRequestID(ctx, r.Header.Get(m.cfg.Headers.Keys.RequestID))
		r = r.WithContext(ctx)

		defer func() {
			if rec := recover(); rec != nil {
				stack := string(debug.Stack())
				attrs := make([]slog.Attr, 0, 5+len(m.cfg.Logging.LogHeaders))
				attrs = append(attrs,
					slog.String("service", m.cfg.Core.ServiceName),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("user_agent", r.UserAgent()),
					slog.Any("panic", rec),
				)
				attrs = append(attrs, m.logHeadersAttrs(r)...)
				m.cfg.Logger.LogAttrs(r.Context(), slog.LevelError, fmt.Sprintf("panic recovered:\n%s", stack), attrs...)

				if m.cfg.Core.EnableTelemetry {
					span := trace.SpanFromContext(r.Context())
					span.RecordError(fmt.Errorf("panic: %v", rec))
					span.SetStatus(codes.Error, "panic recovered")
				}

				// Abort if response already started
				if sp, ok := w.(interface{ Status() int }); ok && sp.Status() != 0 {
					attrs := make([]slog.Attr, 0, 1+len(m.cfg.Logging.LogHeaders))
					attrs = append(attrs, slog.String("service", m.cfg.Core.ServiceName))
					attrs = append(attrs, m.logHeadersAttrs(r)...)
					m.cfg.Logger.LogAttrs(r.Context(), slog.LevelError, "response already written, cannot recover", attrs...)
					return
				}

				response.WriteJSONResponse(w, response.InternalError(r.Context()))
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
			rw = wrapResponseWriter(w, r, int(m.cfg.Logging.ResponseBodyLogLimitSize))
		}

		IDAuditLog := cryptoutil.V7()

		// Generate or propagate Transaction ID
		transactionID := r.Header.Get(m.cfg.Headers.Keys.TransactionID)
		if transactionID == "" {
			transactionID = cryptoutil.V7()
			rw.Header().Set(m.cfg.Headers.Keys.TransactionID, transactionID)
			r.Header.Set(m.cfg.Headers.Keys.TransactionID, transactionID)
		}

		if m.cfg.Core.EnableTelemetry {
			span := trace.SpanFromContext(r.Context())
			span.SetAttributes(
				attribute.String("service", m.cfg.Core.ServiceName),
				attribute.String("transaction_id", transactionID),
				attribute.String("request_id", r.Header.Get(m.cfg.Headers.Keys.RequestID)),
				attribute.String("ip", r.Header.Get(m.cfg.Headers.Keys.IP)),
				attribute.String("ip_origin", r.Header.Get(m.cfg.Headers.Keys.IPOrigin)),
				attribute.String("user_id", r.Header.Get(m.cfg.Headers.Keys.UserID)),
				attribute.String("user_agent", r.UserAgent()),
				attribute.String("path", r.URL.Path),
				attribute.String("protocol", "HTTP "+r.Proto),
				attribute.String("header_auth_type", r.Header.Get(m.cfg.Headers.Keys.AuthType)),
			)
		}

		// Context injection
		r = WithActivityContext(r, &m.cfg.Headers.Keys)

		if m.cfg.ContextInjector != nil {
			r = m.cfg.ContextInjector(r)
		}

		start := time.Now()
		requestHeadersBytes := normalizeHeadersJSON(r.Header, m.cfg.Logging.MaskKeywords)

		var reqBodyBytes any

		// Ensure cleanup and logging ALWAYS happens, even on panics or early error returns.
		defer func() {
			var resBodyBytes any
			if m.cfg.Logging.LogResponseBodies && isLoggableBody(rw.Header().Get("Content-Type")) {
				resBodyBytes = normalizeBodyRaw(rw.Body(), m.cfg.Logging.MaskKeywords)
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
				IP:              r.Header.Get(m.cfg.Headers.Keys.IP),
				IPOrigin:        r.Header.Get(m.cfg.Headers.Keys.IPOrigin),
				RequestID:       r.Header.Get(m.cfg.Headers.Keys.RequestID),
				CreatedBy:       format.ToInt64(r.Header.Get(m.cfg.Headers.Keys.UserID)),
				CreatedAt:       format.NowUTC(),
				TransactionID:   transactionID,
				RequestHeaders:  requestHeadersBytes,
				ResponseHeaders: normalizeHeadersJSON(rw.Header(), m.cfg.Logging.MaskKeywords),
				RequestBody:     reqBodyBytes,
				ResponseBody:    resBodyBytes,
				Protocol:        r.Proto,
				ServiceName:     m.cfg.Core.ServiceName,
				UserAgent:       r.UserAgent(),
				ErrorMessage:    "",
			}

			reqCtx := context.WithoutCancel(r.Context())
			if err := m.cfg.LogStore.Save(reqCtx, &entry); err != nil {
				attrs := make([]slog.Attr, 0, 7+len(m.cfg.Logging.LogHeaders))
				attrs = append(attrs,
					slog.String("service", m.cfg.Core.ServiceName),
					slog.String("transaction_id", transactionID),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("user_agent", r.UserAgent()),
					slog.String("protocol", "HTTP "+r.Proto),
					slog.Any("error", err),
				)
				attrs = append(attrs, m.logHeadersAttrs(r)...)
				m.cfg.Logger.LogAttrs(reqCtx, slog.LevelError, "failed to write audit log entry to store", attrs...)
			}

			if rw != nil {
				rw.Free()
			}
		}()

		if m.cfg.Logging.LogRequestBodies && isLoggableBody(r.Header.Get("Content-Type")) {
			raw, err := ReadAndRestoreBody(r, m.cfg.Limits.RequestBodyNonFileLimitSize)
			if err != nil {
				attrs := make([]slog.Attr, 0, 6+len(m.cfg.Logging.LogHeaders))
				attrs = append(attrs,
					slog.String("service", m.cfg.Core.ServiceName),
					slog.String("transaction_id", transactionID),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.String("user_agent", r.UserAgent()),
					slog.Any("error", err),
				)
				attrs = append(attrs, m.logHeadersAttrs(r)...)
				m.cfg.Logger.LogAttrs(r.Context(), slog.LevelError, "failed to read request body", attrs...)
				response.WriteJSONResponse(rw, response.BadRequest(r.Context(), constants.ErrMsgPayloadTooLarge))
				return
			}

			reqBodyBytes = normalizeBodyRaw(raw, m.cfg.Logging.MaskKeywords)
		}

		next.ServeHTTP(rw, r)
	})
}

// normalizeBodyRaw returns a JSON-parsed value for valid JSON input,
// a plain string for non-JSON input, or nil for empty input.
func normalizeBodyRaw(raw []byte, keywordList []string) any {
	if len(raw) == 0 {
		return nil
	}

	str := string(raw)

	if len(keywordList) > 0 {
		str = format.MaskAfterKeywords(str, keywordList, "*")
	}

	var v any
	if err := sonic.ConfigDefault.UnmarshalFromString(str, &v); err == nil {
		return v
	}
	return str
}

// normalizeHeadersJSON serializes HTTP headers to a JSON object.
// Single-value headers are stored as strings; multi-value headers as arrays.
func normalizeHeadersJSON(h http.Header, keywordList []string) []byte {
	out := make(map[string]any, len(h))
	for k, v := range h {
		if len(v) == 1 {
			out[k] = v[0]
		} else {
			out[k] = v
		}
	}
	b, _ := sonic.ConfigDefault.Marshal(out)
	str := format.MaskAfterKeywords(string(b), keywordList, "*")
	return []byte(str)
}

// RemoveHeaders strips configured response headers before the response reaches the client.
// Useful for removing Server, X-Powered-By, and similar fingerprinting headers.
func (m *Manager) RemoveHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(m.cfg.Security.HeadersToRemove) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		rw := &headerCleanerResponseWriter{
			ResponseWriter:  w,
			headersToRemove: m.cfg.Security.HeadersToRemove,
		}
		next.ServeHTTP(rw, r)
	})
}

// headerCleanerResponseWriter strips specified headers when response headers are written.
// It wraps standard http.ResponseWriter and preserves compatibility with Flusher, Hijacker,
// ReaderFrom, and Go 1.20+ ResponseController unwrap contracts.
type headerCleanerResponseWriter struct {
	http.ResponseWriter
	headersToRemove []string
	cleaned         bool
}

func (w *headerCleanerResponseWriter) cleanHeaders() {
	if !w.cleaned {
		for _, h := range w.headersToRemove {
			w.ResponseWriter.Header().Del(h)
		}
		w.cleaned = true
	}
}

func (w *headerCleanerResponseWriter) WriteHeader(statusCode int) {
	w.cleanHeaders()
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *headerCleanerResponseWriter) Write(b []byte) (int, error) {
	w.cleanHeaders()
	return w.ResponseWriter.Write(b)
}

// WriteString implements io.StringWriter to support zero-allocation string writing while ensuring headers are cleaned.
func (w *headerCleanerResponseWriter) WriteString(s string) (int, error) {
	w.cleanHeaders()
	if sw, ok := w.ResponseWriter.(io.StringWriter); ok {
		return sw.WriteString(s)
	}
	return w.ResponseWriter.Write([]byte(s))
}

func (w *headerCleanerResponseWriter) Flush() {
	w.cleanHeaders()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker to allow connection hijacking under RemoveHeaders.
func (w *headerCleanerResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.cleanHeaders()
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("underlying ResponseWriter does not implement http.Hijacker")
}

// ReadFrom implements io.ReaderFrom to support zero-copy transmission (e.g. sendfile) while ensuring headers are cleaned.
func (w *headerCleanerResponseWriter) ReadFrom(src io.Reader) (int64, error) {
	w.cleanHeaders()
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(w.ResponseWriter, src)
}

func (w *headerCleanerResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Status returns the response status code if the underlying writer tracks it.
func (w *headerCleanerResponseWriter) Status() int {
	if sp, ok := w.ResponseWriter.(interface{ Status() int }); ok {
		return sp.Status()
	}
	return 0
}

// BytesWritten returns the response bytes written if the underlying writer tracks it.
func (w *headerCleanerResponseWriter) BytesWritten() int {
	if bp, ok := w.ResponseWriter.(interface{ BytesWritten() int }); ok {
		return bp.BytesWritten()
	}
	return 0
}

// EnsureInternal validates that headers required for internal service-to-service
// communication are present and that the request signature is valid.
func (m *Manager) EnsureInternal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.validateHeaders(w, r, m.cfg.Headers.RequiredInternalHeaders) {
			return
		}

		if validSignature, signatureServer := m.validateSignatureInternalHeaders(r); !validSignature {
			errMsg := constants.ErrMsgInvalidSignature
			if !m.envProd() {
				errMsg = fmt.Sprintf("%s - expected: %s", constants.ErrMsgInvalidSignature, signatureServer)
			}
			response.WriteJSONResponse(w, response.Unauthorized(r.Context(), errMsg))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ensurePublicWithHeaders validates the given required headers, checks timestamp expiration,
// and verifies the public HMAC signature.
func (m *Manager) ensurePublicWithHeaders(headers []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.validateHeaders(w, r, headers) {
			return
		}
		if err := checkTimestamp(r.Header.Get(constants.HeaderTimestamp), m.cfg.Security.SignatureTimestampExpired); err != nil {
			errMsg := constants.ErrMsgInvalidSignature
			if !m.envProd() {
				errMsg = fmt.Sprintf("%s - Timestamp difference exceeds max allowed skew of %d seconds", constants.ErrMsgInvalidSignature, m.cfg.Security.SignatureTimestampExpired)
			}
			response.WriteJSONResponse(w, response.BadRequest(r.Context(), errMsg))
			return
		}
		
		if validSignature, signatureServer := m.validateSignaturePublicHeaders(r); !validSignature {
			errMsg := constants.ErrMsgInvalidSignature
			if !m.envProd() {
				errMsg = fmt.Sprintf("%s - expected: %s", constants.ErrMsgInvalidSignature, signatureServer)
			}
			response.WriteJSONResponse(w, response.Unauthorized(r.Context(), errMsg))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// EnsurePublicAuth validates headers required for authenticated public requests
// (e.g., a logged-in user calling a mobile app endpoint).
// It checks header presence, timestamp validity, and request signature.
func (m *Manager) EnsurePublicAuth(next http.Handler) http.Handler {
	return m.ensurePublicWithHeaders(m.cfg.Headers.RequiredPublicAuthHeaders, next)
}

// EnsurePublic validates headers required for unauthenticated public requests.
// It checks header presence, timestamp validity, and request signature.
func (m *Manager) EnsurePublic(next http.Handler) http.Handler {
	return m.ensurePublicWithHeaders(m.cfg.Headers.RequiredPublicHeaders, next)
}

// EnsurePublicAPIKey validates headers required for API-key authenticated public requests.
// It checks header presence, timestamp validity, and request signature.
func (m *Manager) EnsurePublicAPIKey(next http.Handler) http.Handler {
	return m.ensurePublicWithHeaders(m.cfg.Headers.RequiredPublicAPIKeyHeaders, next)
}

// validateHeaders checks that all required headers are non-empty.
// Additionally validates the Timestamp and Platform headers.
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
		response.WriteJSONResponse(w, response.BadRequest(r.Context(), message))
		return false
	}

	// Validate timestamp (only if the header is present — internal routes may omit it)
	if ts := r.Header.Get(constants.HeaderTimestamp); ts != "" {
		if format.StringToUnixOrZero(ts).IsZero() {
			response.WriteJSONResponse(w, response.BadRequest(r.Context(), constants.ErrMsgInvalidTimestamp))
			return false
		}
	}

	// Validate platform
	platform := r.Header.Get(constants.HeaderPlatform)
	if platform != "" && !slices.Contains(constants.CheckPlatform, platform) {
		response.WriteJSONResponse(w, response.BadRequest(r.Context(), constants.ErrMsgInvalidPlatform))
		return false
	}

	return true
}

// validateSignatureInternalHeaders assembles the internal signature canonical string
// from the configured signature headers and delegates to validateSignatureHeaders.
func (m *Manager) validateSignatureInternalHeaders(r *http.Request) (valid bool, signature string) {
	authHeaders := make([]string, 0, len(m.cfg.Headers.RequiredSignatureInternalHeaders))
	for _, name := range m.cfg.Headers.RequiredSignatureInternalHeaders {
		authHeaders = append(authHeaders, r.Header.Get(name))
	}
	return m.validateSignatureHeaders(r, m.cfg.Security.PrivateKeySignature, authHeaders)
}

// validateSignaturePublicHeaders assembles the public signature canonical string
// (method + URI + configured headers + body token) and delegates to validateSignatureHeaders.
func (m *Manager) validateSignaturePublicHeaders(r *http.Request) (valid bool, signature string) {
	parts := make([]string, 0, len(m.cfg.Headers.RequiredSignaturePublicHeaders)+3)
	uri := r.RequestURI
	if uri == "" && r.URL != nil {
		uri = r.URL.RequestURI()
	}
	parts = append(parts, strings.ToUpper(r.Method), uri)
	for _, name := range m.cfg.Headers.RequiredSignaturePublicHeaders {
		parts = append(parts, r.Header.Get(name))
	}

	bodyBytes, err := ReadAndRestoreBody(r, m.cfg.Limits.RequestBodyNonFileLimitSize)
	if err != nil {
		attrs := make([]slog.Attr, 0, 2+len(m.cfg.Logging.LogHeaders))
		attrs = append(attrs,
			slog.String("service", m.cfg.Core.ServiceName),
			slog.Any("error", err),
		)
		attrs = append(attrs, m.logHeadersAttrs(r)...)
		m.cfg.Logger.LogAttrs(r.Context(), slog.LevelError, "failed to read request body for signature validation", attrs...)
		return false, err.Error()
	}
	parts = append(parts, ResolveBodyToken(r.Header.Get("Content-Type"), bodyBytes))

	return m.validateSignatureHeaders(r, m.cfg.Security.PublicKeySignature, parts)
}

// validateSignatureHeaders computes the expected HMAC signature and compares it
// against the Signature header using constant-time comparison.
func (m *Manager) validateSignatureHeaders(r *http.Request, key string, values []string) (valid bool, signature string) {
	signatureServer := cryptoutil.Signature(key, values...)
	clientSignature := r.Header.Get(constants.HeaderSignature)

	if clientSignature == "" || len(clientSignature) != len(signatureServer) {
		return false, signatureServer
	}
	return subtle.ConstantTimeCompare([]byte(clientSignature), []byte(signatureServer)) == 1, signatureServer
}

// isPrivateIP checks if an IP is a private/loopback/link-local address (Docker network, localhost, LAN).
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// isTrustedIP checks if a given IP string is in the trusted proxies list or belongs
// to standard private/loopback networks (e.g. Docker network, Kubernetes pod CIDR, localhost).
func (m *Manager) isTrustedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip != nil && isPrivateIP(ip) {
		return true
	}
	if slices.Contains(m.cfg.Security.TrustedProxies, ipStr) {
		return true
	}
	if ip != nil {
		for _, ipNet := range m.trustedCIDRs {
			if ipNet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// TrustProxy extracts the real client IP from headers (CF-Connecting-IP, X-Forwarded-For, X-Real-Ip)
// when the direct connection comes from a trusted proxy or private network (Docker, k8s, localhost).
// It updates r.RemoteAddr and sets the IP header so downstream handlers and rate limiters see the real client address.
func (m *Manager) TrustProxy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteIP, port, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteIP = r.RemoteAddr
			port = "0"
		}

		isTrusted := m.isTrustedIP(remoteIP)
		clientIP := remoteIP

		if isTrusted {
			// 1. Check Cloudflare header (highest priority, set and guaranteed by Cloudflare edge)
			if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" && net.ParseIP(cfIP) != nil {
				clientIP = cfIP
			} else {
				// 2. Check X-Forwarded-For from right to left (prefer first public/non-proxy IP)
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					parts := strings.Split(xff, ",")
					for i := len(parts) - 1; i >= 0; i-- {
						ipStr := strings.TrimSpace(parts[i])
						if parsed := net.ParseIP(ipStr); parsed != nil && !m.isTrustedIP(ipStr) {
							clientIP = ipStr
							break
						}
					}
				}

				// 3. If no public IP in X-Forwarded-For, check X-Real-Ip for a valid public IP
				if clientIP == "" || clientIP == remoteIP {
					if realIP := strings.TrimSpace(r.Header.Get("X-Real-Ip")); realIP != "" && net.ParseIP(realIP) != nil && !m.isTrustedIP(realIP) {
						clientIP = realIP
					}
				}

				// 4. Fallback to leftmost valid IP from X-Forwarded-For if all were private/trusted
				if (clientIP == "" || clientIP == remoteIP) && r.Header.Get("X-Forwarded-For") != "" {
					parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
					if len(parts) > 0 {
						firstIP := strings.TrimSpace(parts[0])
						if net.ParseIP(firstIP) != nil {
							clientIP = firstIP
						}
					}
				}

				// 5. Fallback to X-Real-Ip even if private (e.g. local dev / staging)
				if clientIP == "" || clientIP == remoteIP {
					if realIP := strings.TrimSpace(r.Header.Get("X-Real-Ip")); realIP != "" && net.ParseIP(realIP) != nil {
						clientIP = realIP
					}
				}
			}
		}

		if net.ParseIP(clientIP) == nil {
			clientIP = remoteIP
		}

		// clientIP is real user IP (extracted from CF-Connecting-IP, XFF, or X-Real-Ip)
		// remoteIP is IP from proxy/LB that directly connects to our server
		r.Header.Set(m.cfg.Headers.Keys.IP, clientIP)
		r.Header.Set(m.cfg.Headers.Keys.IPOrigin, remoteIP)

		if clientIP != remoteIP {
			r.RemoteAddr = net.JoinHostPort(clientIP, port)
		}

		next.ServeHTTP(w, r)
	})
}

// IsMultipart reports whether the Content-Type indicates a multipart/form-data body.
func IsMultipart(contentType string) bool {
	ct := strings.TrimSpace(contentType)
	return len(ct) >= 10 && strings.EqualFold(ct[:10], "multipart/")
}

// IsBinary reports whether the Content-Type indicates a binary payload
// that must be excluded from body logging.
func IsBinary(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return false
	}
	if idx := strings.IndexByte(ct, ';'); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	return strings.HasPrefix(ct, "application/octet-stream") ||
		strings.HasPrefix(ct, "image/") ||
		strings.HasPrefix(ct, "audio/") ||
		strings.HasPrefix(ct, "video/") ||
		strings.HasPrefix(ct, "application/pdf") ||
		strings.HasPrefix(ct, "application/zip") ||
		strings.HasPrefix(ct, "application/gzip") ||
		strings.HasPrefix(ct, "application/x-gzip") ||
		strings.HasPrefix(ct, "application/x-tar") ||
		strings.HasPrefix(ct, "application/wasm")
}

// isLoggableBody reports whether the Content-Type represents a human-readable text payload
// that is allowed to be recorded in audit logs (e.g. JSON, XML, plain text, HTML, CSV, form).
// Multipart and binary payloads return false.
func isLoggableBody(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return true // Default to true when Content-Type is omitted (e.g. standard REST or plain text)
	}
	if IsMultipart(ct) || IsBinary(ct) {
		return false
	}
	if idx := strings.IndexByte(ct, ';'); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	if ct == "application/json" || strings.HasSuffix(ct, "+json") {
		return true
	}
	if ct == "application/xml" || strings.HasSuffix(ct, "+xml") {
		return true
	}
	if ct == "application/x-www-form-urlencoded" ||
		ct == "application/javascript" ||
		ct == "application/x-javascript" ||
		ct == "application/graphql" ||
		strings.HasPrefix(ct, "application/graphql-response") {
		return true
	}
	return false
}

// MaxBodySize returns a middleware that limits the size of the request body.
// It supports different limits for file uploads (multipart) vs regular requests
// and enforces allowed content types (case-insensitively).
func (m *Manager) MaxBodySize() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contentType := r.Header.Get("Content-Type")

			// Allow bodyless requests (e.g. GET, HEAD, OPTIONS, or requests with empty body)
			if r.Body == nil || r.Body == http.NoBody || (contentType == "" && r.ContentLength <= 0) {
				next.ServeHTTP(w, r)
				return
			}

			// Validate Content-Type (case-insensitive)
			lowerContentType := strings.ToLower(contentType)
			isAllowed := len(m.cfg.Security.AllowedContentTypes) == 0
			for _, allowed := range m.cfg.Security.AllowedContentTypes {
				if allowed == "*" || strings.Contains(lowerContentType, strings.ToLower(allowed)) {
					isAllowed = true
					break
				}
			}
			if !isAllowed {
				response.WriteJSONResponse(w, response.BadRequest(r.Context(), constants.ErrMsgUnsupportedContentType))
				return
			}

			// File upload: apply overall limit only
			if IsMultipart(lowerContentType) {
				if r.ContentLength > m.cfg.Limits.RequestBodyLimitSize {
					response.WriteJSONResponse(w, response.PayloadTooLarge(r.Context(), constants.ErrMsgPayloadTooLarge))
					return
				}
				if r.Body != nil && r.Body != http.NoBody {
					r.Body = http.MaxBytesReader(w, r.Body, m.cfg.Limits.RequestBodyLimitSize)
				}
				next.ServeHTTP(w, r)
				return
			}

			// Non-file: apply tighter non-file limit
			if r.ContentLength > m.cfg.Limits.RequestBodyNonFileLimitSize {
				response.WriteJSONResponse(w, response.PayloadTooLarge(r.Context(), constants.ErrMsgPayloadTooLarge))
				return
			}
			if r.Body != nil && r.Body != http.NoBody {
				r.Body = http.MaxBytesReader(w, r.Body, m.cfg.Limits.RequestBodyNonFileLimitSize)
			}
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
		matchedExact := false
		for _, o := range allowedOrigins {
			if o == origin {
				allowed = true
				matchedExact = true
				break
			}
			if o == "*" {
				allowed = true
			}
		}

		if allowed {
			if matchedExact {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Add("Vary", "Origin")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
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
		// Use only the first host to guard against header injection and sanitize illegal chars
		h := strings.SplitN(xfHost, ",", 2)[0]
		h = strings.TrimSpace(h)
		if h != "" && !strings.ContainsAny(h, "\r\n/\\") {
			host = h
		}
	}

	return scheme + "://" + host + r.RequestURI
}

// ReadAndRestoreBody reads the request body up to limit bytes and then restores
// it so subsequent handlers can read it again. Returns nil for nil or multipart bodies.
func ReadAndRestoreBody(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	if IsMultipart(r.Header.Get("Content-Type")) {
		return nil, nil
	}

	limitReader := io.LimitReader(r.Body, limit+1)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	if int64(len(bodyBytes)) > limit {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), r.Body))
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
			response.WriteJSONResponse(w, response.MethodNotAllowed(r.Context(), constants.ErrMsgMethodNotAllowed))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ResolveBodyToken computes a canonical body token for use in signature generation.
//   - Multipart bodies → "UNSIGNED"
//   - Binary bodies    → "UNSIGNED"
//   - Empty bodies     → "EMPTY"
//   - All others       → hex-encoded SHA-256 of the raw body
func ResolveBodyToken(contentType string, body []byte) string {
	if IsMultipart(contentType) || IsBinary(contentType) {
		return "UNSIGNED"
	}
	if len(body) == 0 {
		return "EMPTY"
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
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

// PingHandler creates a GET endpoint that can be used for service health checks.
func (m *Manager) PingHandler() http.Handler {
	return m.MethodOnly("GET", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response.WriteJSONResponse(w, response.Success(r.Context(), "pong"))
	}))
}

// ValidateUUIDHeaders validates that specified headers contain valid UUID strings.
// If required is true, missing or empty headers cause a 400 Bad Request error.
// If required is false, missing headers are skipped, but present headers must be valid UUIDs.
func ValidateUUIDHeaders(required bool, headerNames ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, h := range headerNames {
				val := strings.TrimSpace(r.Header.Get(h))
				if val == "" {
					if required {
						response.WriteJSONResponse(w, response.BadRequest(r.Context(), fmt.Sprintf("%s: %s", constants.ErrMsgMissingHeaders, h)))
						return
					}
					continue
				}

				if _, err := uuid.Parse(val); err != nil {
					displayVal := val
					if len(displayVal) > 64 {
						displayVal = displayVal[:64] + "..."
					}
					response.WriteJSONResponse(w, response.BadRequest(r.Context(), fmt.Sprintf("%s: header '%s' with value '%s' is not a valid UUID", constants.ErrMsgInvalidUUID, h, displayVal)))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireUUIDHeaders enforces that all specified headers exist and are valid UUIDs.
func RequireUUIDHeaders(headerNames ...string) func(http.Handler) http.Handler {
	return ValidateUUIDHeaders(true, headerNames...)
}

// ValidateOptionalUUIDHeaders validates that specified headers are valid UUIDs if present in the request.
func ValidateOptionalUUIDHeaders(headerNames ...string) func(http.Handler) http.Handler {
	return ValidateUUIDHeaders(false, headerNames...)
}
