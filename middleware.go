package middleware

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
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
	"github.com/go-chi/chi/v5/middleware"
)

// Recoverer is a middleware that recovers from panics, logs the panic (and a backtrace),
// and returns a HTTP 500 (Internal Server Error) status if possible.
// Recoverer prints a request ID if one is provided.
func (m *Manager) Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			// Handle panic
			if rec := recover(); rec != nil {
				stack := string(debug.Stack())

				m.cfg.Logger.Error().
					Str("error", fmt.Sprintf("%v", rec)).
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Str("remote_addr", r.RemoteAddr).
					Msgf("Panic recovered:\n%s", stack)

				// Chi's middleware.WrapResponseWriter compatibility
				if ww, ok := w.(middleware.WrapResponseWriter); ok {
					if ww.Status() != 0 {
						m.cfg.Logger.Error().Msg("Response already written, cannot recover")
						return
					}
				}

				// Check our own response recorder
				if rw, ok := w.(*responseRecorder); ok {
					if rw.Status() != 0 {
						m.cfg.Logger.Error().Msg("Response already written, cannot recover")
						return
					}
				}

				// Set response headers
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)

				// Encode error response
				if err := json.NewEncoder(w).Encode(response.InternalError(r.Context())); err != nil {
					m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
				}
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// Logger is a middleware that logs the start and completion of each request,
// along with useful information about what was requested, what the response status was,
// and how long it took to return. When a request is completed, a log entry is saved
// using the configured LogStore.
func (m *Manager) Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap response writer to capture status and body
		var rw *responseRecorder

		if existingRw, ok := w.(*responseRecorder); ok {
			rw = existingRw
		} else {
			rw = wrapResponseWriter(w, r, constants.ResponseBodyLogLimit)
		}

		// Generate/propagate Transaction ID
		transactionID := r.Header.Get(constants.HeaderTransactionID)
		if transactionID == "" {
			transactionID = cryptoutil.V7()
		}

		rw.Header().Set(constants.HeaderTransactionID, transactionID)

		// Inject context
		if m.cfg.ContextInjector != nil {
			r = m.cfg.ContextInjector(r)
		} else {
			r = m.injectContext(r)
		}

		start := time.Now()

		// Normalize headers and body
		requestHeadersBytes := normalizeHeadersJSON(r.Header)
		var reqBodyBytes any

		// Normalize request body if logging is enabled
		if m.cfg.LogRequestBodies {
			raw, _ := ReadAndRestoreBody(r)
			reqBodyBytes = normalizeBodyRaw(raw)
		}

		next.ServeHTTP(rw, r)

		// Get status from wrapper
		statusCode := rw.Status()

		// Normalize headers and body
		responseHeadersBytes := normalizeHeadersJSON(rw.Header())

		var responseBody any

		// Normalize response body if logging is enabled
		if m.cfg.LogResponseBodies {
			responseBody = normalizeBodyRaw(rw.body.Bytes())
		}

		// Create audit log entry
		entry := model.AuditLog{
			Method:          r.Method,
			FullURL:         FullURL(r),
			StatusCode:      statusCode,
			LatencyMS:       int(time.Since(start).Milliseconds()),
			APIKey:          r.Header.Get(constants.HeaderAPIKey),
			ClientIP:        r.Header.Get(constants.HeaderIP),
			RequestID:       r.Header.Get(constants.HeaderRequestID),
			CreatedBy:       format.ToInt64(r.Header.Get(constants.HeaderUserID)),
			CreatedAt:       format.NowUTC(),
			TransactionID:   transactionID,
			RequestHeaders:  requestHeadersBytes,
			ResponseHeaders: responseHeadersBytes,
			RequestBody:     reqBodyBytes,
			ResponseBody:    responseBody,
		}

		// Save log asynchronously with proper error handling
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					m.cfg.Logger.Error().
						Interface("panic", rec).
						Msg("Panic in async log save")
				}
			}()

			// Save log asynchronously with proper error handling
			if err := m.cfg.LogStore.Save(entry); err != nil {
				m.cfg.Logger.Error().
					Err(err).
					Str("transaction_id", transactionID).
					Msg("Failed to save audit log")
			}
		}()
	})
}

// normalizeBodyRaw normalizes the body of a request.
func normalizeBodyRaw(raw []byte) any {
	// check if empty
	if len(raw) == 0 {
		return nil
	}

	// check if valid JSON
	if json.Valid(raw) {
		var v any
		if err := json.Unmarshal(raw, &v); err == nil {
			return v
		}
	}

	// if not JSON, marshal to JSON string (escaped)
	return string(raw)
}

// normalizeHeadersJSON normalizes the headers of a request.
func normalizeHeadersJSON(h http.Header) json.RawMessage {
	out := make(map[string]any, len(h))

	for k, v := range h {
		if len(v) == 1 {
			out[k] = v[0]
		} else {
			out[k] = v
		}
	}

	b, _ := json.Marshal(out)
	return json.RawMessage(b)
}

// EnsureCommonHeaders validates that common required headers are present in all requests.
// These headers are: NVX-Request-ID, NVX-API-Key, and NVX-IP.
// It also validates that NVX-IP contains a valid IP address format.
func (m *Manager) EnsureCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate Headers Presence
		valid := m.validateHeaders(w, r, m.cfg.RequiredCommonHeaders)
		if !valid {
			return
		}

		// Validate IP Format
		ipStr := r.Header.Get(constants.HeaderIP)
		if net.ParseIP(ipStr) == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(response.BadRequest(r.Context(), constants.ErrMsgInvalidIP)); err != nil {
				m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

// EnsureAuth validates headers required for authenticated requests.
// It checks for the presence of NVX-Token and NVX-User-ID headers,
// and validates the request signature to ensure authenticity.
func (m *Manager) EnsureAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate Headers Presence
		valid := m.validateHeaders(w, r, m.cfg.RequiredAuthHeaders)
		if !valid {
			return
		}

		// Validate Token
		tokenString := r.Header.Get(constants.HeaderToken)
		if tokenString == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			if err := json.NewEncoder(w).Encode(response.Unauthorized(r.Context(), constants.ErrMsgInvalidToken)); err != nil {
				m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
			}
			return
		}

		// Validate Signature Headers
		if validSignature, signatureServer := m.validateSignatureAuthHeaders(r); !validSignature {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			errMsg := constants.ErrMsgInvalidSignature
			if !m.envProd() {
				errMsg = fmt.Sprintf("%s - Expected: %s", constants.ErrMsgInvalidSignature, signatureServer)
			}

			if err := json.NewEncoder(w).Encode(response.Unauthorized(r.Context(), errMsg)); err != nil {
				m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SecureHeaders adds security-related headers to the response.
// These headers help protect against common web vulnerabilities like XSS,
// clickjacking, and MIME type sniffing.
func (m *Manager) SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, value := range m.cfg.SecurityHeaders {
			w.Header().Set(key, value)
		}
		next.ServeHTTP(w, r)
	})
}

// RemoveHeaders removes specified headers from the response.
// This is useful for removing headers like Server, X-Powered-By, etc.
func (m *Manager) RemoveHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If no headers to remove, skip wrapper overhead
		if len(m.cfg.HeadersToRemove) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Use a custom writer directly without wrapper struct if possible,
		// but since we need to intercept WriteHeader, let's just wrap it locally.
		rw := &headerCleanerResponseWriter{
			ResponseWriter:  w,
			headersToRemove: m.cfg.HeadersToRemove,
		}

		next.ServeHTTP(rw, r)
	})
}

// headerCleanerResponseWriter is a custom response writer that removes specified headers from the response.
type headerCleanerResponseWriter struct {
	http.ResponseWriter
	headersToRemove []string
}

// WriteHeader removes specified headers from the response.
func (w *headerCleanerResponseWriter) WriteHeader(statusCode int) {
	for _, h := range w.headersToRemove {
		w.ResponseWriter.Header().Del(h)
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

// Write removes specified headers from the response.
func (w *headerCleanerResponseWriter) Write(b []byte) (int, error) {
	// Ensure headers are cleaned if Write is called before WriteHeader
	// (Writing body implicitly calls WriteHeader(200) if not called yet)
	// Just delete headers here too to be safe.
	for _, h := range w.headersToRemove {
		w.ResponseWriter.Header().Del(h)
	}

	return w.ResponseWriter.Write(b)
}

// EnsurePublicAuth validates headers required for public authenticated requests.
// This includes device information (User-Agent, Device-ID, Platform, Mac-Address)
// and validates the request signature for public endpoints.
func (m *Manager) EnsurePublicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate Headers Presence
		valid := m.validateHeaders(w, r, m.cfg.RequiredPublicHeaders)
		if !valid {
			return
		}

		// Validate Signature Headers
		if validSignature, signatureServer := m.validateSignaturePublicHeaders(r); !validSignature {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			errMsg := constants.ErrMsgInvalidSignature
			if !m.envProd() {
				errMsg = fmt.Sprintf("%s - Expected: %s", constants.ErrMsgInvalidSignature, signatureServer)
			}

			if err := json.NewEncoder(w).Encode(response.Unauthorized(r.Context(), errMsg)); err != nil {
				m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

// TrustProxy validates the remote IP address of the request.
func (m *Manager) TrustProxy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		remoteIP := func() string {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				return r.RemoteAddr
			}
			return ip
		}()

		isTrusted := false

		for _, proxy := range m.cfg.TrustedProxies {
			if proxy == remoteIP {
				isTrusted = true
				break
			}

			if _, ipNet, err := net.ParseCIDR(proxy); err == nil {
				if ip := net.ParseIP(remoteIP); ip != nil && ipNet.Contains(ip) {
					isTrusted = true
					break
				}
			}
		}

		var clientIP string

		if isTrusted {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				clientIP = strings.TrimSpace(parts[0])
			}
		}
		if net.ParseIP(clientIP) == nil {
			clientIP = remoteIP
		}

		r.Header.Set(constants.HeaderIP, clientIP)

		// If we found a valid client IP from a trusted proxy, update RemoteAddr
		// This protects standard Go functions that rely on RemoteAddr
		if clientIP != remoteIP {
			r.RemoteAddr = net.JoinHostPort(clientIP, "0")
		}

		next.ServeHTTP(w, r)
	})
}

// isMultipart checks if the content type is multipart/form-data
func isMultipart(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(contentType), "multipart/")
}

// MaxBodySize returns a middleware that limits the maximum size of the request body.
// It also restricts the allowed Content-Types based on the configuration.
func (m *Manager) MaxBodySize() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contentType := r.Header.Get("Content-Type")

			// If no content type and no body (Content-Length 0), proceed (e.g. GET requests)
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
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				if err := json.NewEncoder(w).Encode(response.BadRequest(r.Context(), constants.ErrMsgUnsupportedContentType)); err != nil {
					m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
				}
				return
			}

			// Validate Request Body Size
			if r.ContentLength > m.cfg.RequestBodyLimit {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				if err := json.NewEncoder(w).Encode(response.PayloadTooLarge(r.Context(), constants.ErrMsgPayloadTooLarge)); err != nil {
					m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
				}
				return
			}

			// FILE (multipart)
			if isMultipart(contentType) {
				r.Body = http.MaxBytesReader(w, r.Body, m.cfg.RequestBodyLimit)
				next.ServeHTTP(w, r)
				return
			}

			// Validate Request Body Size (non-file)
			if r.ContentLength > m.cfg.RequestBodyNonFileLimit {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				if err := json.NewEncoder(w).Encode(response.PayloadTooLarge(r.Context(), constants.ErrMsgPayloadTooLarge)); err != nil {
					m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
				}
				return
			}

			// Non-FILE (application/json, application/x-www-form-urlencoded, etc.)
			r.Body = http.MaxBytesReader(w, r.Body, m.cfg.RequestBodyNonFileLimit)
			next.ServeHTTP(w, r)
		})
	}
}

// CORS adds Cross-Origin Resource Sharing (CORS) headers to responses.
// It handles preflight OPTIONS requests and sets appropriate headers
// based on the configured allowed origins.
func (m *Manager) CORS(next http.Handler, allowedOrigins []string, allowedHeaders []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", strings.Join(allowedOrigins, ", "))
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
		w.Header().Set("Access-Control-Max-Age", "3600")

		// Handle OPTIONS request
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(response.Success(r.Context(), nil)); err != nil {
				m.cfg.Logger.Error().Err(err).Msg("Failed to encode CORS response")
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// validateHeaders checks if all required headers are present in the request.
// If any headers are missing, it returns false and writes a 400 Bad Request response.
func (m *Manager) validateHeaders(w http.ResponseWriter, r *http.Request, headers []string) bool {
	missingHeaders := []string{}
	for _, header := range headers {
		if r.Header.Get(header) == "" {
			missingHeaders = append(missingHeaders, header)
		}
	}

	// Validate Missing Headers
	if len(missingHeaders) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		message := constants.ErrMsgMissingHeaders
		if !m.envProd() {
			message = fmt.Sprintf("%s - Missing Headers: %s", constants.ErrMsgMissingHeaders, strings.Join(missingHeaders, ", "))
		}
		json.NewEncoder(w).Encode(response.BadRequest(r.Context(), message))
		return false
	}

	// Validate Timestamp
	timestamp := format.StringToUnixOrZero(r.Header.Get(constants.HeaderTimestamp))
	if timestamp.IsZero() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response.BadRequest(r.Context(), constants.ErrMsgInvalidTimestamp))
		return false
	}

	// Validate Platform
	platform := r.Header.Get(constants.HeaderPlatform)
	validPlatform := false
	for _, v := range constants.CheckPlatform {
		if platform == v {
			validPlatform = true
			break
		}
	}

	if !validPlatform {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response.BadRequest(r.Context(), constants.ErrMsgInvalidPlatform))
		return false
	}

	return true
}

// validateSignatureAuthHeaders validates the signature auth headers.
func (m *Manager) validateSignatureAuthHeaders(r *http.Request) (bool, string) {
	authHeaders := make([]string, 0, len(m.cfg.RequiredSignatureHeadersAuth))
	for _, nameHeader := range m.cfg.RequiredSignatureHeadersAuth {
		authHeaders = append(authHeaders, r.Header.Get(nameHeader))
	}

	return m.validateSignatureHeaders(r, m.cfg.PrivateKeySignature, authHeaders)
}

// validateSignaturePublicHeaders validates the signature public headers.
func (m *Manager) validateSignaturePublicHeaders(r *http.Request) (bool, string) {
	publicHeaders := make([]string, 0, len(m.cfg.RequiredSignatureHeadersPublic)+3)
	publicHeaders = append(publicHeaders, strings.ToUpper(r.Method))
	publicHeaders = append(publicHeaders, r.RequestURI)
	for _, nameHeader := range m.cfg.RequiredSignatureHeadersPublic {
		publicHeaders = append(publicHeaders, r.Header.Get(nameHeader))
	}

	bodyBytes, _ := ReadAndRestoreBody(r)
	bodyToken := ResolveBodyToken(r.Header.Get("Content-Type"), bodyBytes)

	publicHeaders = append(publicHeaders, string(bodyToken))

	return m.validateSignatureHeaders(r, m.cfg.PublicKeySignature, publicHeaders)
}

// validateSignatureHeaders validates the signature headers.
func (_ *Manager) validateSignatureHeaders(r *http.Request, keySignature string, values []string) (bool, string) {
	signatureServer := cryptoutil.Signature(keySignature, values...)
	clientSignature := r.Header.Get(constants.HeaderSignature)

	if clientSignature == "" {
		return false, signatureServer
	}

	if len(clientSignature) != len(signatureServer) {
		return false, signatureServer
	}

	return subtle.ConstantTimeCompare([]byte(clientSignature), []byte(signatureServer)) == 1, signatureServer
}

// FullURL reconstructs the full URL of the request, including scheme, host, and path.
// It respects X-Forwarded-Proto and X-Forwarded-Host headers if present.
func FullURL(r *http.Request) string {
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}

	host := r.Host
	if xfHost := r.Header.Get("X-Forwarded-Host"); xfHost != "" {
		host = xfHost
	}

	return scheme + "://" + host + r.RequestURI
}

// injectContext injects common headers into the request context.
func (_ *Manager) injectContext(r *http.Request) *http.Request {
	h := r.Header
	ctx := r.Context()

	ctx = activity.WithTransactionID(ctx, h.Get(constants.HeaderTransactionID))
	ctx = activity.WithRequestID(ctx, h.Get(constants.HeaderRequestID))
	ctx = activity.WithAPIKey(ctx, h.Get(constants.HeaderAPIKey))
	ctx = activity.WithUserID(ctx, h.Get(constants.HeaderUserID))
	ctx = activity.WithUserIP(ctx, h.Get(constants.HeaderIP))
	ctx = activity.WithUserType(ctx, h.Get(constants.HeaderUserType))

	return r.WithContext(ctx)
}

// ReadAndRestoreBody reads the request body and restores it for later use.
// It returns the body as a byte slice and an error if the read fails.
// If the request body is nil or the content type is multipart, it returns nil and no error.
func ReadAndRestoreBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	// skip read body if multipart
	if isMultipart(r.Header.Get("Content-Type")) {
		return nil, nil
	}

	limitReader := io.LimitReader(r.Body, constants.RequestBodyNonFileLimit)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	r.Body = io.NopCloser(io.MultiReader(bytes.NewBuffer(bodyBytes), r.Body))
	return bodyBytes, nil
}

// MethodOnly restricts a handler to only accept a specific HTTP method.
// If the request method doesn't match, it returns a 405 Method Not Allowed response.
func (m *Manager) MethodOnly(method string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			if err := json.NewEncoder(w).Encode(response.MethodNotAllowed(r.Context(), constants.ErrMsgMethodNotAllowed)); err != nil {
				m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ResolveBodyToken resolves a body token based on the content type and body.
// If the content type is multipart, it returns "UNSIGNED".
// If the body is empty, it returns "EMPTY".
// Otherwise, it returns the SHA-256 hash of the body.
func ResolveBodyToken(contentType string, body []byte) string {
	ct := strings.ToLower(strings.TrimSpace(contentType))

	// multipart / file upload → UNSIGNED
	if strings.HasPrefix(ct, "multipart/") {
		return "UNSIGNED"
	}

	// no body → EMPTY
	if len(body) == 0 {
		return "EMPTY"
	}

	// all non-multipart → hash
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// EnsurePreSignHeaders validates that common required headers are present in all requests.
// These headers are: NVX-Request-ID, NVX-API-Key, NVX-Platform, and NVX-Timestamp.
// It also validates that NVX-IP contains a valid IP address format.
func (m *Manager) EnsurePreSignHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate Headers Presence
		valid := m.validateHeaders(w, r, m.cfg.RequiredSignatureHeadersPublic)
		if !valid {
			return
		}

		// Validate IP Format
		ipStr := r.Header.Get(constants.HeaderIP)
		if net.ParseIP(ipStr) == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(response.BadRequest(r.Context(), constants.ErrMsgInvalidIP)); err != nil {
				m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

// PreSignHandler creates a handler for presigning requests
func (m *Manager) PreSignHandler(cfg ChainConfig) http.Handler {
	return m.MethodOnly("POST", m.PreSignChain(cfg)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set content type
			w.Header().Set("Content-Type", "application/json")
			var req model.PresignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				// Invalid request
				w.WriteHeader(http.StatusBadRequest)
				if err := json.NewEncoder(w).Encode(response.BadRequest(r.Context(), constants.ErrMsgInvalidRequest)); err != nil {
					m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
				}
				return
			}
			
			// Validate request
			err := validator.Struct(req)
			if err != nil {
				// Get errors
				errs := validator.GetErrors(err)
				var result = make([]string, len(errs))
				for i, e := range errs {
					result[i] = fmt.Sprintf("%s: %s", e.Field(), e.Tag())
				}
				w.WriteHeader(http.StatusBadRequest)
				if err := json.NewEncoder(w).Encode(response.BadRequest(r.Context(), strings.Join(result, ", "))); err != nil {
					m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
				}
				return
			}

			// Create canonical 
			publicCanonical := make([]string, 0, len(m.cfg.RequiredSignatureHeadersPublic)+3)
			publicCanonical = append(publicCanonical, strings.ToUpper(req.Method))
			publicCanonical = append(publicCanonical, req.Uri)
			for _, nameHeader := range m.cfg.RequiredSignatureHeadersPublic {
				publicCanonical = append(publicCanonical, r.Header.Get(nameHeader))
			}

			// Add body token
			bodyBytes, _ := ReadAndRestoreBody(r)
			bodyToken := ResolveBodyToken(req.ContentType, bodyBytes)
			publicCanonical = append(publicCanonical, string(bodyToken))

			// Sign canonical
			json.NewEncoder(w).Encode(response.Success(r.Context(), model.PresignResponse{
				Signature: cryptoutil.Signature(m.cfg.PublicKeySignature, publicCanonical...),
			}))
		})))
}
