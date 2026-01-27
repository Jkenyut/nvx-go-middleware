package middleware

import (
	"bytes"
	"context"
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
	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/Jkenyut/nvx-go-middleware/model"
	"github.com/go-chi/chi/v5/middleware"
)

const (
	// DefaultCompressionLevel is the default gzip compression level
	DefaultCompressionLevel = 5
	// DefaultThrottleLimit is the default concurrent request limit
	DefaultThrottleLimit = 100
	// MaxHeaderSize is the maximum size for header values
	MaxHeaderSize = 8192
)

// Recoverer is a middleware that recovers from panics, logs the panic (and a backtrace),
// and returns a HTTP 500 (Internal Server Error) status if possible.
// Recoverer prints a request ID if one is provided.
func (m *Manager) Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
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
					if rw.wroteHeader {
						m.cfg.Logger.Error().Msg("Response already written, cannot recover")
						return
					}
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)

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

		// Chi already wrapped with middleware.WrapResponseWriter
		if ww, ok := w.(middleware.WrapResponseWriter); ok {
			rw = &responseRecorder{
				ResponseWriter: ww,
				statusCode:     http.StatusOK,
			}
		} else if existingRw, ok := w.(*responseRecorder); ok {
			rw = existingRw
		} else {
			rw = wrapResponseWriter(w)
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

		// Also set Chi's RequestID key for compatibility
		ctx := r.Context()
		if middleware.GetReqID(ctx) == "" {
			ctx = context.WithValue(ctx, middleware.RequestIDKey, transactionID)
			r = r.WithContext(ctx)
		}

		start := time.Now()
		requestHeadersBytes, _ := json.Marshal(r.Header)
		reqBodyBytes, _ := m.readAndRestoreBodyJSON(r)

		next.ServeHTTP(rw, r)

		// Get status from wrapper
		statusCode := rw.statusCode
		if ww, ok := w.(middleware.WrapResponseWriter); ok {
			if ww.Status() != 0 {
				statusCode = ww.Status()
			}
		}

		responseHeadersBytes, _ := json.Marshal(rw.Header())

		entry := model.AuditLog{
			Method:          r.Method,
			FullURL:         FullURL(r),
			StatusCode:      statusCode,
			LatencyMS:       int(time.Since(start).Milliseconds()),
			MerchantKey:     r.Header.Get(constants.HeaderMerchantKey),
			ClientIP:        r.Header.Get(constants.HeaderIP),
			RequestID:       r.Header.Get(constants.HeaderRequestID),
			CreatedBy:       format.ToInt64(r.Header.Get(constants.HeaderUserID)),
			CreatedAt:       format.NowUTC(),
			TransactionID:   transactionID,
			RequestHeaders:  string(requestHeadersBytes),
			ResponseHeaders: string(responseHeadersBytes),
			RequestBody:     string(reqBodyBytes),
			ResponseBody:    rw.body.String(),
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

			if err := m.cfg.LogStore.Save(entry); err != nil {
				m.cfg.Logger.Error().
					Err(err).
					Str("transaction_id", transactionID).
					Msg("Failed to save audit log")
			}
		}()
	})
}

// EnsureCommonHeaders validates that common required headers are present in all requests.
// These headers are: NVX-Request-ID, NVX-Merchant-Key, and NVX-IP.
// It also validates that NVX-IP contains a valid IP address format.
func (m *Manager) EnsureCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate Headers Presence
		valid := validateHeaders(w, r, m.cfg.RequiredCommonHeaders)
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
		valid := validateHeaders(w, r, m.cfg.RequiredAuthHeaders)
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

// EnsurePublicAuth validates headers required for public authenticated requests.
// This includes device information (User-Agent, Device-ID, Platform, Mac-Address)
// and validates the request signature for public endpoints.
func (m *Manager) EnsurePublicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate Presence of Required Public Headers
		valid := validateHeaders(w, r, m.cfg.RequiredPublicAuthHeaders)
		if !valid {
			return
		}

		// Validate MAC Address Format
		macStr := r.Header.Get(constants.HeaderMacAddress)
		if _, err := net.ParseMAC(macStr); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(response.BadRequest(r.Context(), constants.ErrMsgInvalidMacAddress)); err != nil {
				m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
			}
			return
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
			if err := json.NewEncoder(w).Encode(response.BadRequest(r.Context(), constants.ErrMsgInvalidPlatform)); err != nil {
				m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
			}
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

// TrustProxy extracts the real client IP from X-Forwarded-For header
// if the request comes from a trusted proxy. Otherwise, it uses RemoteAddr.
// The extracted IP is set in the NVX-IP header for downstream handlers.
func (m *Manager) TrustProxy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isTrusted := false

		if len(m.cfg.TrustedProxies) > 0 {
			remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				remoteIP = r.RemoteAddr
			}

			for _, proxy := range m.cfg.TrustedProxies {
				if proxy == remoteIP {
					isTrusted = true
					break
				}

				_, ipNet, err := net.ParseCIDR(proxy)
				if err == nil {
					ip := net.ParseIP(remoteIP)
					if ip != nil && ipNet.Contains(ip) {
						isTrusted = true
						break
					}
				}
			}
		}

		if r.Header.Get(constants.HeaderIP) == "" {
			xff := r.Header.Get("X-Forwarded-For")
			if xff != "" && isTrusted {
				if idx := strings.Index(xff, ","); idx != -1 {
					xff = xff[:idx]
				}
				r.Header.Set(constants.HeaderIP, strings.TrimSpace(xff))
			} else {
				remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
				r.Header.Set(constants.HeaderIP, remoteIP)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// MaxBodySize returns a middleware that limits the maximum size of the request body.
// This helps prevent DoS attacks from large request bodies. The limit only applies
// to requests with Content-Type: application/json.
func (m *Manager) MaxBodySize(limitBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
				if r.ContentLength > limitBytes {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusRequestEntityTooLarge)
					if err := json.NewEncoder(w).Encode(response.PayloadTooLarge(r.Context(), constants.ErrMsgPayloadTooLarge)); err != nil {
						m.cfg.Logger.Error().Err(err).Msg("Failed to encode error response")
					}
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, limitBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CORS adds Cross-Origin Resource Sharing (CORS) headers to responses.
// It handles preflight OPTIONS requests and sets appropriate headers
// based on the configured allowed origins.
func (m *Manager) CORS(next http.Handler, allowedOrigins []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", strings.Join(allowedOrigins, ", "))
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, NVX-*")
		w.Header().Set("Access-Control-Max-Age", "3600")

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

// Helper functions

// validateHeaders checks if all required headers are present in the request.
// If any headers are missing, it returns false and writes a 400 Bad Request response.
func validateHeaders(w http.ResponseWriter, r *http.Request, headers []string) bool {
	missingHeaders := []string{}
	for _, header := range headers {
		if r.Header.Get(header) == "" {
			missingHeaders = append(missingHeaders, header)
		}
	}

	if len(missingHeaders) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		meta := response.NewMeta(r.Context(), false, constants.ErrMsgMissingHeaders, http.StatusBadRequest)
		resp := response.Response{
			Meta: meta,
			Data: map[string]interface{}{
				"missing": missingHeaders,
			},
		}

		json.NewEncoder(w).Encode(resp)
		return false
	}

	return true
}

func (m *Manager) validateSignatureAuthHeaders(r *http.Request) (bool, string) {
	authHeaders := make([]string, 0, len(m.cfg.RequiredSignatureAuthHeaders))
	for _, nameHeader := range m.cfg.RequiredSignatureAuthHeaders {
		authHeaders = append(authHeaders, r.Header.Get(nameHeader))
	}

	return m.validateSignatureHeaders(r, m.cfg.PrivateKeySignature, authHeaders)
}

func (m *Manager) validateSignaturePublicHeaders(r *http.Request) (bool, string) {
	messageHeaders := make([]string, 0, len(m.cfg.RequiredSignatureMessageHeaders))
	for _, nameHeader := range m.cfg.RequiredSignatureMessageHeaders {
		messageHeaders = append(messageHeaders, r.Header.Get(nameHeader))
	}
	messageSignature := cryptoutil.Signature(m.cfg.PublicKeySignature, messageHeaders...)

	publicHeaders := make([]string, 0, len(m.cfg.RequiredSignaturePublicHeaders)+1)
	for _, nameHeader := range m.cfg.RequiredSignaturePublicHeaders {
		publicHeaders = append(publicHeaders, r.Header.Get(nameHeader))
	}

	return m.validateSignatureHeaders(r, m.cfg.PublicKeySignature, append(publicHeaders, messageSignature))
}

func (_ *Manager) validateSignatureHeaders(r *http.Request, keySignature string, headers []string) (bool, string) {
	signatureServer := cryptoutil.Signature(keySignature, headers...)
	clientSignature := r.Header.Get(constants.HeaderSignature)

	if clientSignature == "" {
		return false, signatureServer
	}

	return clientSignature == signatureServer, signatureServer
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

func (_ *Manager) injectContext(r *http.Request) *http.Request {
	h := r.Header
	ctx := r.Context()

	ctx = activity.WithTransactionID(ctx, h.Get(constants.HeaderTransactionID))
	ctx = activity.WithRequestID(ctx, h.Get(constants.HeaderRequestID))
	ctx = activity.WithMerchantKey(ctx, h.Get(constants.HeaderMerchantKey))
	ctx = activity.WithUserID(ctx, h.Get(constants.HeaderUserID))
	ctx = activity.WithUserIP(ctx, h.Get(constants.HeaderIP))
	ctx = activity.WithUserType(ctx, h.Get(constants.HeaderUserType))

	return r.WithContext(ctx)
}

func (m *Manager) readAndRestoreBodyJSON(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	ct := r.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		return nil, nil
	}

	limitReader := io.LimitReader(r.Body, m.cfg.RequestBodyLimit)
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
