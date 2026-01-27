package middleware

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/Jkenyut/nvx-go-helper/activity"
	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-helper/format"
	"github.com/Jkenyut/nvx-go-helper/response"
	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/Jkenyut/nvx-go-middleware/model"
	"github.com/rs/zerolog"
)

// Config holds the configuration for the middleware manager.
type Config struct {
	// LogStore is the storage backend for audit logs.
	LogStore LogStore
	// RequiredCommonHeaders lists headers required for all requests.
	RequiredCommonHeaders []string
	// RequiredAuthHeaders lists headers required for authenticated requests.
	RequiredAuthHeaders []string
	// RequiredPublicAuthHeaders lists headers required for public authenticated requests.
	RequiredPublicAuthHeaders []string
	// SecurityHeaders maps security header keys to their values.
	SecurityHeaders map[string]string
	// RequiredSignatureAuthHeaders lists headers included in the signature for authenticated requests.
	RequiredSignatureAuthHeaders []string
	// RequiredSignatureMessageHeaders lists headers included in the message for signature verification.
	RequiredSignatureMessageHeaders []string
	// RequiredSignaturePublicHeaders lists headers included in the signature for public requests.
	RequiredSignaturePublicHeaders []string
	// PublicKeySignature is the public key used for verification (RSA).
	PublicKeySignature string
	// PrivateKeySignature is the private key used for signing (RSA).
	PrivateKeySignature string
	// ContextInjector is a custom function to inject values into the request context.
	ContextInjector func(r *http.Request) *http.Request
	// RequestTimeout is the duration before a request times out.
	RequestTimeout time.Duration
	// RequestBodyLimit is the maximum allowed size for the request body.
	RequestBodyLimit int64
	// Logger is the internal logger instance.
	Logger *zerolog.Logger
	// AllowedOrigins is the list of allowed origins for CORS.
	AllowedOrigins []string
	// TrustedProxies is the list of trusted proxy IPs or CIDRs.
	TrustedProxies []string
	// Env is the environment the application is running in.
	Env string
}

// Manager holds the middleware configuration and provides middleware methods.
type Manager struct {
	cfg Config
}

// New creates a new Middleware Manager with the given configuration.
// It initializes required fields and sets default values if they are missing.
func New(cfg Config) *Manager {

	// Set default logger if not set
	if cfg.Logger == nil {
		l := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).With().Timestamp().Logger()
		cfg.Logger = &l
	}

	// Set default LogStore if nil
	if cfg.LogStore == nil {
		cfg.LogStore = &ConsoleStore{
			logger: cfg.Logger,
		}
	}

	// Set default RequestTimeout if not set
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 60 * time.Second
	}
	// Set default RequestBodyLimit if not set (3MB)
	if cfg.RequestBodyLimit == 0 {
		cfg.RequestBodyLimit = 3 * 1024 * 1024 // 3 MB
	}
	// Set default env if not set
	if cfg.Env == "" {
		cfg.Env = "development"
	}

	// Validate required keys
	if cfg.PublicKeySignature == "" || cfg.PrivateKeySignature == "" {
		panic("PublicKey and PrivateKey are required in middleware configuration")
	}

	// Validate AllowedOrigins
	if len(cfg.AllowedOrigins) == 0 {
		panic("AllowedOrigins is required in middleware configuration")
	}

	// Set default RequiredCommonHeaders if not set
	if len(cfg.RequiredCommonHeaders) == 0 {
		cfg.RequiredCommonHeaders = constants.RequiredCommonHeaders
	}

	// Set default RequiredAuthHeaders if not set
	if len(cfg.RequiredAuthHeaders) == 0 {
		cfg.RequiredAuthHeaders = constants.RequiredAuthHeaders
	}

	// Set default RequiredPublicAuthHeaders if not set
	if len(cfg.RequiredPublicAuthHeaders) == 0 {
		cfg.RequiredPublicAuthHeaders = constants.RequiredPublicAuthHeaders
	}

	// Set default RequiredSignatureAuthHeaders if not set
	if len(cfg.RequiredSignatureAuthHeaders) == 0 {
		cfg.RequiredSignatureAuthHeaders = constants.RequiredSignatureAuthHeaders
	}

	// Set default RequiredSignaturePublicHeaders if not set
	if len(cfg.RequiredSignaturePublicHeaders) == 0 {
		cfg.RequiredSignaturePublicHeaders = constants.RequiredSignaturePublicHeaders
	}

	// Set default RequiredSignatureMessageHeaders if not set
	if len(cfg.RequiredSignatureMessageHeaders) == 0 {
		cfg.RequiredSignatureMessageHeaders = constants.RequiredSignatureMessagePublicHeaders
	}

	// Set default SecurityHeaders if not set
	if cfg.SecurityHeaders == nil {
		cfg.SecurityHeaders = constants.SecurityHeaders
	}

	return &Manager{cfg: cfg}
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
	body        bytes.Buffer
}

func wrapResponseWriter(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK, // Default to 200 OK
	}
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	// set status code
	r.statusCode = code
	r.wroteHeader = true
	// write header
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	// detect JSON response
	ct := r.Header().Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		r.body.Write(b)
	}

	return r.ResponseWriter.Write(b)
}

// Flush implements the http.Flusher interface to allow streaming.
func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements the http.Hijacker interface to allow WebSockets and other hijacks.
func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("http.Hijacker not supported by underlying ResponseWriter")
}

// LogStore defines the interface for storing log entries.
type LogStore interface {
	Save(entry model.AuditLog) error
}

// ConsoleStore is a default implementation of LogStore that writes to the console.
type ConsoleStore struct {
	logger *zerolog.Logger
}

// Save writes the audit log entry to the configured logger or stdout.
func (m *ConsoleStore) Save(entry model.AuditLog) error {
	// Log structured data using zerolog
	m.logger.Info().Interface("log entry", entry).Msg("saving audit log")

	return nil
}

// Logger is a middleware that logs the start and end of each request.
// It uses the configured LogStore to save the log entry.
func (m *Manager) Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Generate Transaction ID
		if r.Header.Get(constants.HeaderTransactionID) == "" {
			uuidV7 := cryptoutil.V7()
			w.Header().Set(constants.HeaderTransactionID, uuidV7)
		} else {
			w.Header().Set(constants.HeaderTransactionID, r.Header.Get(constants.HeaderTransactionID))
		}

		// 2. Inject Context
		// If a custom injector is provided, use it. Otherwise, use the default.
		if m.cfg.ContextInjector != nil {
			r = m.cfg.ContextInjector(r)
		} else {
			r = m.injectContext(r)
		}

		// 3. Start Timer
		start := time.Now()

		// 4. Wrap ResponseWriter to capture status code and body
		wrapped := wrapResponseWriter(w)
		// Marshal request headers for logging
		requestHeadersBytes, _ := json.Marshal(r.Header)
		// Read and restore request body for logging
		reqBodyBytes, _ := m.readAndRestoreBodyJSON(r)

		// 5. Serve Next Handler
		next.ServeHTTP(wrapped, r)

		// Marshal response headers for logging
		responseHeadersBytes, _ := json.Marshal(wrapped.Header())

		// 6. Create Audit Log Entry
		entry := model.AuditLog{
			Method:          r.Method,
			FullURL:         FullURL(r),
			StatusCode:      wrapped.statusCode,
			LatencyMS:       int(time.Since(start).Milliseconds()),
			MerchantKey:     r.Header.Get(constants.HeaderMerchantKey),
			ClientIP:        r.Header.Get(constants.HeaderIP),
			RequestID:       r.Header.Get(constants.HeaderRequestID),
			CreatedBy:       format.ToInt64(r.Header.Get(constants.HeaderUserID)),
			CreatedAt:       format.NowUTC(),
			TransactionID:   wrapped.Header().Get(constants.HeaderTransactionID),
			RequestHeaders:  string(requestHeadersBytes),
			ResponseHeaders: string(responseHeadersBytes),
			RequestBody:     string(reqBodyBytes),
			ResponseBody:    wrapped.body.String(),
		}

		// 7. Save Log Entry Asynchronously
		go func() {
			if err := m.cfg.LogStore.Save(entry); err != nil {

				m.cfg.Logger.Error().Err(err).Msg("Failed to save log")

			}
		}()
	})
}

// EnsureCommonHeaders validates headers required for ALL requests.
func (m *Manager) EnsureCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Validate Headers Presence
		valid := validateHeaders(w, r, m.cfg.RequiredCommonHeaders)
		if !valid {
			// Response already written
			return
		}

		// 2. Validate IP Format
		if net.ParseIP(r.Header.Get(constants.HeaderIP)) == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(response.BadRequest(r.Context(), constants.ErrMsgInvalidIP))
			return
		}

		// 3. Serve Next
		next.ServeHTTP(w, r)
	})
}

// EnsureAuth validates headers required for Authenticated requests and verifies the JWT token.
func (m *Manager) EnsureAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Validate Headers Presence
		// Check if keys from RequiredAuthHeaders are present in the request
		valid := validateHeaders(w, r, m.cfg.RequiredAuthHeaders)
		if !valid {
			// Response already written in validateHeaders
			return
		}

		// 2. Validate Token
		// Extract token from header
		tokenString := r.Header.Get(constants.HeaderToken) // Assuming NVX-Token contains the raw Bearer token
		if tokenString == "" {
			// Return 401 Unauthorized if token is missing
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(response.Unauthorized(r.Context(), constants.ErrMsgInvalidToken))
			return
		}

		// 3. Validate Signature Headers
		// Check if the request signature is valid based on configured headers
		if validSignature, signatureServer := m.validateSignatureAuthHeaders(r); !validSignature {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			if m.envProd() {
				json.NewEncoder(w).Encode(response.Unauthorized(r.Context(), constants.ErrMsgInvalidSignature))
			} else {
				json.NewEncoder(w).Encode(response.Unauthorized(r.Context(), constants.ErrMsgInvalidSignature+" - "+signatureServer))
			}
			return
		}

		// optional: store claims in context if needed (User ID, etc.)
		// ctx := context.WithValue(r.Context(), "user_claims", claims)
		// next.ServeHTTP(w, r.WithContext(ctx))

		// 4. Pass execution to the next handler
		next.ServeHTTP(w, r)
	})
}

// SecureHeaders adds security-related headers to the response based on configuration.
func (m *Manager) SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Iterate over configured security headers and set them
		for key, value := range m.cfg.SecurityHeaders {
			w.Header().Set(key, value)
		}

		next.ServeHTTP(w, r)
	})
}

// Recoverer is a middleware that recovers from panics and logs the stack trace.
func (m *Manager) Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// 1. Capture Stack Trace
				stackBytes := debug.Stack()
				stackStr := string(stackBytes)

				// 2. Log Panic with Stack Trace
				// Use structured logging if available for better parsing
				m.cfg.Logger.Error().
					Str("error", fmt.Sprintf("%v", err)).
					Msgf("Panic recovered:\n%s", stackStr)

					// 3. Return 500 Internal Server Error
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(response.InternalError(r.Context()))
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// validateHeaders is a private helper function.
func validateHeaders(w http.ResponseWriter, r *http.Request, headers []string) bool {
	// get missing headers
	missingHeaders := []string{}
	for _, header := range headers {
		if r.Header.Get(header) == "" {
			missingHeaders = append(missingHeaders, header)
		}
	}

	// validate missing headers
	if len(missingHeaders) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		// create response
		meta := response.NewMeta(r.Context(), false, constants.ErrMsgMissingHeaders, http.StatusBadRequest)
		resp := response.Response{
			Meta: meta,
			Data: map[string]interface{}{
				"missing": missingHeaders,
			},
		}

		// encode response
		json.NewEncoder(w).Encode(resp)
		return false
	}

	return true
}

// EnsurePublicAuth validates that the request has a valid User-Agent, Device-ID, Platform, and Mac-Address.
func (m *Manager) EnsurePublicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Validate Presence of Required Public Headers
		valid := validateHeaders(w, r, m.cfg.RequiredPublicAuthHeaders)
		if !valid {
			// Response already written
			return
		}

		// 2. Validate MAC Address Format
		if _, err := net.ParseMAC(r.Header.Get(constants.HeaderMacAddress)); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(response.BadRequest(r.Context(), constants.ErrMsgInvalidMacAddress))
			return
		}

		// 3. Validate Platform
		validPlatform := false
		for _, v := range constants.CheckPlatform {
			if r.Header.Get(constants.HeaderPlatform) == v {
				validPlatform = true
			}
		}

		if !validPlatform {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(response.BadRequest(r.Context(), constants.ErrMsgInvalidPlatform))
			return
		}

		// 4. Validate Signature Headers
		if validSignature, signatureServer := m.validateSignaturePublicHeaders(r); !validSignature {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			if m.envProd() {
				json.NewEncoder(w).Encode(response.Unauthorized(r.Context(), constants.ErrMsgInvalidSignature))
			} else {
				json.NewEncoder(w).Encode(response.Unauthorized(r.Context(), constants.ErrMsgInvalidSignature+" - "+signatureServer))
			}
			return
		}

		// 5. Serve Next
		next.ServeHTTP(w, r)
	})
}

func (m *Manager) validateSignatureAuthHeaders(r *http.Request) (bool, string) {
	// get auth headers
	authHeaders := []string{}
	for _, nameHeader := range m.cfg.RequiredSignatureAuthHeaders {
		authHeaders = append(authHeaders, r.Header.Get(nameHeader))
	}

	// validate signature headers
	return m.validateSignatureHeaders(r, m.cfg.PrivateKeySignature, authHeaders)
}

func (m *Manager) validateSignaturePublicHeaders(r *http.Request) (bool, string) {
	// get message headers
	messageHeaders := []string{}
	for _, nameHeader := range m.cfg.RequiredSignatureMessageHeaders {
		messageHeaders = append(messageHeaders, r.Header.Get(nameHeader))
	}
	// get message signature
	messageSignature := cryptoutil.Signature(m.cfg.PublicKeySignature, messageHeaders...)

	// get public headers
	publicHeaders := []string{}
	for _, nameHeader := range m.cfg.RequiredSignaturePublicHeaders {
		publicHeaders = append(publicHeaders, r.Header.Get(nameHeader))
	}

	// validate signature headers
	return m.validateSignatureHeaders(r, m.cfg.PublicKeySignature, append(publicHeaders, messageSignature))
}

func (_ *Manager) validateSignatureHeaders(r *http.Request, keySignature string, headers []string) (bool, string) {
	signatureServer := cryptoutil.Signature(keySignature, headers...)
	// validate signature headers
	if r.Header.Get(constants.HeaderSignature) == "" {
		return false, signatureServer
	}
	return r.Header.Get(constants.HeaderSignature) == signatureServer, signatureServer
}

func FullURL(r *http.Request) string {
	// get scheme
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}

	// get host
	host := r.Host
	if xfHost := r.Header.Get("X-Forwarded-Host"); xfHost != "" {
		host = xfHost
	}

	// return full url
	return scheme + "://" + host + r.RequestURI
}

func (_ *Manager) injectContext(r *http.Request) *http.Request {
	// get header
	h := r.Header
	// get context
	ctx := r.Context()

	// inject transaction id to context
	ctx = activity.WithTransactionID(ctx, h.Get(constants.HeaderTransactionID))
	// inject request id to context
	ctx = activity.WithRequestID(ctx, h.Get(constants.HeaderRequestID))
	// inject merchant key to context
	ctx = activity.WithMerchantKey(ctx, h.Get(constants.HeaderMerchantKey))
	// inject user id to context
	ctx = activity.WithUserID(ctx, h.Get(constants.HeaderUserID))
	// inject user ip to context
	ctx = activity.WithUserIP(ctx, h.Get(constants.HeaderIP))
	// inject user type to context
	ctx = activity.WithUserType(ctx, h.Get(constants.HeaderUserType))

	// return request with context
	return r.WithContext(ctx)
}

func OnlyMethod(method string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(response.MethodNotAllowed(r.Context(), constants.ErrMsgMethodNotAllowed))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Manager) readAndRestoreBodyJSON(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	ct := r.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		return nil, nil
	}

	// Limit the size of body read for logging
	limitReader := io.LimitReader(r.Body, m.cfg.RequestBodyLimit)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, err
	}

	// restore body so next handler can read it
	r.Body = io.NopCloser(io.MultiReader(bytes.NewBuffer(bodyBytes), r.Body))
	return bodyBytes, nil
}

// Timeout wraps the handler with a timeout context.
// If the handler takes longer than the timeout, it returns a 503 Service Unavailable.
func (_ *Manager) Timeout(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// standard http.TimeoutHandler returns a simple string body.
			// We can customize the message to be a JSON string to match the app style.
			// Note: This hijacks the writer, so we can't easily use the 'response' helper inside.
			// We provide a pre-marshaled JSON error message.
			errorMsg := fmt.Sprintf(`{"meta":{"success":false,"message":"%s","code":503}}`, constants.ErrMsgRequestTimeout)
			h := http.TimeoutHandler(next, timeout, errorMsg)
			h.ServeHTTP(w, r)
		})
	}
}

// MaxBodySize limits the size of the request body to prevent DoS attacks.
// It ONLY applies to requests with Content-Type containing "application/json".
// MaxBodySize limits the size of the request body to prevent DoS attacks.
// It ONLY applies to requests with Content-Type containing "application/json".
func (_ *Manager) MaxBodySize(limitBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
				if r.ContentLength > limitBytes {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusRequestEntityTooLarge)
					json.NewEncoder(w).Encode(response.PayloadTooLarge(r.Context(), constants.ErrMsgPayloadTooLarge))
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, limitBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TrustProxy populates the NVX-IP header from X-Forwarded-For if the request comes from a trusted proxy.
func (m *Manager) TrustProxy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Check if we should trust the proxy
		isTrusted := false

		// If no trusted proxies are configured, we default to NOT trusting X-Forwarded-For for security.
		// NOTE: This changes previous behavior where it always trusted.
		if len(m.cfg.TrustedProxies) > 0 {
			remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				remoteIP = r.RemoteAddr
			}

			// Check against list of trusted proxies (exact match or CIDR)
			for _, proxy := range m.cfg.TrustedProxies {
				// Simple IP match
				if proxy == remoteIP {
					isTrusted = true
					break
				}

				// Check CIDR match
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

		// 2. Logic to set NVX-IP
		if r.Header.Get(constants.HeaderIP) == "" {
			xff := r.Header.Get("X-Forwarded-For")
			if xff != "" && isTrusted {
				// X-Forwarded-For can be a comma separated list of IPs.
				// The first one is the original client IP.
				if idx := strings.Index(xff, ","); idx != -1 {
					xff = xff[:idx]
				}
				r.Header.Set(constants.HeaderIP, strings.TrimSpace(xff))
			} else {
				// If not trusted or XFF empty, fallback to RemoteAddr (real IP)
				remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
				r.Header.Set(constants.HeaderIP, remoteIP)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// gzipWriter wraps the http.ResponseWriter to transparently compress the response body.
type gzipWriter struct {
	http.ResponseWriter
	writer *gzip.Writer
}

func (w gzipWriter) Write(b []byte) (int, error) {
	return w.writer.Write(b)
}

func (w gzipWriter) WriteHeader(status int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(status)
}

// Flush implements the http.Flusher interface to allow streaming.
func (w gzipWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
	w.writer.Flush()
}

// Hijack implements the http.Hijacker interface to allow WebSockets and other hijacks.
func (w gzipWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("http.Hijacker not supported by underlying ResponseWriter")
}

// Gzip compresses the response body using gzip compression if the client supports it.
func (_ *Manager) Gzip(next http.Handler) http.Handler {
	// pool for gzip writers to reduce allocation
	pool := sync.Pool{
		New: func() interface{} {
			w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
			return w
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check if client supports gzip
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		// check if content is already compressed
		if w.Header().Get("Content-Encoding") != "" {
			next.ServeHTTP(w, r)
			return
		}

		// get writer from pool
		gw := pool.Get().(*gzip.Writer)
		gw.Reset(w)
		defer func() {
			gw.Close()
			pool.Put(gw)
		}()

		// set headers
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")

		// wrap response writer
		gzw := gzipWriter{ResponseWriter: w, writer: gw}

		next.ServeHTTP(gzw, r)
	})
}
// GlobalChain applies a recommended chain of middleware.
// Runtime order (outer → inner):
// Recover -> Logger -> TrustProxy -> EnsureCommonHeaders -> SecureHeaders
// -> CORS -> MaxBodySize -> Gzip -> Timeout
func (m *Manager) GlobalChain(next http.Handler) http.Handler {
	return m.Recoverer(
		m.Logger(
			m.TrustProxy(
				m.EnsureCommonHeaders(
					m.SecureHeaders(
						m.CORS(
							m.MaxBodySize(m.cfg.RequestBodyLimit)(
								m.Gzip(
									m.Timeout(m.cfg.RequestTimeout)(next),
								),
							),
							m.cfg.AllowedOrigins,
						),
					),
				),
			),
		),
	)
}

func (_ *Manager) CORS(next http.Handler, allowedOrigins []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set header CORS standard
		w.Header().Set("Access-Control-Allow-Origin", strings.Join(allowedOrigins, ", "))
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response.Success(r.Context(), nil))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Manager) envProd() bool {
	return m.cfg.Env == "prod" || m.cfg.Env == "production"
}
