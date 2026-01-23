package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-helper/response"
	"github.com/Jkenyut/nvx-go-middleware/constants"
)

// Config holds the configuration for the middleware manager.
type Config struct {
	LogStore                        LogStore
	RequiredCommonHeaders           []string
	RequiredAuthHeaders             []string
	RequiredPublicAuthHeaders       []string
	SecurityHeaders                 map[string]string
	RequiredSignatureAuthHeaders    []string
	RequiredSignatureMessageHeaders []string
	RequiredSignaturePublicHeaders  []string
	PublicKeySignature              string
	PrivateKeySignature             string
}

// Manager holds the middleware configuration and provides middleware methods.
type Manager struct {
	cfg Config
}

// New creates a new Middleware Manager with the given configuration.
func New(cfg Config) *Manager {
	if cfg.PublicKeySignature == "" || cfg.PrivateKeySignature == "" {
		panic("PublicKey and PrivateKey are required in middleware configuration")
	}

	// Set defaults if nil
	if cfg.LogStore == nil {
		cfg.LogStore = &ConsoleStore{}
	}
	return &Manager{cfg: cfg}
}

// responseWriter is a minimal wrapper for http.ResponseWriter that allows the
// written HTTP status code to be captured for logging.
type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func wrapResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w}
}

func (rw *responseWriter) Status() int {
	return rw.status
}

func (rw *responseWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
	rw.wroteHeader = true
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// LogEntry holds the details of a request/response to be logged.
type LogEntry struct {
	Method   string        `json:"method"`
	URL      string        `json:"url"`
	Status   int           `json:"status"`
	Duration time.Duration `json:"duration"`
}

// LogStore defines the interface for storing log entries.
type LogStore interface {
	Save(entry LogEntry) error
}

// ConsoleStore is a default implementation of LogStore that writes to the console.
type ConsoleStore struct{}

func (cs *ConsoleStore) Save(entry LogEntry) error {
	log.Printf(
		"%s %s %d %s",
		entry.Method,
		entry.URL,
		entry.Status,
		entry.Duration,
	)
	return nil
}

// Logger is a middleware that logs the start and end of each request.
// It uses the configured LogStore to save the log entry.
func (m *Manager) Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapped := wrapResponseWriter(w)
		next.ServeHTTP(wrapped, r)

		entry := LogEntry{
			Method:   r.Method,
			URL:      r.RequestURI,
			Status:   wrapped.Status(),
			Duration: time.Since(start),
		}

		// Save the log entry asynchronously
		go func() {
			if err := m.cfg.LogStore.Save(entry); err != nil {
				log.Printf("Failed to save log: %v", err)
			}
		}()
	})
}

// EnsureCommonHeaders validates headers required for ALL requests.
func (m *Manager) EnsureCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		valid := validateHeaders(w, r, m.cfg.RequiredCommonHeaders)
		if !valid {
			return
		}

		next.ServeHTTP(w, r)
	})
}

// EnsureAuth validates headers required for Authenticated requests and verifies the JWT token.
func (m *Manager) EnsureAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Validate Headers Presence
		valid := validateHeaders(w, r, m.cfg.RequiredAuthHeaders)
		if !valid {
			return
		}

		// 2. Validate JWT Token
		tokenString := r.Header.Get(constants.HeaderGetToken) // Assuming NVX-Token contains the raw Bearer token
		if tokenString == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(response.Unauthorized(r.Context(), constants.ErrMsgInvalidToken))
			return
		}

		if !m.validateSignatureAuthHeaders(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(response.Unauthorized(r.Context(), constants.ErrMsgInvalidSignature))
			return
		}

		// Optional: Store claims in context if needed (User ID, etc.)
		// ctx := context.WithValue(r.Context(), "user_claims", claims)
		// next.ServeHTTP(w, r.WithContext(ctx))

		// For now, just pass through since validation passed
		next.ServeHTTP(w, r)
	})
}

// SecureHeaders adds security-related headers to the response from config.
func (m *Manager) SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, value := range m.cfg.SecurityHeaders {
			w.Header().Set(key, value)
		}

		next.ServeHTTP(w, r)
	})
}

// Recoverer is a middleware that recovers from panics.
func (m *Manager) Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("NVX-Transaction-id", cryptoutil.V7())
		defer func() {
			if err := recover(); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				log.Printf("PANIC: %v", err)

				json.NewEncoder(w).Encode(response.InternalError(r.Context()))
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// EnforceMethods restricts the allowed HTTP methods (GET, POST).
func (m *Manager) EnforceMethods(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)

			json.NewEncoder(w).Encode(response.MethodNotAllowed(r.Context(), constants.ErrMsgMethodNotAllowed))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// validateHeaders is a private helper function.
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

// EnsurePublicAuth validates that the request has a valid User-Agent and other required public headers.
// Required: User-Agent, X-Device-ID, X-Platform, X-Mac-Address.
func (m *Manager) EnsurePublicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		valid := validateHeaders(w, r, m.cfg.RequiredPublicAuthHeaders)
		if !valid {
			return
		}

		// Validate Platform
		validPlatform := false
		for _, v := range constants.CheckPlatform {
			if r.Header.Get(constants.HeaderGetPlatform) == v {
				validPlatform = true
			}
		}

		if !validPlatform {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			json.NewEncoder(w).Encode(response.BadRequest(r.Context(), constants.ErrMsgInvalidPlatform))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Manager) validateSignatureHeaders(r *http.Request, keySignature string, headers []string) bool {
	return r.Header.Get(constants.HeaderGetSignature) == cryptoutil.Signature(keySignature, headers...)
}

func (m *Manager) validateSignatureAuthHeaders(r *http.Request) bool {
	headers := []string{}
	for _, nameHeader := range m.cfg.RequiredSignatureAuthHeaders {
		headers = append(headers, r.Header.Get(nameHeader))
	}

	return m.validateSignatureHeaders(r, m.cfg.PrivateKeySignature, headers)
}

func (m *Manager) validateSignatureMessageHeaders(r *http.Request) bool {
	messageHeaders := []string{}
	for _, nameHeader := range m.cfg.RequiredSignatureMessageHeaders {
		messageHeaders = append(messageHeaders, r.Header.Get(nameHeader))
	}
	messageSignature := cryptoutil.Signature(m.cfg.PublicKeySignature, messageHeaders...)
	

	headers := []string{}
	for _, nameHeader := range m.cfg.RequiredSignaturePublicHeaders {
		headers = append(headers, r.Header.Get(nameHeader))
	}

	return m.validateSignatureHeaders(r, m.cfg.PublicKeySignature, headers)
}
