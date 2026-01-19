package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

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
// It uses a LogStore to save the log entry.
func Logger(store LogStore, next http.Handler) http.Handler {
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

		// Save the log entry asynchronously to avoid blocking the response
		// Note: For production reliability, consider using a worker pool or similar
		go func() {
			if err := store.Save(entry); err != nil {
				log.Printf("Failed to save log: %v", err)
			}
		}()
	})
}

// EnsureHeaders is a middleware that validates the presence of required headers.
// If any of the required headers are missing, it responds with 400 Bad Request.
func EnsureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requiredHeaders := []string{
			"NVX-Token",
			"NVX-Signature",
			"NVX-IP",
			"NVX-Request-ID",
			"NVX-Merchant-ID",
			"NVX-Datetime",
		}

		missingHeaders := []string{}

		for _, header := range requiredHeaders {
			if r.Header.Get(header) == "" {
				missingHeaders = append(missingHeaders, header)
			}
		}

		if len(missingHeaders) > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			resp := map[string]interface{}{
				"error":   "Missing required headers",
				"missing": missingHeaders,
			}

			json.NewEncoder(w).Encode(resp)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SecureHeaders adds security-related headers to the response.
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		next.ServeHTTP(w, r)
	})
}

// Recoverer is a middleware that recovers from panics, logs the panic (and a
// backtrace), and returns a HTTP 500 (Internal Server Error) status if
// possible.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Printf("PANIC: %v", err)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// EnforceMethods restricts the allowed HTTP methods to the specified list.
// In this case, only GET and POST are allowed.
func EnforceMethods(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)

			resp := map[string]string{
				"error": "Method not allowed. Only GET and POST are permitted.",
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		next.ServeHTTP(w, r)
	})
}
