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

// Logger is a middleware that logs the start and end of each request, along
// with some useful data about what was requested, what the response status was,
// and how long it took to return.
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapped := wrapResponseWriter(w)
		next.ServeHTTP(wrapped, r)

		log.Printf(
			"%s %s %d %s",
			r.Method,
			r.RequestURI,
			wrapped.Status(),
			time.Since(start),
		)
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
