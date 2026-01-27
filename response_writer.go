package middleware

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
)

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
	if ct == "" || ct == "application/json" {
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

// Status returns the status code
func (r *responseRecorder) Status() int {
	return r.statusCode
}

// BytesWritten returns the number of bytes written to the body
func (r *responseRecorder) BytesWritten() int {
	return r.body.Len()
}
