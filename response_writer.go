package middleware

import (
	"bytes"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

type responseRecorder struct {
	middleware.WrapResponseWriter
	body *bytes.Buffer
}

func wrapResponseWriter(w http.ResponseWriter, r *http.Request) *responseRecorder {
	mw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
	return &responseRecorder{
		WrapResponseWriter: mw,
		body:               &bytes.Buffer{},
	}
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	// detect JSON response
	ct := r.Header().Get("Content-Type")
	if ct == "" || ct == "application/json" {
		r.body.Write(b)
	}

	return r.WrapResponseWriter.Write(b)
}

// Status returns the status code
func (r *responseRecorder) Status() int {
	return r.WrapResponseWriter.Status()
}

// BytesWritten returns the number of bytes written to the body
func (r *responseRecorder) BytesWritten() int {
	return r.WrapResponseWriter.BytesWritten()
}
