package middleware

import (
	"bytes"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

// DefaultResponseBodyLogLimit is the maximum size of response body to log (5MB)
const DefaultResponseBodyLogLimit = 5 * 1024 * 1024

type responseRecorder struct {
	middleware.WrapResponseWriter
	body        *bytes.Buffer
	maxBodySize int
}

func wrapResponseWriter(w http.ResponseWriter, r *http.Request, limit int) *responseRecorder {
	mw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
	return &responseRecorder{
		WrapResponseWriter: mw,
		body:               &bytes.Buffer{},
		maxBodySize:        limit,
	}
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	ct := r.Header().Get("Content-Type")
	if !isMultipart(ct) {
		// Only buffer if we haven't exceeded the limit
		if r.body.Len() < r.maxBodySize {
			remaining := r.maxBodySize - r.body.Len()
			if len(b) > remaining {
				r.body.Write(b[:remaining])
			} else {
				r.body.Write(b)
			}
		}
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
