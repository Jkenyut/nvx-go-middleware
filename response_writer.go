package middleware

import (
	"bytes"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5/middleware"
)

// responseRecorder is a custom response writer that records the response body.
type responseRecorder struct {
	middleware.WrapResponseWriter
	body        *bytes.Buffer
	maxBodySize int
}

var responseBufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// wrapResponseWriter wraps the response writer with a response recorder.
func wrapResponseWriter(w http.ResponseWriter, r *http.Request, limit int) *responseRecorder {
	mw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
	buf := responseBufferPool.Get().(*bytes.Buffer)
	buf.Reset()

	return &responseRecorder{
		WrapResponseWriter: mw,
		body:               buf,
		maxBodySize:        limit,
	}
}

// Write writes the response body to the buffer.
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

// Free returns the buffer to the sync.Pool to prevent memory leaks.
// It should be called after the response body is no longer needed.
func (r *responseRecorder) Free() {
	if r.body != nil {
		responseBufferPool.Put(r.body)
		r.body = nil
	}
}
