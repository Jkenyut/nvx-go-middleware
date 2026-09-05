package middleware

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"sync"
)

// responseRecorder is a native http.ResponseWriter that records status, bytes written,
// and the response body up to maxBodySize without requiring third-party router wrappers.
// It implements http.ResponseWriter, http.Flusher, http.Hijacker, io.ReaderFrom, and
// provides Unwrap() for Go 1.20+ http.ResponseController compatibility.
type responseRecorder struct {
	http.ResponseWriter
	status       int
	bytesWritten int
	wroteHeader  bool
	body         *bytes.Buffer
	maxBodySize  int
}

var responseBufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// wrapResponseWriter wraps the response writer with a response recorder.
func wrapResponseWriter(w http.ResponseWriter, _ *http.Request, limit int) *responseRecorder {
	if existingRw, ok := w.(*responseRecorder); ok {
		return existingRw
	}
	buf := responseBufferPool.Get().(*bytes.Buffer)
	buf.Reset()

	return &responseRecorder{
		ResponseWriter: w,
		body:           buf,
		maxBodySize:    limit,
	}
}

// WriteHeader captures the status code and delegates to the underlying ResponseWriter.
func (r *responseRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
		r.ResponseWriter.WriteHeader(code)
	}
}

// Write writes the response body to the buffer and delegates to the underlying ResponseWriter.
func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}

	ct := r.Header().Get("Content-Type")
	if !isMultipart(ct) && r.body != nil && r.maxBodySize > 0 {
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

	n, err := r.ResponseWriter.Write(b)
	r.bytesWritten += n
	return n, err
}

// WriteString implements io.StringWriter to avoid []byte(s) heap allocations when writing strings.
func (r *responseRecorder) WriteString(s string) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}

	ct := r.Header().Get("Content-Type")
	if !isMultipart(ct) && r.body != nil && r.maxBodySize > 0 {
		// Only buffer if we haven't exceeded the limit
		if r.body.Len() < r.maxBodySize {
			remaining := r.maxBodySize - r.body.Len()
			if len(s) > remaining {
				r.body.WriteString(s[:remaining])
			} else {
				r.body.WriteString(s)
			}
		}
	}

	var n int
	var err error
	if sw, ok := r.ResponseWriter.(io.StringWriter); ok {
		n, err = sw.WriteString(s)
	} else {
		n, err = r.ResponseWriter.Write([]byte(s))
	}
	r.bytesWritten += n
	return n, err
}

// Status returns the captured status code (defaults to 200 OK if Write was called without WriteHeader).
func (r *responseRecorder) Status() int {
	if r.status != 0 {
		return r.status
	}
	if sp, ok := r.ResponseWriter.(interface{ Status() int }); ok {
		if s := sp.Status(); s != 0 {
			return s
		}
	}
	return http.StatusOK
}

// BytesWritten returns the total number of bytes written to the client.
func (r *responseRecorder) BytesWritten() int {
	if r.bytesWritten != 0 {
		return r.bytesWritten
	}
	if bp, ok := r.ResponseWriter.(interface{ BytesWritten() int }); ok {
		return bp.BytesWritten()
	}
	return 0
}

// Body returns the bytes buffered in the response recorder.
func (r *responseRecorder) Body() []byte {
	if r.body != nil {
		return r.body.Bytes()
	}
	return nil
}

// Unwrap returns the underlying ResponseWriter, conforming to Go 1.20+ http.ResponseController.
func (r *responseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// Flush implements http.Flusher by forwarding the call if the underlying ResponseWriter supports it.
func (r *responseRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack implements http.Hijacker by forwarding the call if the underlying ResponseWriter supports it.
func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// ReadFrom implements io.ReaderFrom to enable kernel zero-copy (sendfile) transfers.
func (r *responseRecorder) ReadFrom(src io.Reader) (int64, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	if rf, ok := r.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(src)
		r.bytesWritten += int(n)
		return n, err
	}
	n, err := io.Copy(r.ResponseWriter, src)
	r.bytesWritten += int(n)
	return n, err
}

// maxPooledBufferSize is the maximum buffer capacity eligible for recycling back into sync.Pool.
// Buffers larger than 256KB (e.g. from large response body logging) are left for GC
// to prevent permanent heap memory bloat.
const maxPooledBufferSize = 256 * 1024

// Free returns the buffer to the sync.Pool to prevent memory leaks.
// It should be called after the response body is no longer needed.
func (r *responseRecorder) Free() {
	if r.body != nil {
		if r.body.Cap() <= maxPooledBufferSize {
			responseBufferPool.Put(r.body)
		}
		r.body = nil
	}
}
