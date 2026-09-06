package middleware

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/Jkenyut/nvx-go-middleware/model"
	"github.com/bytedance/sonic"
)

// MockLogStore captures audit log entries in memory for testing.
type MockLogStore struct {
	mu   sync.Mutex
	Logs []model.AuditLog
}

func (m *MockLogStore) Save(_ context.Context, entry *model.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Logs = append(m.Logs, *entry)
	return nil
}

func (m *MockLogStore) GetLogs() []model.AuditLog {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]model.AuditLog(nil), m.Logs...)
}

// newTestManager creates a Manager with minimal config suitable for unit tests.
func newTestManager(overrides ...func(*Config)) *Manager {
	cfg := Config{
		Security: ConfigSecurity{
			PublicKeySignature:  "test-public-key",
			PrivateKeySignature: "test-private-key",
			AllowedOrigins:      []string{"*"},
		},
		LogStore: &MockLogStore{},
	}
	for _, fn := range overrides {
		fn(&cfg)
	}
	mgr, err := NewWithError(&cfg)
	if err != nil {
		panic(err)
	}
	return mgr
}

// ─── Constructor ─────────────────────────────────────────────────────────────

func TestNewWithError(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				Security: ConfigSecurity{
					PublicKeySignature:  "pub",
					PrivateKeySignature: "priv",
					AllowedOrigins:      []string{"*"},
				},
			},
			wantErr: false,
		},
		{
			name:    "missing keys",
			cfg:     Config{Security: ConfigSecurity{AllowedOrigins: []string{"*"}}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewWithError(&tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewWithError() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ─── Recoverer ───────────────────────────────────────────────────────────────

func TestRecoverer(t *testing.T) {
	mgr := newTestManager()

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	handler := mgr.Recoverer(panicHandler)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}

	var resp map[string]any
	if err := sonic.ConfigDefault.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	meta := resp["meta"].(map[string]any)
	if meta["success"].(bool) {
		t.Error("expected success=false")
	}
}

// ─── Logger ──────────────────────────────────────────────────────────────────

func TestLogger(t *testing.T) {
	store := &MockLogStore{}
	mgr := newTestManager(func(c *Config) { c.LogStore = store })

	handler := mgr.Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))

	req := httptest.NewRequest("POST", "/test", bytes.NewBufferString(`{"hello":"world"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(constants.HeaderRequestID, "req-123")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	time.Sleep(100 * time.Millisecond) // wait for async save

	logs := store.GetLogs()
	if len(logs) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(logs))
	}

	logEntry := logs[0]
	if logEntry.Method != "POST" {
		t.Errorf("expected POST, got %s", logEntry.Method)
	}
	if logEntry.StatusCode != http.StatusOK {
		t.Errorf("expected status to be 200, got %d", logEntry.StatusCode)
	}
	if logEntry.TransactionID == "" {
		t.Error("TransactionID should be set")
	}
}

// ─── MaxBodySize ─────────────────────────────────────────────────────────────

func TestMaxBodySize(t *testing.T) {
	mgr := newTestManager(func(c *Config) {
		// Set both limits; non-file (JSON) limit is the tighter constraint for regular requests.
		c.Limits.RequestBodyLimitSize = 1024 * 1024 // 1 MB (file)
		c.Limits.RequestBodyNonFileLimitSize = 100  // 100 bytes (non-file: JSON etc.)
		c.Security.AllowedContentTypes = []string{"application/json", "multipart/form-data"}
	})

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	tests := []struct {
		name          string
		bodySize      int
		contentLength int64
		contentType   string
		wantStatus    int
	}{
		{"json within limit", 50, 50, "application/json", http.StatusOK},
		{"case-insensitive json within limit", 50, 50, "Application/JSON; charset=utf-8", http.StatusOK},
		{"json exceeds limit", 200, 200, "application/json", http.StatusRequestEntityTooLarge},
		{"multipart within limit", 50, 50, "multipart/form-data; boundary=x", http.StatusOK},
		{"unsupported content type", 50, 50, "text/plain", http.StatusBadRequest},
		{"no body no content type (GET-like)", 0, 0, "", http.StatusOK},
		{"bodyless with -1 content length", 0, -1, "", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bodyReader *bytes.Reader
			if tt.bodySize > 0 {
				body := bytes.Repeat([]byte("a"), tt.bodySize)
				bodyReader = bytes.NewReader(body)
			} else {
				bodyReader = bytes.NewReader([]byte{})
			}
			req := httptest.NewRequest("POST", "/test", bodyReader)
			req.ContentLength = tt.contentLength
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			w := httptest.NewRecorder()
			mgr.MaxBodySize()(ok).ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("expected %d, got %d", tt.wantStatus, w.Code)
			}
		})
	}
}

// ─── MethodOnly ──────────────────────────────────────────────────────────────

func TestMethodOnly(t *testing.T) {
	mgr := newTestManager()
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	tests := []struct {
		allowed string
		method  string
		want    int
	}{
		{"POST", "POST", http.StatusOK},
		{"POST", "GET", http.StatusMethodNotAllowed},
		{"GET", "DELETE", http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, "/", nil)
		w := httptest.NewRecorder()
		mgr.MethodOnly(tt.allowed, ok).ServeHTTP(w, req)
		if w.Code != tt.want {
			t.Errorf("MethodOnly(%s) with %s: expected %d got %d", tt.allowed, tt.method, tt.want, w.Code)
		}
	}
}

// ─── CORS ─────────────────────────────────────────────────────────────────────

func TestCORS(t *testing.T) {
	mgr := newTestManager(func(c *Config) {
		c.Security.AllowedOrigins = []string{"https://example.com"}
	})
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	t.Run("allowed origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()
		mgr.CORS(ok, []string{"https://example.com"}, []string{"Content-Type"}).ServeHTTP(w, req)

		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
			t.Errorf("expected ACAO header, got %q", got)
		}
		if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
			t.Errorf("expected ACAC=true, got %q", got)
		}
	})

	t.Run("disallowed origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "https://evil.com")
		w := httptest.NewRecorder()
		mgr.CORS(ok, []string{"https://example.com"}, []string{}).ServeHTTP(w, req)

		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("expected no ACAO header for disallowed origin, got %q", got)
		}
	})

	t.Run("preflight", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/", nil)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()
		mgr.CORS(ok, []string{"https://example.com"}, []string{"Content-Type"}).ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("expected 204, got %d", w.Code)
		}
	})
}

// ─── TrustProxy ──────────────────────────────────────────────────────────────

func TestTrustProxy(t *testing.T) {
	t.Run("docker container with X-Real-Ip without trusted proxies config", func(t *testing.T) {
		mgr := newTestManager() // No trustedProxies configured

		var capturedIP, capturedOrigin string
		handler := mgr.TrustProxy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedIP = r.Header.Get(constants.HeaderIP)
			capturedOrigin = r.Header.Get(constants.HeaderIPOrigin)
		}))

		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "172.18.0.4:54321" // Docker bridge IP
		req.Header.Set("X-Real-Ip", "43.133.91.48")
		req.Header.Set("X-Forwarded-For", "172.18.0.4")
		handler.ServeHTTP(httptest.NewRecorder(), req)

		if capturedIP != "43.133.91.48" {
			t.Errorf("expected 43.133.91.48, got %s", capturedIP)
		}
		if capturedOrigin != "172.18.0.4" {
			t.Errorf("expected 172.18.0.4, got %s", capturedOrigin)
		}
	})

	t.Run("docker container with XFF chain extracts public IP", func(t *testing.T) {
		mgr := newTestManager()

		var capturedIP string
		handler := mgr.TrustProxy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedIP = r.Header.Get(constants.HeaderIP)
		}))

		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "172.18.0.4:12345"
		req.Header.Set("X-Forwarded-For", "43.133.91.48, 10.0.0.1")
		handler.ServeHTTP(httptest.NewRecorder(), req)

		if capturedIP != "43.133.91.48" {
			t.Errorf("expected 43.133.91.48, got %s", capturedIP)
		}
	})

	t.Run("cloudflare header takes highest priority from trusted/private proxy", func(t *testing.T) {
		mgr := newTestManager()

		var capturedIP string
		handler := mgr.TrustProxy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedIP = r.Header.Get(constants.HeaderIP)
		}))

		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("CF-Connecting-IP", "103.21.244.2")
		req.Header.Set("X-Real-Ip", "43.133.91.48")
		handler.ServeHTTP(httptest.NewRecorder(), req)

		if capturedIP != "103.21.244.2" {
			t.Errorf("expected 103.21.244.2, got %s", capturedIP)
		}
	})

	t.Run("untrusted direct public connection keeps remote IP and ignores spoofing", func(t *testing.T) {
		mgr := newTestManager()

		var capturedIP string
		handler := mgr.TrustProxy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedIP = r.Header.Get(constants.HeaderIP)
		}))

		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "5.5.5.5:9000" // Public IP
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		req.Header.Set("X-Real-Ip", "1.2.3.4")
		handler.ServeHTTP(httptest.NewRecorder(), req)

		if capturedIP != "5.5.5.5" {
			t.Errorf("expected 5.5.5.5, got %s", capturedIP)
		}
	})

	t.Run("xff public ip takes precedence over spoofed x-real-ip from trusted proxy", func(t *testing.T) {
		mgr := newTestManager()

		var capturedIP, capturedRemote string
		handler := mgr.TrustProxy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedIP = r.Header.Get(constants.HeaderIP)
			capturedRemote = r.RemoteAddr
		}))

		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "127.0.0.1:45678"                // Trusted local proxy (e.g. Traefik)
		req.Header.Set("X-Forwarded-For", "203.0.113.50") // Legitimate client IP
		req.Header.Set("X-Real-Ip", "8.8.8.8")            // Spoofed X-Real-Ip header
		handler.ServeHTTP(httptest.NewRecorder(), req)

		if capturedIP != "203.0.113.50" {
			t.Errorf("expected 203.0.113.50 from XFF, got %s", capturedIP)
		}
		if capturedRemote != "203.0.113.50:45678" {
			t.Errorf("expected RemoteAddr to preserve port 45678, got %s", capturedRemote)
		}
	})
}

// ─── ResolveBodyToken ────────────────────────────────────────────────────────

func TestResolveBodyToken(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        []byte
		wantPrefix  string
		wantExact   string
	}{
		{"multipart returns UNSIGNED", "multipart/form-data; boundary=x", []byte("data"), "", "UNSIGNED"},
		{"binary octet-stream returns UNSIGNED", "application/octet-stream", []byte("binary"), "", "UNSIGNED"},
		{"binary image returns UNSIGNED", "image/png", []byte("png"), "", "UNSIGNED"},
		{"binary pdf returns UNSIGNED", "application/pdf", []byte("%PDF-1.4"), "", "UNSIGNED"},
		{"empty body returns EMPTY", "application/json", []byte{}, "", "EMPTY"},
		{"nil body returns EMPTY", "application/json", nil, "", "EMPTY"},
		{"json body returns sha256", "application/json", []byte(`{"a":1}`), "hex:", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveBodyToken(tt.contentType, tt.body)
			if tt.wantExact != "" && got != tt.wantExact {
				t.Errorf("expected %q, got %q", tt.wantExact, got)
			}
			if tt.wantPrefix == "hex:" && (len(got) != 64) {
				t.Errorf("expected 64-char hex sha256, got %q (len=%d)", got, len(got))
			}
		})
	}
}

// ─── FullURL ─────────────────────────────────────────────────────────────────

func TestFullURL(t *testing.T) {
	t.Run("http scheme default", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/foo?bar=1", nil)
		req.Host = "example.com"
		url := FullURL(req)
		if !strings.HasPrefix(url, "http://example.com") {
			t.Errorf("unexpected url: %s", url)
		}
	})

	t.Run("https via X-Forwarded-Proto", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/foo", nil)
		req.Host = "example.com"
		req.Header.Set("X-Forwarded-Proto", "https")
		url := FullURL(req)
		if !strings.HasPrefix(url, "https://") {
			t.Errorf("expected https, got %s", url)
		}
	})

	t.Run("X-Forwarded-Proto injection blocked", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/foo", nil)
		req.Host = "example.com"
		req.Header.Set("X-Forwarded-Proto", "ftp") // not https
		url := FullURL(req)
		if !strings.HasPrefix(url, "http://") {
			t.Errorf("expected http fallback for unknown proto, got %s", url)
		}
	})
}

// ─── Heartbeat ───────────────────────────────────────────────────────────────

func TestHeartbeat(t *testing.T) {
	t.Run("responds to matching path", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
		h := Heartbeat("/ping")(next)

		req := httptest.NewRequest("GET", "/ping", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		if w.Body.String() != "OK" {
			t.Errorf("expected OK body, got %q", w.Body.String())
		}
	})

	t.Run("forwards other paths to next", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
		h := Heartbeat("/ping")(next)

		req := httptest.NewRequest("GET", "/other", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusTeapot {
			t.Errorf("expected 418 (forwarded to next), got %d", w.Code)
		}
	})
}

// ─── GraphQL depth ───────────────────────────────────────────────────────────

func TestGraphqlQueryDepth(t *testing.T) {
	tests := []struct {
		query string
		want  int
	}{
		{"{ user { name } }", 1},
		{"{ user { posts { comments { author { name } } } } }", 4},
		{"{ a }", 0},
		{"query { a { b { c { d { e } } } } }", 4},
	}

	for _, tt := range tests {
		got := graphqlQueryDepth(tt.query)
		if got != tt.want {
			t.Errorf("depth(%q) = %d, want %d", tt.query, got, tt.want)
		}
	}
}

// ─── RemoveHeaders ───────────────────────────────────────────────────────────

func TestRemoveHeaders(t *testing.T) {
	mgr := newTestManager(func(c *Config) {
		c.Security.HeadersToRemove = []string{"X-Powered-By", "Server"}
	})

	handler := mgr.RemoveHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Go")
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got := w.Header().Get("X-Powered-By"); got != "" {
		t.Errorf("X-Powered-By should be removed, got %q", got)
	}
	if got := w.Header().Get("Server"); got != "" {
		t.Errorf("Server should be removed, got %q", got)
	}
	if got := w.Header().Get("Content-Type"); got == "" {
		t.Error("Content-Type should be preserved")
	}

	t.Run("strips headers even on direct Write without WriteHeader", func(t *testing.T) {
		handlerWrite := mgr.RemoveHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Powered-By", "Go")
			w.Header().Set("Server", "nginx")
			_, _ = w.Write([]byte("direct body without WriteHeader"))
		}))

		w2 := httptest.NewRecorder()
		handlerWrite.ServeHTTP(w2, req)

		if got := w2.Header().Get("X-Powered-By"); got != "" {
			t.Errorf("X-Powered-By should be removed on direct Write, got %q", got)
		}
		if got := w2.Header().Get("Server"); got != "" {
			t.Errorf("Server should be removed on direct Write, got %q", got)
		}
	})

	t.Run("supports native Unwrap and Status inspection", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rw := &headerCleanerResponseWriter{
			ResponseWriter:  rec,
			headersToRemove: []string{"Server"},
		}
		if rw.Unwrap() != rec {
			t.Error("expected Unwrap to return underlying recorder")
		}

		// Status and BytesWritten return 0 when underlying does not implement them
		if rw.Status() != 0 {
			t.Errorf("expected Status 0, got %d", rw.Status())
		}
		if rw.BytesWritten() != 0 {
			t.Errorf("expected BytesWritten 0, got %d", rw.BytesWritten())
		}
	})

	t.Run("supports Hijack and Flush", func(t *testing.T) {
		rw := &headerCleanerResponseWriter{
			ResponseWriter:  httptest.NewRecorder(),
			headersToRemove: []string{"Server"},
		}
		rw.Flush()
		if !rw.cleaned {
			t.Error("expected cleaned to be true after Flush")
		}

		_, _, err := rw.Hijack()
		if err == nil {
			t.Error("expected error when underlying does not implement Hijacker")
		}

		// ReadFrom test
		rw2 := &headerCleanerResponseWriter{
			ResponseWriter:  httptest.NewRecorder(),
			headersToRemove: []string{"Server"},
		}
		rw2.Header().Set("Server", "nginx")
		n, err := rw2.ReadFrom(strings.NewReader("hello from reader"))
		if err != nil {
			t.Errorf("unexpected error on ReadFrom: %v", err)
		}
		if n != 17 {
			t.Errorf("expected 17 bytes read, got %d", n)
		}
		if !rw2.cleaned {
			t.Error("expected cleaned to be true after ReadFrom")
		}
		if got := rw2.Header().Get("Server"); got != "" {
			t.Errorf("Server should be removed on ReadFrom, got %q", got)
		}

		// WriteString test
		rw3 := &headerCleanerResponseWriter{
			ResponseWriter:  httptest.NewRecorder(),
			headersToRemove: []string{"Server"},
		}
		rw3.Header().Set("Server", "nginx")
		sn, serr := io.WriteString(rw3, "string test")
		if serr != nil || sn != 11 {
			t.Errorf("unexpected error on WriteString: %v, sn: %d", serr, sn)
		}
		if !rw3.cleaned {
			t.Error("expected cleaned to be true after WriteString")
		}
		if got := rw3.Header().Get("Server"); got != "" {
			t.Errorf("Server should be removed on WriteString, got %q", got)
		}
	})
}

// ─── UUID Headers Validation ──────────────────────────────────────────────────

func TestRequireUUIDHeaders(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	tests := []struct {
		name           string
		headers        map[string]string
		checkHeaders   []string
		expectedStatus int
	}{
		{
			name: "valid UUID v4",
			headers: map[string]string{
				"X-User-Id": "123e4567-e89b-12d3-a456-426614174000",
			},
			checkHeaders:   []string{"X-User-Id"},
			expectedStatus: http.StatusOK,
		},
		{
			name: "missing required header",
			headers: map[string]string{
				"Other-Header": "value",
			},
			checkHeaders:   []string{"X-User-Id"},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "invalid UUID string",
			headers: map[string]string{
				"X-User-Id": "invalid-not-a-uuid",
			},
			checkHeaders:   []string{"X-User-Id"},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "multiple valid UUID headers",
			headers: map[string]string{
				"X-User-Id":    "123e4567-e89b-12d3-a456-426614174000",
				"X-Request-Id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
			},
			checkHeaders:   []string{"X-User-Id", "X-Request-Id"},
			expectedStatus: http.StatusOK,
		},
		{
			name: "one valid one invalid among multiple",
			headers: map[string]string{
				"X-User-Id":    "123e4567-e89b-12d3-a456-426614174000",
				"X-Request-Id": "12345",
			},
			checkHeaders:   []string{"X-User-Id", "X-Request-Id"},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			standaloneHandler := RequireUUIDHeaders(tc.checkHeaders...)(okHandler)
			reqStandalone := httptest.NewRequest("GET", "/test", nil)
			for k, v := range tc.headers {
				reqStandalone.Header.Set(k, v)
			}
			wStandalone := httptest.NewRecorder()
			standaloneHandler.ServeHTTP(wStandalone, reqStandalone)
			if wStandalone.Code != tc.expectedStatus {
				t.Errorf("RequireUUIDHeaders standalone: expected status %d, got %d. Body: %s", tc.expectedStatus, wStandalone.Code, wStandalone.Body.String())
			}
		})
	}
}

func TestValidateOptionalUUIDHeaders(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	tests := []struct {
		name           string
		headers        map[string]string
		checkHeaders   []string
		expectedStatus int
	}{
		{
			name:           "empty/omitted header is allowed",
			headers:        map[string]string{},
			checkHeaders:   []string{"X-User-Id"},
			expectedStatus: http.StatusOK,
		},
		{
			name: "present valid UUID is allowed",
			headers: map[string]string{
				"X-User-Id": "123e4567-e89b-12d3-a456-426614174000",
			},
			checkHeaders:   []string{"X-User-Id"},
			expectedStatus: http.StatusOK,
		},
		{
			name: "present invalid UUID returns 400",
			headers: map[string]string{
				"X-User-Id": "abc-123-not-uuid",
			},
			checkHeaders:   []string{"X-User-Id"},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			standaloneHandler := ValidateOptionalUUIDHeaders(tc.checkHeaders...)(okHandler)
			reqStandalone := httptest.NewRequest("GET", "/test", nil)
			for k, v := range tc.headers {
				reqStandalone.Header.Set(k, v)
			}
			wStandalone := httptest.NewRecorder()
			standaloneHandler.ServeHTTP(wStandalone, reqStandalone)
			if wStandalone.Code != tc.expectedStatus {
				t.Errorf("ValidateOptionalUUIDHeaders standalone: expected status %d, got %d", tc.expectedStatus, wStandalone.Code)
			}
		})
	}
}

// ─── WithActivityContext & Signature Tests ──────────────────────────────────

func TestWithActivityContext(t *testing.T) {
	keys := &HeaderKeys{
		RequestID:     constants.HeaderRequestID,
		TransactionID: constants.HeaderTransactionID,
		IP:            constants.HeaderIP,
		IPOrigin:      constants.HeaderIPOrigin,
		UserID:        constants.HeaderUserID,
		APIKey:        constants.HeaderAPIKey,
		AuthType:      constants.HeaderAuthType,
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(constants.HeaderRequestID, "req-1")
	req.Header.Set(constants.HeaderTransactionID, "tx-1")
	req.Header.Set(constants.HeaderUserID, "user-123")

	reqEnriched := WithActivityContext(req, keys)
	if reqEnriched == nil {
		t.Fatal("expected non-nil request")
	}

	// Nil keys test
	reqNil := WithActivityContext(req, nil)
	if reqNil != req {
		t.Fatal("expected same request pointer when keys is nil")
	}
}

func TestSignatureValidationPublic(t *testing.T) {
	mgr := newTestManager()
	handler := mgr.EnsurePublic(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	now := strconv.FormatInt(time.Now().Unix(), 10)
	reqID := "req-123"
	platform := "web"
	userAgent := "Mozilla/5.0"
	method := "POST"
	path := "/test-endpoint"
	bodyContent := `{"name":"test"}`
	bodyBytes := []byte(bodyContent)
	bodyToken := ResolveBodyToken("application/json", bodyBytes)

	// Canonical: METHOD, URI, HeaderRequestID, HeaderPlatform, HeaderTimestamp, BodyToken
	canonical := []string{
		method,
		path,
		reqID,
		platform,
		now,
		bodyToken,
	}
	validSig := cryptoutil.Signature("test-public-key", canonical...)

	req := httptest.NewRequest(method, path, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(constants.HeaderRequestID, reqID)
	req.Header.Set(constants.HeaderPlatform, platform)
	req.Header.Set(constants.HeaderUserAgent, userAgent)
	req.Header.Set(constants.HeaderTimestamp, now)
	req.Header.Set(constants.HeaderSignature, validSig)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	// Tampered signature should fail with 401
	reqTampered := httptest.NewRequest(method, path, bytes.NewReader(bodyBytes))
	reqTampered.Header.Set("Content-Type", "application/json")
	reqTampered.Header.Set(constants.HeaderRequestID, reqID)
	reqTampered.Header.Set(constants.HeaderPlatform, platform)
	reqTampered.Header.Set(constants.HeaderUserAgent, userAgent)
	reqTampered.Header.Set(constants.HeaderTimestamp, now)
	reqTampered.Header.Set(constants.HeaderSignature, "invalid-sig")

	wTampered := httptest.NewRecorder()
	handler.ServeHTTP(wTampered, reqTampered)

	if wTampered.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for tampered signature, got %d", wTampered.Code)
	}

	// Missing header should fail with 400
	reqMissing := httptest.NewRequest(method, path, bytes.NewReader(bodyBytes))
	reqMissing.Header.Set("Content-Type", "application/json")
	reqMissing.Header.Set(constants.HeaderPlatform, platform)
	reqMissing.Header.Set(constants.HeaderSignature, validSig)

	wMissing := httptest.NewRecorder()
	handler.ServeHTTP(wMissing, reqMissing)

	if wMissing.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for missing headers, got %d", wMissing.Code)
	}
}

func TestConsoleStore_NilLogger(t *testing.T) {
	store := &ConsoleStore{logger: nil}
	err := store.Save(context.Background(), &model.AuditLog{
		ServiceName: "test-service",
	})
	if err != nil {
		t.Fatalf("expected nil error when logger is nil, got %v", err)
	}
}

func TestGraphqlQueryDepth_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  int
	}{
		{name: "empty query", query: "", want: 0},
		{name: "no braces query", query: "query MyQuery", want: 0},
		{name: "single level braces", query: "{ user }", want: 0},
		{name: "nested 2 levels", query: "{ user { profile } }", want: 1},
		{name: "nested 3 levels", query: "{ user { profile { avatar } } }", want: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := graphqlQueryDepth(tt.query)
			if got != tt.want {
				t.Errorf("graphqlQueryDepth(%q) = %d, want %d", tt.query, got, tt.want)
			}
		})
	}
}

func TestNewSlogLogger(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := NewSlogLogger(slog.New(handler))

	logger.Info("test info message", slog.String("key", "value"), slog.Int("status", 200))
	logger.Error("test error formatted detail", slog.String("errKey", "errVal"), slog.Any("error", errors.New("custom error")))

	output := buf.String()
	if !strings.Contains(output, "test info message") {
		t.Errorf("expected info message in output, got: %s", output)
	}
	if !strings.Contains(output, "test error formatted detail") {
		t.Errorf("expected error message in output, got: %s", output)
	}
	if !strings.Contains(output, "custom error") {
		t.Errorf("expected error attribute in output, got: %s", output)
	}
}

func TestFullURL_SanitizedHost(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Host = "legit.example.com"
	req.Header.Set("X-Forwarded-Host", "attacker.com\r\nInjected-Header: evil")

	url := FullURL(req)
	if strings.Contains(url, "Injected-Header") || strings.Contains(url, "attacker.com") {
		t.Errorf("expected malicious X-Forwarded-Host to be rejected, got: %s", url)
	}
	if !strings.Contains(url, "legit.example.com") {
		t.Errorf("expected fallback to legit host, got: %s", url)
	}
}

func TestRateLimit(t *testing.T) {
	limiterCfg := ConfigLimiter{
		RateLimitRequests: 2,
		RateLimitWindow:   1, // 1 minute
	}

	handler := RateLimit(limiterCfg, "test-secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Received-Rate-Key", r.Header.Get(constants.HeaderRateKey))
		w.WriteHeader(http.StatusOK)
	}))

	// Request 1: should pass and receive rate key
	req1 := httptest.NewRequest("GET", "/api/test", nil)
	req1.Header.Set(constants.HeaderIP, "192.168.1.100")
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on request 1, got %d", w1.Code)
	}
	if w1.Header().Get("X-Received-Rate-Key") == "" {
		t.Error("expected X-Rate-Key to be injected into request")
	}

	// Request 2: should pass
	req2 := httptest.NewRequest("GET", "/api/test", nil)
	req2.Header.Set(constants.HeaderIP, "192.168.1.100")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on request 2, got %d", w2.Code)
	}

	// Request 3: should be rate limited (429)
	req3 := httptest.NewRequest("GET", "/api/test", nil)
	req3.Header.Set(constants.HeaderIP, "192.168.1.100")
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)

	if w3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests on request 3, got %d", w3.Code)
	}

	// OPTIONS request should bypass rate limiting
	reqOptions := httptest.NewRequest("OPTIONS", "/api/test", nil)
	reqOptions.Header.Set(constants.HeaderIP, "192.168.1.100")
	wOptions := httptest.NewRecorder()
	handler.ServeHTTP(wOptions, reqOptions)

	if wOptions.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on OPTIONS bypass, got %d", wOptions.Code)
	}
}

func TestGraphQLChain(t *testing.T) {
	mgr := newTestManager()

	var capturedOp string
	graphqlHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedOp = r.Header.Get("X-GraphQL-Operation")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"user":{"id":"1"}}}`))
	})

	// maxDepth = 2
	chain := mgr.GraphQLChain(2)(graphqlHandler)

	// Valid query with depth 1
	validBody := `{"query":"query GetUser { user { id } }","operationName":"GetUser"}`
	reqValid := httptest.NewRequest("POST", "/graphql", bytes.NewBufferString(validBody))
	reqValid.Header.Set("Content-Type", "application/json")
	wValid := httptest.NewRecorder()
	chain.ServeHTTP(wValid, reqValid)

	if wValid.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid GraphQL query, got %d: %s", wValid.Code, wValid.Body.String())
	}
	if capturedOp != "GetUser" {
		t.Errorf("expected operationName 'GetUser', got %q", capturedOp)
	}

	// Deep query with depth 3 (exceeds maxDepth 2)
	deepBody := `{"query":"query Deep { user { profile { avatar { url } } } }","operationName":"Deep"}`
	reqDeep := httptest.NewRequest("POST", "/graphql", bytes.NewBufferString(deepBody))
	reqDeep.Header.Set("Content-Type", "application/json")
	wDeep := httptest.NewRecorder()
	chain.ServeHTTP(wDeep, reqDeep)

	if wDeep.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for exceeding depth, got %d", wDeep.Code)
	}
}

func TestWebSocketChain(t *testing.T) {
	mgr := newTestManager()

	wsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusSwitchingProtocols)
	})

	authenticator := func(r *http.Request) bool {
		return r.Header.Get("Authorization") == "Bearer valid-token"
	}

	chain := mgr.WebSocketChain(authenticator)(wsHandler)

	// Test 1: Non-websocket request returns 400
	reqNonWS := httptest.NewRequest("GET", "/ws", nil)
	wNonWS := httptest.NewRecorder()
	chain.ServeHTTP(wNonWS, reqNonWS)

	if wNonWS.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-WS request, got %d", wNonWS.Code)
	}

	// Test 2: WebSocket request with invalid auth returns 401
	reqAuthFail := httptest.NewRequest("GET", "/ws", nil)
	reqAuthFail.Header.Set("Upgrade", "websocket")
	reqAuthFail.Header.Set("Connection", "Upgrade")
	wAuthFail := httptest.NewRecorder()
	chain.ServeHTTP(wAuthFail, reqAuthFail)

	if wAuthFail.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthorized WS upgrade, got %d", wAuthFail.Code)
	}

	// Test 3: WebSocket request with valid auth succeeds
	reqSuccess := httptest.NewRequest("GET", "/ws", nil)
	reqSuccess.Header.Set("Upgrade", "websocket")
	reqSuccess.Header.Set("Connection", "Upgrade")
	reqSuccess.Header.Set("Authorization", "Bearer valid-token")
	wSuccess := httptest.NewRecorder()
	chain.ServeHTTP(wSuccess, reqSuccess)

	if wSuccess.Code != http.StatusSwitchingProtocols {
		t.Errorf("expected 101 SwitchingProtocols, got %d", wSuccess.Code)
	}
}

func TestGraphQLQueryDepth_StringsAndComments(t *testing.T) {
	// Query with braces inside strings and comments
	query := `
		query GetUser {
			# { this comment has braces { { {
			user(filter: "{ not a nested query }", note: "escaped \" { quote") {
				id
				name
			}
		}
	`
	depth := graphqlQueryDepth(query)
	if depth != 1 {
		t.Errorf("expected depth 1, got %d", depth)
	}
}

func TestGraphQLBlockIntrospection_GET(t *testing.T) {
	mgr := newTestManager()
	handler := mgr.GraphQLBlockIntrospection(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	// GET request with __schema introspection
	req := httptest.NewRequest("GET", "/graphql?query={__schema{types{name}}}", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for GET introspection, got %d", w.Code)
	}

	// GET request with normal query
	reqNormal := httptest.NewRequest("GET", "/graphql?query={user{id}}", nil)
	wNormal := httptest.NewRecorder()
	handler.ServeHTTP(wNormal, reqNormal)

	if wNormal.Code != http.StatusOK {
		t.Errorf("expected 200 OK for normal GET query, got %d", wNormal.Code)
	}
}

type mockContextCapturingStore struct {
	onSave func(ctx context.Context, entry *model.AuditLog) error
}

func (m *mockContextCapturingStore) Save(ctx context.Context, entry *model.AuditLog) error {
	if m.onSave != nil {
		return m.onSave(ctx, entry)
	}
	return nil
}

func TestLogger_ContextCancelledPreservation(t *testing.T) {
	var capturedCtx context.Context
	var mu sync.Mutex

	customStore := &mockContextCapturingStore{
		onSave: func(ctx context.Context, _ *model.AuditLog) error {
			mu.Lock()
			capturedCtx = ctx
			mu.Unlock()
			return nil
		},
	}

	mgr := newTestManager(func(c *Config) {
		c.LogStore = customStore
	})

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)

	handler := mgr.Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Cancel context mid-flight
		cancel()
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	mu.Lock()
	defer mu.Unlock()
	if capturedCtx == nil {
		t.Fatal("expected capturedCtx to be non-nil")
	}
	if err := capturedCtx.Err(); err != nil {
		t.Errorf("expected log context to remain active (without cancel), got err: %v", err)
	}
}

func TestResponseRecorder_BufferPoolCapLimit(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)

	// Case 1: Normal body (< 256KB)
	rec1 := wrapResponseWriter(w, r, 1024)
	_, _ = rec1.Write([]byte("small response"))
	rec1.Free()

	// Case 2: Huge buffer (> 256KB)
	rec2 := wrapResponseWriter(w, r, 5*1024*1024)
	hugeData := make([]byte, 300*1024)
	_, _ = rec2.Write(hugeData)
	if rec2.body.Cap() <= maxPooledBufferSize {
		t.Fatalf("expected buffer cap > %d, got %d", maxPooledBufferSize, rec2.body.Cap())
	}
	rec2.Free()
	if rec2.body != nil {
		t.Error("expected rec2.body to be nil after Free()")
	}
}

func TestResponseRecorder_NativeInterfaces(t *testing.T) {
	inner := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)

	rec := wrapResponseWriter(inner, r, 1024)

	// Idempotent wrapResponseWriter returns same pointer
	if wrapResponseWriter(rec, r, 1024) != rec {
		t.Error("expected wrapResponseWriter to return existing *responseRecorder")
	}

	// Unwrap
	if rec.Unwrap() != inner {
		t.Errorf("expected Unwrap to return inner recorder, got %v", rec.Unwrap())
	}

	// Default status before write
	if rec.Status() != http.StatusOK {
		t.Errorf("expected default Status 200, got %d", rec.Status())
	}

	// WriteHeader
	rec.WriteHeader(http.StatusCreated)
	if rec.Status() != http.StatusCreated {
		t.Errorf("expected Status 201, got %d", rec.Status())
	}
	// Secondary WriteHeader should be ignored
	rec.WriteHeader(http.StatusBadRequest)
	if rec.Status() != http.StatusCreated {
		t.Errorf("expected Status to remain 201, got %d", rec.Status())
	}

	// Write
	payload := []byte("hello world")
	n, err := rec.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("unexpected Write result: n=%d, err=%v", n, err)
	}
	if rec.BytesWritten() != len(payload) {
		t.Errorf("expected BytesWritten %d, got %d", len(payload), rec.BytesWritten())
	}
	if string(rec.Body()) != "hello world" {
		t.Errorf("expected Body 'hello world', got %q", string(rec.Body()))
	}

	// WriteString (io.StringWriter)
	strPayload := " additional text"
	sn, serr := io.WriteString(rec, strPayload)
	if serr != nil || sn != len(strPayload) {
		t.Fatalf("unexpected WriteString result: sn=%d, err=%v", sn, serr)
	}
	if !strings.Contains(string(rec.Body()), "additional text") {
		t.Errorf("expected Body to contain 'additional text', got %q", string(rec.Body()))
	}

	// Flush (httptest.ResponseRecorder implements http.Flusher)
	rec.Flush()
	if !inner.Flushed {
		t.Error("expected inner recorder to be flushed")
	}

	// ReadFrom
	src := bytes.NewReader([]byte(" extra data"))
	rn, rerr := rec.ReadFrom(src)
	if rerr != nil || rn != int64(len(" extra data")) {
		t.Fatalf("unexpected ReadFrom result: rn=%d, err=%v", rn, rerr)
	}

	// Free
	rec.Free()
	if rec.Body() != nil {
		t.Error("expected Body() to be nil after Free()")
	}
}

func TestBuildInnerChain_CompressAndLogger(t *testing.T) {
	mockStore := &MockLogStore{}
	mgr := newTestManager(func(c *Config) {
		c.LogStore = mockStore
		c.Logging.LogResponseBodies = true
		c.Logging.ResponseBodyLogLimitSize = 4096
	})

	cfg := &ChainConfig{
		Features: ChainFeatures{
			UseChiCompress: true,
		},
		Compression: ChainCompression{
			CompressionLevel: 5,
		},
	}
	cfg.ApplyDefaults()

	jsonResponse := `{"status":"ok","message":"compressed payload"}`
	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jsonResponse))
	})

	chain := mgr.buildInnerChain(cfg, appHandler)

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	// 1. Verify client received gzip compressed body
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("expected Content-Encoding 'gzip', got %q", rec.Header().Get("Content-Encoding"))
	}

	gzReader, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader from response: %v", err)
	}
	decompressed, err := io.ReadAll(gzReader)
	if err != nil {
		t.Fatalf("failed to read decompressed gzip data: %v", err)
	}
	_ = gzReader.Close()

	if string(decompressed) != jsonResponse {
		t.Errorf("expected decompressed body %q, got %q", jsonResponse, string(decompressed))
	}

	// 2. Verify Audit Log recorded readable uncompressed JSON (not raw gzip binary)
	logs := mockStore.GetLogs()
	if len(logs) == 0 {
		t.Fatal("expected 1 audit log entry to be recorded")
	}
	logEntry := logs[0]
	if logEntry.StatusCode != http.StatusOK {
		t.Errorf("expected log StatusCode 200, got %d", logEntry.StatusCode)
	}

	// ResBody should be parsed as map[string]any or uncompressed string, NOT binary gzip
	m, ok := logEntry.ResponseBody.(map[string]any)
	if !ok {
		t.Fatalf("expected log ResponseBody to be uncompressed JSON map, got %T: %v", logEntry.ResponseBody, logEntry.ResponseBody)
	}
	if m["status"] != "ok" || m["message"] != "compressed payload" {
		t.Errorf("unexpected logged response body values: %+v", m)
	}
}

func TestManager_Config_Close(t *testing.T) {
	mgr := newTestManager()
	cfg := mgr.Config()
	if cfg.Security.PublicKeySignature != "test-public-key" {
		t.Errorf("unexpected PublicKeySignature: %s", cfg.Security.PublicKeySignature)
	}
	if err := mgr.Close(); err != nil {
		t.Errorf("unexpected error on Close: %v", err)
	}
}

func TestPingHandler(t *testing.T) {
	mgr := newTestManager()
	handler := mgr.PingHandler()

	// GET -> 200 pong
	req := httptest.NewRequest("GET", "/ping", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pong") {
		t.Errorf("expected response to contain 'pong', got %s", rec.Body.String())
	}

	// POST -> 405 Method Not Allowed
	reqPost := httptest.NewRequest("POST", "/ping", nil)
	recPost := httptest.NewRecorder()
	handler.ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", recPost.Code)
	}
}

func TestApplyMiddleware(t *testing.T) {
	var order []string
	mw1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "mw1-before")
			next.ServeHTTP(w, r)
			order = append(order, "mw1-after")
		})
	}
	mw2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "mw2-before")
			next.ServeHTTP(w, r)
			order = append(order, "mw2-after")
		})
	}

	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "final")
	})

	chained := ApplyMiddleware(final, mw1, mw2)
	chained.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	expected := []string{"mw1-before", "mw2-before", "final", "mw2-after", "mw1-after"}
	if !slices.Equal(order, expected) {
		t.Errorf("expected execution order %v, got %v", expected, order)
	}
}

func TestWebhookChain(t *testing.T) {
	mgr := newTestManager()
	cfg := &ChainConfig{}
	cfg.ApplyDefaults()

	called := false
	handler := mgr.WebhookChain(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(`{"event":"test"}`))
	req.Header.Set("Content-Type", "application/json")

	handler.ServeHTTP(rec, req)
	if !called {
		t.Error("expected webhook handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

// ─── Benchmarks ──────────────────────────────────────────────────────────────

func BenchmarkLogger(b *testing.B) {
	mgr := newTestManager()
	handler := mgr.Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(constants.HeaderRequestID, "req-bench")

	b.ReportAllocs()
	for b.Loop() {
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
}

func BenchmarkRecoverer(b *testing.B) {
	mgr := newTestManager()
	handler := mgr.Recoverer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest("GET", "/test", nil)

	b.ReportAllocs()
	for b.Loop() {
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
}

func BenchmarkResolveBodyToken(b *testing.B) {
	body := bytes.Repeat([]byte("x"), 4096)

	b.ReportAllocs()
	for b.Loop() {
		ResolveBodyToken("application/json", body)
	}
}

func BenchmarkBuildRateKey(b *testing.B) {
	req := httptest.NewRequest("GET", "/api/v1/users", nil)
	req.Header.Set(constants.HeaderIP, "192.168.1.100")
	req.Header.Set(constants.HeaderUserAgent, "Go-Client/1.0")

	b.ReportAllocs()
	for b.Loop() {
		_ = buildRateKeyPublic(req, constants.AuthTypePublic, "test-secret")
	}
}

func BenchmarkRateLimit(b *testing.B) {
	cfg := ConfigLimiter{
		RateLimitRequests: 1000000,
		RateLimitWindow:   1,
	}
	rl := RateLimit(cfg, "test-secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set(constants.HeaderIP, "192.168.1.50")
	req.Header.Set(constants.HeaderUserAgent, "Benchmark/1.0")
	req.Header.Set(constants.HeaderPlatform, "mobile")

	b.ReportAllocs()
	for b.Loop() {
		rl.ServeHTTP(httptest.NewRecorder(), req)
	}
}

// ─── Regression & Hardening Tests ───────────────────────────────────────────

func TestReadAndRestoreBody_ExceedsLimitPreservesBody(t *testing.T) {
	originalContent := "this is a long payload exceeding limit"
	req := httptest.NewRequest("POST", "/test", strings.NewReader(originalContent))
	req.Header.Set("Content-Type", "application/json")

	// Read with limit smaller than payload
	_, err := ReadAndRestoreBody(req, 10)
	if err == nil {
		t.Fatal("expected error for body exceeding limit, got nil")
	}

	// Verify that req.Body was restored and can still be fully read
	restoredBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read restored body: %v", err)
	}
	if string(restoredBytes) != originalContent {
		t.Errorf("expected restored body %q, got %q", originalContent, string(restoredBytes))
	}
}

func TestGraphQLChain_AuditsDepthRejection(t *testing.T) {
	store := &MockLogStore{}
	mgr := newTestManager(func(c *Config) { c.LogStore = store })

	handler := mgr.GraphQLChain(1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Query with depth 2 > maxDepth 1
	body := `{"query":"query { user { profile { name } } }"}`
	req := httptest.NewRequest("POST", "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for depth rejection, got %d", w.Code)
	}

	time.Sleep(50 * time.Millisecond)
	logs := store.GetLogs()
	if len(logs) != 1 {
		t.Fatalf("expected 1 audit log entry for depth rejection, got %d", len(logs))
	}
	if logs[0].StatusCode != http.StatusBadRequest {
		t.Errorf("expected audit log status 400, got %d", logs[0].StatusCode)
	}
}

func TestWebSocketChain_AuditsAuthRejection(t *testing.T) {
	store := &MockLogStore{}
	mgr := newTestManager(func(c *Config) { c.LogStore = store })

	// Reject all connections
	chain := mgr.WebSocketChain(func(r *http.Request) bool {
		return false
	})

	handler := chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for unauthorized WS attempt, got %d", w.Code)
	}

	time.Sleep(50 * time.Millisecond)
	logs := store.GetLogs()
	if len(logs) != 1 {
		t.Fatalf("expected 1 audit log entry for rejected WS attempt, got %d", len(logs))
	}
	if logs[0].StatusCode != http.StatusUnauthorized {
		t.Errorf("expected audit log status 401, got %d", logs[0].StatusCode)
	}
}

func TestCORS_WildcardCredentialsHardened(t *testing.T) {
	mgr := newTestManager(func(c *Config) {
		c.Security.AllowedOrigins = []string{"*"}
	})

	handler := mgr.CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), []string{"*"}, []string{"Authorization"})

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Origin", "https://untrusted-site.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// When wildcard * is matched, credentials MUST NOT be true, and Allow-Origin should be *
	if w.Header().Get("Access-Control-Allow-Credentials") == "true" {
		t.Error("Access-Control-Allow-Credentials must not be true when origin matched via wildcard *")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected Access-Control-Allow-Origin to be '*', got %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestBuildOuterChain_ExecutionOrder(t *testing.T) {
	mgr := newTestManager(func(c *Config) {
		c.Core.EnableTelemetry = true
		c.Security.TrustedProxies = []string{"10.0.0.1"}
	})

	chainCfg := ChainConfig{
		Features: ChainFeatures{
			UseChiTimeout:  true,
			UseChiThrottle: true,
		},
	}
	chainCfg.ApplyDefaults()

	var observedIP string
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedIP = r.Header.Get(mgr.Config().Headers.Keys.IP)
		if r.URL.Path == "/panic" {
			panic("test panic for trace")
		}
		w.WriteHeader(http.StatusOK)
	})

	outer := mgr.buildOuterChain(&chainCfg, innerHandler)

	// 1. Verify TrustProxy runs before inner handler and resolves real IP
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.195")
	w := httptest.NewRecorder()
	outer.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if observedIP != "203.0.113.195" {
		t.Errorf("expected resolved client IP 203.0.113.195, got %q", observedIP)
	}

	// 2. Verify Recoverer catches panics safely
	panicReq := httptest.NewRequest("GET", "/panic", nil)
	panicReq.RemoteAddr = "10.0.0.1:12345"
	panicReq.Header.Set("X-Forwarded-For", "203.0.113.195")
	panicW := httptest.NewRecorder()
	outer.ServeHTTP(panicW, panicReq)

	if panicW.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on panic, got %d", panicW.Code)
	}
}

func TestIsBinary(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"application/octet-stream", true},
		{"APPLICATION/OCTET-STREAM", true},
		{"application/octet-stream; charset=binary", true},
		{"image/png", true},
		{"image/jpeg", true},
		{"image/gif", true},
		{"audio/mpeg", true},
		{"audio/ogg", true},
		{"video/mp4", true},
		{"video/webm", true},
		{"application/pdf", true},
		{"application/zip", true},
		{"application/gzip", true},
		{"application/x-gzip", true},
		{"application/x-tar", true},
		{"application/wasm", true},
		{"text/plain", false},
		{"text/html", false},
		{"application/json", false},
		{"application/xml", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := IsBinary(tt.contentType); got != tt.expected {
			t.Errorf("IsBinary(%q) = %v, expected %v", tt.contentType, got, tt.expected)
		}
	}
}

func TestIsLoggableBody(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		// Text and JSON variants allowed
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"application/problem+json", true},
		{"application/vnd.api+json", true},
		{"application/graphql-response+json", true},
		{"application/xml", true},
		{"application/atom+xml", true},
		{"text/plain", true},
		{"text/html; charset=utf-8", true},
		{"text/csv", true},
		{"application/x-www-form-urlencoded", true},
		{"application/javascript", true},
		{"application/graphql", true},
		{"", true}, // Unspecified content-type defaults to allowed

		// Multipart and binary rejected
		{"multipart/form-data; boundary=xyz", false},
		{"multipart/mixed", false},
		{"application/octet-stream", false},
		{"image/png", false},
		{"image/jpeg", false},
		{"audio/wav", false},
		{"video/mp4", false},
		{"application/pdf", false},
		{"application/zip", false},
		{"application/gzip", false},
		{"application/vnd.ms-excel", false},
		{"application/protobuf", false},
		{"application/x-protobuf", false},
	}

	for _, tt := range tests {
		if got := isLoggableBody(tt.contentType); got != tt.expected {
			t.Errorf("isLoggableBody(%q) = %v, expected %v", tt.contentType, got, tt.expected)
		}
	}
}

func TestLogger_ExcludesBinaryBodies(t *testing.T) {
	mockStore := &MockLogStore{}
	mgr := newTestManager(func(c *Config) {
		c.LogStore = mockStore
		c.Logging.LogRequestBodies = true
		c.Logging.LogResponseBodies = true
		c.Logging.ResponseBodyLogLimitSize = 4096
	})

	binaryPayload := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x01}

	// 1. Request with binary body and response with binary body
	handler := mgr.Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(binaryPayload)
	}))

	req := httptest.NewRequest("POST", "/upload-image", bytes.NewReader(binaryPayload))
	req.Header.Set("Content-Type", "image/png")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	time.Sleep(50 * time.Millisecond)
	logs := mockStore.GetLogs()
	if len(logs) == 0 {
		t.Fatal("expected 1 audit log entry")
	}

	logEntry := logs[0]
	if logEntry.RequestBody != nil {
		t.Errorf("expected RequestBody to be nil for binary image/png, got %v", logEntry.RequestBody)
	}
	if logEntry.ResponseBody != nil {
		t.Errorf("expected ResponseBody to be nil for binary image/png, got %v", logEntry.ResponseBody)
	}

	// 2. Request and response with text/json should be logged normally
	jsonReq := `{"hello":"world"}`
	jsonRes := `{"status":"success"}`
	jsonHandler := mgr.Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jsonRes))
	}))

	reqJSON := httptest.NewRequest("POST", "/api/json", strings.NewReader(jsonReq))
	reqJSON.Header.Set("Content-Type", "application/json")
	recJSON := httptest.NewRecorder()

	jsonHandler.ServeHTTP(recJSON, reqJSON)

	time.Sleep(50 * time.Millisecond)
	logs = mockStore.GetLogs()
	if len(logs) < 2 {
		t.Fatal("expected at least 2 audit log entries")
	}

	jsonLogEntry := logs[1]
	if jsonLogEntry.RequestBody == nil {
		t.Error("expected RequestBody to be recorded for application/json")
	}
	if jsonLogEntry.ResponseBody == nil {
		t.Error("expected ResponseBody to be recorded for application/json")
	}
}

func TestIsProdEnv(t *testing.T) {
	tests := []struct {
		env      string
		expected bool
	}{
		{"production", true},
		{"Production", true},
		{"PRODUCTION", true},
		{"prod", true},
		{"Prod", true},
		{"PROD", true},
		{"  prod  ", true},
		{"  Production  ", true},
		{"development", false},
		{"dev", false},
		{"staging", false},
		{"test", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := isProdEnv(tt.env); got != tt.expected {
			t.Errorf("isProdEnv(%q) = %v, expected %v", tt.env, got, tt.expected)
		}
	}
}

func TestRateLimit_RoutePatternGrouping(t *testing.T) {
	secret := "test-secret-123"

	// Request 1: /api/v1/users/user-123 with WithRoutePattern("/api/v1/users/{id}")
	req1 := httptest.NewRequest("GET", "/api/v1/users/user-123", nil)
	req1.Header.Set(constants.HeaderIP, "192.168.1.1")
	req1.Header.Set(constants.HeaderUserAgent, "TestAgent")
	req1 = req1.WithContext(WithRoutePattern(req1.Context(), "/api/v1/users/{id}"))

	// Request 2: /api/v1/users/user-456 with WithRoutePattern("/api/v1/users/{id}")
	req2 := httptest.NewRequest("GET", "/api/v1/users/user-456", nil)
	req2.Header.Set(constants.HeaderIP, "192.168.1.1")
	req2.Header.Set(constants.HeaderUserAgent, "TestAgent")
	req2 = req2.WithContext(WithRoutePattern(req2.Context(), "/api/v1/users/{id}"))

	key1 := buildRateKeyPublic(req1, constants.AuthTypePublic, secret)
	key2 := buildRateKeyPublic(req2, constants.AuthTypePublic, secret)

	if key1 != key2 {
		t.Fatalf("expected rate keys to match across dynamic parameter values, got key1=%q key2=%q", key1, key2)
	}

	// Request 3: Without WithRoutePattern, should fallback to URL Path
	req3 := httptest.NewRequest("GET", "/api/v1/users/user-123", nil)
	req3.Header.Set(constants.HeaderIP, "192.168.1.1")
	req3.Header.Set(constants.HeaderUserAgent, "TestAgent")

	key3 := buildRateKeyPublic(req3, constants.AuthTypePublic, secret)
	if key1 == key3 {
		t.Fatalf("expected route pattern key to differ from raw path fallback key")
	}
}

func TestRateLimit_CustomEndpointFunc(t *testing.T) {
	secret := "test-secret-123"

	customFunc := func(r *http.Request) string {
		return "custom-endpoint-key"
	}

	req1 := httptest.NewRequest("GET", "/dynamic/abc", nil)
	req1.Header.Set(constants.HeaderIP, "192.168.1.1")
	req1.Header.Set(constants.HeaderUserAgent, "TestAgent")

	req2 := httptest.NewRequest("GET", "/dynamic/xyz", nil)
	req2.Header.Set(constants.HeaderIP, "192.168.1.1")
	req2.Header.Set(constants.HeaderUserAgent, "TestAgent")

	key1 := buildRateKeyPublic(req1, constants.AuthTypePublic, secret, customFunc)
	key2 := buildRateKeyPublic(req2, constants.AuthTypePublic, secret, customFunc)

	if key1 != key2 {
		t.Fatalf("expected rate keys using custom endpointFunc to match, got %q vs %q", key1, key2)
	}
}
