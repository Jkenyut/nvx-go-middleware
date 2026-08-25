package middleware

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
		name        string
		bodySize    int
		contentType string
		wantStatus  int
	}{
		{"json within limit", 50, "application/json", http.StatusOK},
		{"json exceeds limit", 200, "application/json", http.StatusRequestEntityTooLarge},
		{"multipart within limit", 50, "multipart/form-data; boundary=x", http.StatusOK},
		{"unsupported content type", 50, "text/plain", http.StatusBadRequest},
		{"no body no content type (GET-like)", 0, "", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := bytes.Repeat([]byte("a"), tt.bodySize)
			req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
			req.ContentLength = int64(len(body)) // required for Content-Length check in MaxBodySize
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			if tt.bodySize == 0 {
				req.ContentLength = 0
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
