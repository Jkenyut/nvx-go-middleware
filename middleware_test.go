package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/Jkenyut/nvx-go-middleware/model"
)

// Mock LogStore for testing
type MockLogStore struct {
	Logs []model.AuditLog
}

func (m *MockLogStore) Save(entry model.AuditLog) error {
	m.Logs = append(m.Logs, entry)
	return nil
}

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		shouldErr bool
	}{
		{
			name: "valid config",
			config: Config{
				PublicKeySignature:  "test-public-key",
				PrivateKeySignature: "test-private-key",
				AllowedOrigins:      []string{"*"},
			},
			shouldErr: false,
		},
		{
			name: "missing keys should panic",
			config: Config{
				AllowedOrigins: []string{"*"},
			},
			shouldErr: true,
		},
		{
			name: "missing origins should panic",
			config: Config{
				PublicKeySignature:  "test-public-key",
				PrivateKeySignature: "test-private-key",
			},
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if (r != nil) != tt.shouldErr {
					t.Errorf("New() panic = %v, shouldErr = %v", r != nil, tt.shouldErr)
				}
			}()

			mgr := New(tt.config)
			if !tt.shouldErr && mgr == nil {
				t.Error("New() returned nil manager")
			}
		})
	}
}

func TestRecoverer(t *testing.T) {
	mockStore := &MockLogStore{}
	mgr := New(Config{
		LogStore:            mockStore,
		PublicKeySignature:  "test-public-key",
		PrivateKeySignature: "test-private-key",
		AllowedOrigins:      []string{"*"},
	})

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	handler := mgr.Recoverer(panicHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	// Should not panic
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	meta := response["meta"].(map[string]interface{})
	if meta["success"].(bool) {
		t.Error("Expected success=false in response")
	}
}

func TestEnsureCommonHeaders(t *testing.T) {
	mockStore := &MockLogStore{}
	mgr := New(Config{
		LogStore:            mockStore,
		PublicKeySignature:  "test-public-key",
		PrivateKeySignature: "test-private-key",
		AllowedOrigins:      []string{"*"},
	})

	tests := []struct {
		name       string
		headers    map[string]string
		wantStatus int
	}{
		{
			name: "all headers present",
			headers: map[string]string{
				constants.HeaderRequestID:   "req-123",
				constants.HeaderMerchantKey: "merchant-1",
				constants.HeaderDatetime:    "2024-01-01T00:00:00Z",
				constants.HeaderSignature:   "sig-123",
				// HeaderIP is populated by TrustProxy/RealIP, we mock it via TrustProxy if needed or assume set by previous middleware?
				// Actually EnsureCommonHeaders checks it from request header which *should* be there.
				constants.HeaderIP: "192.168.1.1",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "missing request id",
			headers: map[string]string{
				constants.HeaderMerchantKey: "merchant-1",
				constants.HeaderDatetime:    "2024-01-01T00:00:00Z",
				constants.HeaderSignature:   "sig-123",
				constants.HeaderIP:          "192.168.1.1",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing datetime",
			headers: map[string]string{
				constants.HeaderRequestID:   "req-123",
				constants.HeaderMerchantKey: "merchant-1",
				constants.HeaderSignature:   "sig-123",
				constants.HeaderIP:          "192.168.1.1",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid ip format",
			headers: map[string]string{
				constants.HeaderRequestID:   "req-123",
				constants.HeaderMerchantKey: "merchant-1",
				constants.HeaderDatetime:    "2024-01-01T00:00:00Z",
				constants.HeaderSignature:   "sig-123",
				constants.HeaderIP:          "invalid-ip",
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := mgr.EnsureCommonHeaders(okHandler)

			req := httptest.NewRequest("GET", "/test", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, w.Code)
			}
		})
	}
}

func TestLogger(t *testing.T) {
	mockStore := &MockLogStore{}
	mgr := New(Config{
		LogStore:            mockStore,
		PublicKeySignature:  "test-public-key",
		PrivateKeySignature: "test-private-key",
		AllowedOrigins:      []string{"*"},
	})

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	handler := mgr.Logger(testHandler)

	req := httptest.NewRequest("POST", "/test", bytes.NewBufferString(`{"test":"data"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(constants.HeaderRequestID, "req-123")
	req.Header.Set(constants.HeaderMerchantKey, "merchant-1")
	req.Header.Set(constants.HeaderIP, "192.168.1.1")
	req.Header.Set(constants.HeaderDatetime, "2024-01-01T00:00:00Z")
	req.Header.Set(constants.HeaderSignature, "sig-123")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Wait for async log save
	time.Sleep(100 * time.Millisecond)

	if len(mockStore.Logs) != 1 {
		t.Errorf("Expected 1 log entry, got %d", len(mockStore.Logs))
	}

	log := mockStore.Logs[0]
	if log.Method != "POST" {
		t.Errorf("Expected method POST, got %s", log.Method)
	}
	if log.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", log.StatusCode)
	}
	if log.TransactionID == "" {
		t.Error("Expected transaction ID to be set")
	}
}

func TestMaxBodySize(t *testing.T) {
	mockStore := &MockLogStore{}
	mgr := New(Config{
		LogStore:            mockStore,
		PublicKeySignature:  "test-public-key",
		PrivateKeySignature: "test-private-key",
		AllowedOrigins:      []string{"*"},
		RequestBodyLimit:    100, // 100 bytes limit
	})

	tests := []struct {
		name       string
		bodySize   int
		wantStatus int
	}{
		{
			name:       "body within limit",
			bodySize:   50,
			wantStatus: http.StatusOK,
		},
		{
			name:       "body exceeds limit",
			bodySize:   200,
			wantStatus: http.StatusRequestEntityTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := mgr.MaxBodySize(mgr.cfg.RequestBodyLimit)(okHandler)

			body := bytes.Repeat([]byte("a"), tt.bodySize)
			req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, w.Code)
			}
		})
	}
}

func TestMethodOnly(t *testing.T) {
	tests := []struct {
		name           string
		allowedMethod  string
		requestMethod  string
		expectedStatus int
	}{
		{
			name:           "matching method",
			allowedMethod:  "POST",
			requestMethod:  "POST",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "non-matching method",
			allowedMethod:  "POST",
			requestMethod:  "GET",
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := New(Config{
				LogStore:            &MockLogStore{},
				PublicKeySignature:  "test-public-key",
				PrivateKeySignature: "test-private-key",
				AllowedOrigins:      []string{"*"},
			})
			okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := mgr.MethodOnly(tt.allowedMethod, okHandler)

			req := httptest.NewRequest(tt.requestMethod, "/test", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestSecureHeaders(t *testing.T) {
	mockStore := &MockLogStore{}
	mgr := New(Config{
		LogStore:            mockStore,
		PublicKeySignature:  "test-public-key",
		PrivateKeySignature: "test-private-key",
		AllowedOrigins:      []string{"*"},
	})

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := mgr.SecureHeaders(okHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check security headers are set
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("Expected X-Content-Type-Options header to be set")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("Expected X-Frame-Options header to be set")
	}
}

func BenchmarkLogger(b *testing.B) {
	mockStore := &MockLogStore{}
	mgr := New(Config{
		LogStore:            mockStore,
		PublicKeySignature:  "test-public-key",
		PrivateKeySignature: "test-private-key",
		AllowedOrigins:      []string{"*"},
	})

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := mgr.Logger(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(constants.HeaderRequestID, "req-123")
	req.Header.Set(constants.HeaderMerchantKey, "merchant-1")
	req.Header.Set(constants.HeaderIP, "192.168.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkRecoverer(b *testing.B) {
	mockStore := &MockLogStore{}
	mgr := New(Config{
		LogStore:            mockStore,
		PublicKeySignature:  "test-public-key",
		PrivateKeySignature: "test-private-key",
		AllowedOrigins:      []string{"*"},
	})

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := mgr.Recoverer(okHandler)

	req := httptest.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}
