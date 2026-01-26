package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Jkenyut/nvx-go-helper/cryptoutil"
	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/golang-jwt/jwt/v5"
)

// Helper to generate RSA keys for testing
func generateRSAKeys() (string, string, *rsa.PrivateKey) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Encode Private Key
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	// Encode Public Key
	pubBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})

	return string(pubPem), string(privPem), privateKey
}

func TestEnsurePublicAuth(t *testing.T) {
	pubKey, privKey, _ := generateRSAKeys()

	cfg := Config{
		RequiredPublicAuthHeaders: constants.RequiredPublicAuthHeaders,
		PublicKeySignature:        pubKey,
		PrivateKeySignature:       privKey,
		AllowedOrigins:            []string{"*"},
	}
	manager := New(cfg)

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := manager.EnsurePublicAuth(next)

	tests := []struct {
		name           string
		headers        map[string]string
		expectedStatus int
	}{
		{
			name: "Valid Headers (iOS)",
			headers: map[string]string{
				"NVX-User-Agent":  "MyApp/1.0",
				"NVX-Device-ID":   "device-123",
				"NVX-Platform":    "ios",
				"NVX-Mac-Address": "00:00:00:00:00:00",
				"NVX-Message":     "hello",
				"NVX-Token":       "dummy",
				// Sig = Signature(pubKey, Signature(pubKey)) since other signature headers empty
				"NVX-Signature": cryptoutil.Signature(pubKey, cryptoutil.Signature(pubKey)),
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Valid Headers (Web)",
			headers: map[string]string{
				"NVX-User-Agent":  "MyApp/1.0",
				"NVX-Device-ID":   "device-web-123",
				"NVX-Platform":    "web",
				"NVX-Mac-Address": "00:00:00:00:00:00",
				"NVX-Message":     "hello",
				"NVX-Token":       "dummy",
				"NVX-Signature":   cryptoutil.Signature(pubKey, cryptoutil.Signature(pubKey)),
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Missing NVX-User-Agent",
			headers: map[string]string{
				"NVX-Device-ID":   "device-123",
				"NVX-Platform":    "ios",
				"NVX-Mac-Address": "00:00:00:00:00:00",
				"NVX-Message":     "hello",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Missing NVX-Device-ID",
			headers: map[string]string{
				"NVX-User-Agent":  "MyApp/1.0",
				"NVX-Platform":    "ios",
				"NVX-Mac-Address": "00:00:00:00:00:00",
				"NVX-Message":     "hello",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid Platform",
			headers: map[string]string{
				"NVX-User-Agent":  "MyApp/1.0",
				"NVX-Device-ID":   "device-123",
				"NVX-Platform":    "blackberry",
				"NVX-Mac-Address": "00:00:00:00:00:00",
				"NVX-Message":     "hello",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestEnsureAuth(t *testing.T) {
	pubKey, privKey, signKey := generateRSAKeys()

	cfg := Config{
		RequiredAuthHeaders: []string{"Authorization", "NVX-Request-ID"},
		PublicKeySignature:  pubKey,
		PrivateKeySignature: privKey,
		AllowedOrigins:      []string{"*"},
	}
	manager := New(cfg)

	// Helper to create valid JWT
	createValidToken := func() string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"user_id": "123",
			"exp":     time.Now().Add(time.Hour).Unix(),
		})
		s, _ := token.SignedString(signKey)
		return s
	}

	tests := []struct {
		name           string
		headers        map[string]string
		token          string
		expectedStatus int
	}{
		{
			name: "Valid Headers and Valid Token",
			headers: map[string]string{
				"Authorization":  "Bearer token",
				"NVX-Request-ID": "12345",
				// Sign(privKey, empty_headers...) since test config doesn't set RequiredSignatureAuthHeaders
				"NVX-Signature": cryptoutil.Signature(privKey),
			},
			token:          createValidToken(),
			expectedStatus: http.StatusOK,
		},
		{
			name: "Missing Token",
			headers: map[string]string{
				"Authorization":  "Bearer token",
				"NVX-Request-ID": "12345",
			},
			token:          "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Expired/Invalid Token",
			headers: map[string]string{
				"Authorization":  "Bearer token",
				"NVX-Request-ID": "12345",
			},
			token:          "invalid-token-string",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Missing Auth Header",
			headers: map[string]string{
				"NVX-Request-ID": "12345",
			},
			token:          createValidToken(),
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if tt.token != "" {
				req.Header.Set("NVX-Token", tt.token)
			}

			w := httptest.NewRecorder()
			manager.EnsureAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestLoggerMiddleware(t *testing.T) {
	// 1. Setup minimal config to trigger default ConsoleStore and default logger
	pubKey, privKey, _ := generateRSAKeys()
	cfg := Config{
		PublicKeySignature:  pubKey,
		PrivateKeySignature: privKey,
		AllowedOrigins:      []string{"*"},
	}
	manager := New(cfg)

	// 2. Wrap a simple handler with Logger middleware (which uses LogStore.Save)
	handler := manager.Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.WriteHeader(http.StatusOK)
w.Write([]byte("ok"))
}))

	// 3. Serve a request
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// 4. Execute (should not panic)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Middleware panicked: %v", r)
		}
	}()
	handler.ServeHTTP(w, req)

	// 5. Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}
