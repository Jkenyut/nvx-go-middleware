package main_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/Jkenyut/nvx-go-middleware/gateway"
	"github.com/Jkenyut/nvx-go-middleware/middleware"
)

// TestPublicRoute_StrictHeaders verifies that public routes are secured by:
// 1. Strict Common Headers (Global Middleware)
// 2. User-Agent Check (Public Middleware)
func TestPublicRoute_StrictHeaders(t *testing.T) {
	// 1. Setup Support Objects
	cfg := middleware.Config{
		LogStore:                  &middleware.ConsoleStore{},
		RequiredCommonHeaders:     constants.RequiredCommonHeaders,
		RequiredAuthHeaders:       constants.RequiredAuthHeaders,
		RequiredPublicAuthHeaders: constants.RequiredPublicAuthHeaders,
		SecurityHeaders:           constants.SecurityHeaders,
		PublicKeySignature:                 "test-pub",
		PrivateKeySignature:                "test-priv",
	}
	mw := middleware.New(cfg)

	// 2. Setup Router with a Public Route
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	store := &gateway.MemoryRouteStore{
		Routes: []gateway.Route{
			{
				PathPrefix:   "/public-api",
				TargetURL:    backend.URL,
				RequiresAuth: false,
			},
		},
	}
	router := gateway.NewRouter(store, time.Minute)
	router.AuthMiddleware = mw.EnsureAuth
	router.PublicMiddleware = mw.EnsurePublicAuth

	// 3. Build Global Middleware Chain (replicating main.go)
	globalChain := func(next http.Handler) http.Handler {
		return mw.Recoverer(
			mw.Logger(
				mw.EnforceMethods(
					mw.SecureHeaders(
						mw.EnsureCommonHeaders(next),
					),
				),
			),
		)
	}

	handler := globalChain(router)

	// 4. Test Case: Missing Common Header (NVX-Request-ID)
	t.Run("Missing Common Header Should Fail", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/public-api/test", nil)
		// Set User-Agent (valid for Public Middleware)
		req.Header.Set("User-Agent", "TestAgent/1.0")
		// BUT Missing NVX-Request-ID (Global Middleware)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request due to missing common header, got %d", w.Code)
		}
	})

	// 5. Test Case: Missing User-Agent
	t.Run("Missing User-Agent Should Fail", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/public-api/test", nil)
		// Set Common Headers (Valid for Global Middleware)
		for _, h := range constants.RequiredCommonHeaders {
			req.Header.Set(h, "dummy-value")
		}
		// BUT Missing User-Agent (Public Middleware)
		req.Header.Del("NVX-User-Agent")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request due to missing User-Agent, got %d", w.Code)
		}
	})

	// 6. Test Case: All Headers Present
	t.Run("All Headers Present Should Succeed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/public-api/test", nil)
		// Set Common Headers
		for _, h := range constants.RequiredCommonHeaders {
			req.Header.Set(h, "dummy-value")
		}
		// Set Public Auth Headers
		req.Header.Set("NVX-User-Agent", "TestAgent/1.0")
		req.Header.Set("NVX-Device-ID", "test-device-id")
		req.Header.Set("NVX-Platform", "android")
		req.Header.Set("NVX-Mac-Address", "AA:BB:CC:DD:EE:FF")
		req.Header.Set("NVX-Message", "integration test")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", w.Code)
		}
	})
}
