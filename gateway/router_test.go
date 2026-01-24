package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDynamicRouter_Authentication(t *testing.T) {
	// 1. Setup a dummy backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	backendURL := backend.URL

	// 2. Setup RouteStore with one public and one private route
	store := &MemoryRouteStore{
		Routes: []Route{
			{
				PathPrefix:   "/public",
				TargetURL:    backendURL,
				RequiresAuth: false,
			},
			{
				PathPrefix:   "/private",
				TargetURL:    backendURL,
				RequiresAuth: true,
			},
		},
	}

	// 3. Initialize Router
	router := NewRouter(store, time.Minute) // Long refresh so it doesn't trigger during test

	// 4. Define a Mock Auth Middleware
	// This middleware sets a header "X-Auth-Executed" to "true"
	mockAuthMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Auth-Executed", "true")
			next.ServeHTTP(w, r)
		})
	}

	router.AuthMiddleware = mockAuthMiddleware

	// Mock Public Middleware
	mockPublicMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Public-Auth-Executed", "true")
			next.ServeHTTP(w, r)
		})
	}
	router.PublicMiddleware = mockPublicMiddleware

	// 5. Run Tests
	tests := []struct {
		name             string
		path             string
		expectAuthExec   bool
		expectPublicExec bool
	}{
		{
			name:             "Public Route - Should Execute Public Middleware, NOT Auth",
			path:             "/public/something",
			expectAuthExec:   false,
			expectPublicExec: true,
		},
		{
			name:             "Private Route - Should Execute Auth Middleware, NOT Public",
			path:             "/private/something",
			expectAuthExec:   true,
			expectPublicExec: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			// Check if backend was reached
			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 from backend, got %d", w.Code)
			}

			// Check auth execution
			authHeader := w.Header().Get("X-Auth-Executed")
			if tt.expectAuthExec && authHeader != "true" {
				t.Error("Expected Auth Middleware to be executed, but it wasn't")
			}
			if !tt.expectAuthExec && authHeader == "true" {
				t.Error("Expected Auth Middleware NOT to be executed, but it was")
			}

			// Check public auth execution
			publicHeader := w.Header().Get("X-Public-Auth-Executed")
			if tt.expectPublicExec && publicHeader != "true" {
				t.Error("Expected Public Middleware to be executed, but it wasn't")
			}
			if !tt.expectPublicExec && publicHeader == "true" {
				t.Error("Expected Public Middleware NOT to be executed, but it was")
			}
		})
	}
}
