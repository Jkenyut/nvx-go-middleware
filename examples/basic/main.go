// main
package main

import (
	"log"
	"net/http"

	mw "github.com/Jkenyut/nvx-go-middleware"
	"github.com/bytedance/sonic"
)

func main() {
	// Create middleware manager using functional options
	mgr, err := mw.New(
		mw.WithSecurityKeys("your-rsa-public-key-here", "your-rsa-private-key-here"),
		mw.WithAllowedOrigins("https://example.com", "http://localhost:3000"),
		mw.WithTrustedProxies("10.0.0.0/8", "172.16.0.0/12"),
		mw.WithAllowedContentTypes("application/json", "text/plain", "multipart/form-data", "form-data"),
		mw.WithSignatureTimestampExpiredMs(600000), // 10 minutes
		mw.WithRequestTimeoutMs(60000),             // 60 seconds
		mw.WithRequestBodyLimitSize(3*1024*1024),
		mw.WithEnv("development"),
		mw.WithBodyLogging(true, true),
	)
	if err != nil {
		log.Fatalf("Failed to initialize middleware manager: %v", err)
	}

	// Chain rate limiting options
	rateLimitOpts := []mw.ChainOption{
		mw.WithRateLimitConfigMs(5, 600000), // 5 requests per 10 minutes (600,000 ms)
		mw.WithRateLimitAuth(true),
		mw.WithRateLimitPublic(true),
	}

	// Create HTTP mux
	mux := http.NewServeMux()

	// ========================================
	// GLOBAL ROUTES (device validation only)
	// ========================================

	mux.Handle("/api/register", mgr.PublicChain(rateLimitOpts...)(
		mgr.MethodOnly("POST", http.HandlerFunc(registerHandler)),
	))

	// ========================================
	// PUBLIC ROUTES (device validation only)
	// ========================================
	mux.Handle("/api/login", mgr.PublicChain(rateLimitOpts...)(
		mgr.MethodOnly("POST", http.HandlerFunc(loginHandler)),
	))

	// ========================================
	// AUTHENTICATED ROUTES
	// ========================================

	mux.Handle("/api/profile", mgr.PublicAuthChain(rateLimitOpts...)(
		mgr.MethodOnly("GET", http.HandlerFunc(profileHandler)),
	))

	mux.Handle("/api/posts", mgr.PublicAuthChain(rateLimitOpts...)(
		mgr.MethodOnly("POST", http.HandlerFunc(createPostHandler)),
	))

	// ========================================
	// HEALTH CHECK (bypass all middleware)
	// ========================================

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// ========================================
	// PRESIGN ROUTES (device validation only)
	// ========================================
	mux.Handle("/api/presign", mgr.PreSignHandler(rateLimitOpts...))

	mux.Handle("/ping", mw.Heartbeat("/ping")(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})))

	// Start server
	log.Println("Server starting on :8081")
	if err := http.ListenAndServe(":8081", mux); err != nil {
		log.Fatal(err)
	}
}

// registerHandler
func registerHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = sonic.ConfigDefault.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]interface{}{
			"success": true,
			"message": "Registration successful",
			"code":    200,
		},
		"data": map[string]string{
			"user_id": "12345",
			"email":   "user@example.com",
		},
	})
}

func loginHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = sonic.ConfigDefault.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]interface{}{
			"success": true,
			"message": "Login successful",
			"code":    200,
		},
		"data": map[string]string{
			"token":   "fake-jwt-token-12345",
			"user_id": "12345",
		},
	})
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = sonic.ConfigDefault.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]interface{}{
			"success": true,
			"message": "Profile retrieved",
			"code":    200,
		},
		"data": map[string]interface{}{
			"user_id": r.Header.Get("User-ID"),
			"name":    "John Doe",
			"email":   "john@example.com",
		},
	})
}

func createPostHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = sonic.ConfigDefault.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]interface{}{
			"success": true,
			"message": "Post created",
			"code":    201,
		},
		"data": map[string]string{
			"post_id": "post-12345",
		},
	})
}
