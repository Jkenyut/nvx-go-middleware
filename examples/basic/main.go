package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	mw "github.com/Jkenyut/nvx-go-middleware"
)

func main() {
	// Create middleware manager with configuration
	mgr := mw.New(mw.Config{
		PublicKeySignature:        "your-rsa-public-key-here",
		PrivateKeySignature:       "your-rsa-private-key-here",
		AllowedOrigins:            []string{"https://example.com", "http://localhost:3000"},
		TrustedProxies:            []string{"10.0.0.0/8", "172.16.0.0/12"},
		RequestTimeout:            60 * time.Second,
		RequestBodyLimitSize:      3 * 1024 * 1024, // 3MB
		Env:                       "development",
		HeadersToRemove:           []string{},
		LogRequestBodies:          true,
		LogResponseBodies:         true,
		AllowedContentTypes:       []string{"application/json", "text/plain"},
		SignatureTimestampExpired: 6000000,
	})

	// Create chain config
	chainCfg := mw.DefaultChainConfig()
	chainCfg.LimiterConfig.RateLimitRequests = 5
	chainCfg.LimiterConfig.RateLimitWindow = 10 * time.Second
	chainCfg.UseChiRateLimitAuth = true
	chainCfg.UseChiRateLimitPublic = true

	// Create HTTP mux
	mux := http.NewServeMux()

	// ========================================
	// GLOBAL ROUTES (device validation only)
	// ========================================

	mux.Handle("/api/register", mgr.PublicChain(chainCfg)(
		mgr.MethodOnly("POST", http.HandlerFunc(registerHandler)),
	))

	// ========================================
	// PUBLIC ROUTES (device validation only)
	// ========================================
	mux.Handle("/api/login", mgr.PublicChain(chainCfg)(
		mgr.MethodOnly("POST", http.HandlerFunc(loginHandler)),
	))

	// ========================================
	// AUTHENTICATED ROUTES
	// ========================================

	mux.Handle("/api/profile", mgr.PublicAuthChain(chainCfg)(
		mgr.MethodOnly("GET", http.HandlerFunc(profileHandler)),
	))

	mux.Handle("/api/posts", mgr.PublicAuthChain(chainCfg)(
		mgr.MethodOnly("POST", http.HandlerFunc(createPostHandler)),
	))

	// ========================================
	// HEALTH CHECK (bypass all middleware)
	// ========================================

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// ========================================
	// PRESIGN ROUTES (device validation only)
	// ========================================
	mux.Handle("/api/presign", mgr.PreSignHandler(chainCfg))

	mux.HandleFunc("/ping", mw.Heartbeat("/ping"))

	// Start server
	log.Println("Server starting on :8081")
	if err := http.ListenAndServe(":8081", mux); err != nil {
		log.Fatal(err)
	}
}

// ========================================
// HANDLERS
// ========================================

func registerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
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

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
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
	json.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]interface{}{
			"success": true,
			"message": "Profile retrieved",
			"code":    200,
		},
		"data": map[string]interface{}{
			"user_id": r.Header.Get("NVX-User-ID"),
			"name":    "John Doe",
			"email":   "john@example.com",
		},
	})
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
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
