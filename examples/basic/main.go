// main
package main

import (
	"log"
	"net/http"
	"time"

	mw "github.com/Jkenyut/nvx-go-middleware"
	"github.com/bytedance/sonic"
)

func main() {
	// Create middleware manager with configuration
	mgr, err := mw.NewWithError(&mw.Config{
		Security: mw.ConfigSecurity{
			PublicKeySignature:        "your-rsa-public-key-here",
			PrivateKeySignature:       "your-rsa-private-key-here",
			AllowedOrigins:            []string{"https://example.com", "http://localhost:3000"},
			TrustedProxies:            []string{"10.0.0.0/8", "172.16.0.0/12"},
			HeadersToRemove:           []string{},
			AllowedContentTypes:       []string{"application/json", "text/plain", "multipart/form-data", "form-data"},
			SignatureTimestampExpired: 6000000,
		},
		Limits: mw.ConfigLimits{
			RequestTimeout:       60 * time.Second,
			RequestBodyLimitSize: 3 * 1024 * 1024, // 3MB
		},
		Core: mw.ConfigCore{
			Env: "development",
		},
		Logging: mw.ConfigLogging{
			LogRequestBodies:  true,
			LogResponseBodies: true,
		},
	})
	if err != nil {
		log.Fatalf("Failed to initialize middleware manager: %v", err)
	}

	// Create chain config
	chainCfg := mw.ChainConfig{}
	chainCfg.ApplyDefaults()
	chainCfg.Limiter.RateLimitRequests = 5
	chainCfg.Limiter.RateLimitWindow = 10
	chainCfg.Features.UseChiRateLimitAuth = true
	chainCfg.Features.UseChiRateLimitPublic = true

	// Create HTTP mux
	mux := http.NewServeMux()

	// ========================================
	// GLOBAL ROUTES (device validation only)
	// ========================================

	mux.Handle("/api/register", mgr.PublicChain(&chainCfg)(
		mgr.MethodOnly("POST", http.HandlerFunc(registerHandler)),
	))

	// ========================================
	// PUBLIC ROUTES (device validation only)
	// ========================================
	mux.Handle("/api/login", mgr.PublicChain(&chainCfg)(
		mgr.MethodOnly("POST", http.HandlerFunc(loginHandler)),
	))

	// ========================================
	// AUTHENTICATED ROUTES
	// ========================================

	mux.Handle("/api/profile", mgr.PublicAuthChain(&chainCfg)(
		mgr.MethodOnly("GET", http.HandlerFunc(profileHandler)),
	))

	mux.Handle("/api/posts", mgr.PublicAuthChain(&chainCfg)(
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
	mux.Handle("/api/presign", mgr.PreSignHandler(&chainCfg))

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
			"user_id": r.Header.Get("NVX-User-ID"),
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
