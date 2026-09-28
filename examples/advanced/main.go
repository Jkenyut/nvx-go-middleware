// Main
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	mw "github.com/Jkenyut/nvx-go-middleware"
)

func main() {
	// Create middleware manager using functional options
	mgr, err := mw.New(
		mw.WithSecurityKeys("your-rsa-public-key-here", "your-rsa-private-key-here"),
		mw.WithAllowedOrigins("https://example.com"),
		mw.WithTrustedProxies("10.0.0.0/8"),
		mw.WithRequestTimeoutMs(30000), // 30 seconds
		mw.WithRequestBodyLimitSize(5*1024*1024),
		mw.WithEnv("production"),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Chain options for production
	prodChainOpts := []mw.ChainOption{
		mw.WithChiCompress(true, 9), // Max compression
		mw.WithChiThrottleMs(true, 50, 100, 30000),
		mw.WithChiStripSlashes(true),
	}

	mux := http.NewServeMux()

	// ========================================
	// PUBLIC ROUTES
	// ========================================

	mux.Handle("/api/v1/register", mgr.PublicChain(prodChainOpts...)(
		mgr.MethodOnly("POST", http.HandlerFunc(registerHandler)),
	))

	mux.Handle("/api/v1/login", mgr.PublicChain(prodChainOpts...)(
		mgr.MethodOnly("POST", http.HandlerFunc(loginHandler)),
	))

	// ========================================
	// AUTHENTICATED ROUTES
	// ========================================

	mux.Handle("/api/v1/profile", mgr.PublicAuthChain(prodChainOpts...)(
		mgr.MethodOnly("GET", http.HandlerFunc(profileHandler)),
	))

	mux.Handle("/api/v1/profile/update", mgr.PublicAuthChain(prodChainOpts...)(
		mgr.MethodOnly("PUT", http.HandlerFunc(updateProfileHandler)),
	))

	mux.Handle("/api/v1/posts", mgr.PublicAuthChain(prodChainOpts...)(
		mgr.MethodOnly("POST", http.HandlerFunc(createPostHandler)),
	))

	mux.Handle("/api/v1/posts/list", mgr.PublicAuthChain(prodChainOpts...)(
		mgr.MethodOnly("GET", http.HandlerFunc(listPostsHandler)),
	))

	// ========================================
	// WEBHOOK ROUTES
	// ========================================

	mux.Handle("/webhooks/payment", mgr.WebhookChain(prodChainOpts...)(
		mgr.MethodOnly("POST", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Webhook received"))
		})),
	))

	// ========================================
	// DEBUG ROUTES (only in non-production)
	// ========================================

	if mgr.Config().Core.Env != "production" {
		mux.Handle("/debug/", mgr.ChiProfiler())
	}

	// ========================================
	// HEALTH CHECK
	// ========================================

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "healthy",
			"time":   time.Now(),
		})
	})

	// Start server
	log.Println("🚀 Server starting on :8080")
	log.Println("Environment:", mgr.Config().Core.Env)
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

// ========================================
// HANDLERS
// ========================================

func registerHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]interface{}{
			"success": true,
			"message": "User registered successfully",
			"code":    201,
		},
		"data": map[string]string{
			"user_id": "usr_12345",
			"email":   "newuser@example.com",
		},
	})
}

func loginHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]interface{}{
			"success": true,
			"message": "Login successful",
			"code":    200,
		},
		"data": map[string]string{
			"token":         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
			"refresh_token": "refresh_token_12345",
			"expires_in":    "3600",
		},
	})
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("User-ID")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]interface{}{
			"success": true,
			"message": "Profile retrieved",
			"code":    200,
		},
		"data": map[string]interface{}{
			"user_id":    userID,
			"name":       "John Doe",
			"email":      "john@example.com",
			"created_at": "2024-01-01T00:00:00Z",
		},
	})
}

func updateProfileHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]interface{}{
			"success": true,
			"message": "Profile updated successfully",
			"code":    200,
		},
		"data": map[string]bool{
			"updated": true,
		},
	})
}

func createPostHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]interface{}{
			"success": true,
			"message": "Post created successfully",
			"code":    201,
		},
		"data": map[string]string{
			"post_id":    "post_67890",
			"created_at": time.Now().Format(time.RFC3339),
		},
	})
}

func listPostsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]interface{}{
			"success": true,
			"message": "Posts retrieved",
			"code":    200,
		},
		"data": []map[string]interface{}{
			{
				"post_id": "post_1",
				"title":   "First Post",
				"author":  "John Doe",
			},
			{
				"post_id": "post_2",
				"title":   "Second Post",
				"author":  "Jane Doe",
			},
		},
	})
}
