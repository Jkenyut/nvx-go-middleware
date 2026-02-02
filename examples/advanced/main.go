package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	mw "github.com/Jkenyut/nvx-go-middleware"
)

func main() {
	// Create middleware manager
	mgr := mw.New(mw.Config{
		PublicKeySignature:   "your-rsa-public-key-here",
		PrivateKeySignature:  "your-rsa-private-key-here",
		AllowedOrigins:       []string{"https://example.com"},
		TrustedProxies:       []string{"10.0.0.0/8"},
		RequestTimeout:       30 * time.Second,
		RequestBodyLimitSize: 5 * 1024 * 1024, // 5MB
		Env:                  "production",
	})

	// Custom chain config for production
	chainCfg := mw.ChainConfig{
		UseChiRealIP:       true,
		UseChiCompress:     true,
		UseChiTimeout:      false, // Use custom timeout
		UseChiThrottle:     true,
		UseChiStripSlashes: true,
		CompressionLevel:   9, // Max compression
		ThrottleLimit:      50,
	}

	mux := http.NewServeMux()

	// ========================================
	// PUBLIC ROUTES
	// ========================================

	mux.Handle("/api/v1/register", mgr.PublicChain(chainCfg)(
		mgr.MethodOnly("POST", http.HandlerFunc(registerHandler)),
	))

	mux.Handle("/api/v1/login", mgr.PublicChain(chainCfg)(
		mgr.MethodOnly("POST", http.HandlerFunc(loginHandler)),
	))

	// ========================================
	// AUTHENTICATED ROUTES
	// ========================================

	mux.Handle("/api/v1/profile", mgr.PublicAuthChain(chainCfg)(
		mgr.MethodOnly("GET", http.HandlerFunc(profileHandler)),
	))

	mux.Handle("/api/v1/profile/update", mgr.PublicAuthChain(chainCfg)(
		mgr.MethodOnly("PUT", http.HandlerFunc(updateProfileHandler)),
	))

	mux.Handle("/api/v1/posts", mgr.PublicAuthChain(chainCfg)(
		mgr.MethodOnly("POST", http.HandlerFunc(createPostHandler)),
	))

	mux.Handle("/api/v1/posts/list", mgr.PublicAuthChain(chainCfg)(
		mgr.MethodOnly("GET", http.HandlerFunc(listPostsHandler)),
	))

	// ========================================
	// WEBHOOK ROUTES
	// ========================================

	mux.Handle("/webhooks/payment", mgr.WebhookChain(chainCfg)(
		mgr.MethodOnly("POST", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Webhook received"))
		})),
	))

	// ========================================
	// ADMIN ROUTES
	// ========================================

	// Custom admin check middleware
	adminCheck := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userType := r.Header.Get("NVX-User-Type")
			if userType != "admin" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"meta": map[string]interface{}{
						"success": false,
						"message": "Admin access required",
						"code":    403,
					},
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	mux.Handle("/api/v1/admin/users", mgr.AdminChain(chainCfg, adminCheck)(
		mgr.MethodOnly("GET", http.HandlerFunc(listUsersHandler)),
	))

	mux.Handle("/api/v1/admin/stats", mgr.AdminChain(chainCfg, adminCheck)(
		mgr.MethodOnly("GET", http.HandlerFunc(statsHandler)),
	))

	// ========================================
	// DEBUG ROUTES (only in non-production)
	// ========================================

	if mgr.Config().Env != "production" {
		mux.Handle("/debug/", mgr.ChiProfiler())
	}

	// ========================================
	// HEALTH CHECK
	// ========================================

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "healthy",
			"time":   time.Now(),
		})
	})

	// Start server
	log.Println("🚀 Server starting on :8080")
	log.Println("Environment:", mgr.Config().Env)
	if err := http.ListenAndServe(":8080", mux); err != nil {
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
			"message": "User registered successfully",
			"code":    201,
		},
		"data": map[string]string{
			"user_id": "usr_12345",
			"email":   "newuser@example.com",
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
			"token":         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
			"refresh_token": "refresh_token_12345",
			"expires_in":    "3600",
		},
	})
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("NVX-User-ID")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
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

func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
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

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
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

func listPostsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
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

func listUsersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]interface{}{
			"success": true,
			"message": "Users retrieved",
			"code":    200,
		},
		"data": []map[string]interface{}{
			{
				"user_id": "usr_1",
				"name":    "User One",
				"role":    "user",
			},
			{
				"user_id": "usr_2",
				"name":    "User Two",
				"role":    "admin",
			},
		},
	})
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"meta": map[string]interface{}{
			"success": true,
			"message": "Stats retrieved",
			"code":    200,
		},
		"data": map[string]interface{}{
			"total_users":    1234,
			"total_posts":    5678,
			"active_users":   456,
			"server_uptime":  "24h 30m",
			"requests_today": 98765,
		},
	})
}
