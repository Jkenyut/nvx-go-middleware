package main

import (
	"fmt"
	"log"
	"net/http"

	"time"

	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/Jkenyut/nvx-go-middleware/gateway"
	"github.com/Jkenyut/nvx-go-middleware/middleware"
)

func main() {
	// 1. Initialize Configuration
	cfg := middleware.Config{
		LogStore:              &middleware.ConsoleStore{},
		RequiredCommonHeaders: constants.RequiredCommonHeaders,
		RequiredAuthHeaders:   constants.RequiredAuthHeaders,
		SecurityHeaders:       constants.SecurityHeaders,
		PublicKeySignature:    "dummy-public-key",
		PrivateKeySignature:   "dummy-private-key",
	}

	// 2. Initialize Middleware Manager
	mw := middleware.New(cfg)

	// 3. Initialize Route Store (Mock DB)
	// In production, this would be NewPostgresRouteStore(...)
	routeStore := &gateway.MemoryRouteStore{
		Routes: []gateway.Route{
			{
				PathPrefix:   "/public-api",
				TargetURL:    "https://httpbin.org/anything/public",
				RequiresAuth: false,
			},
			{
				PathPrefix:   "/private-api",
				TargetURL:    "https://httpbin.org/anything/private",
				RequiresAuth: true,
			},
		},
	}

	// 4. Initialize Dynamic Gateway Router
	// Refresh routes every 30 seconds
	router := gateway.NewRouter(routeStore, 30*time.Second)

	// Inject the Auth Middleware from our Manager to the Router
	// We chain EnsureAuth -> InjectHeaders so that headers are added after successful auth.
	router.AuthMiddleware = func(next http.Handler) http.Handler {
		return mw.EnsureAuth(next)
	}
	router.PublicMiddleware = mw.EnsurePublicAuth

	// 5. Define Global Middleware Chain
	// Note: We don't apply EnsureAuth here globaly, because the Router applies it dynamically.
	// We DO apply Recoverer, Logger, Security, etc.
	globalMiddleware := func(next http.Handler) http.Handler {
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

	// Wraps the router with global middleware
	handler := globalMiddleware(router)

	fmt.Println("Gateway Server executing on port 8080")
	fmt.Println("Routes:")
	fmt.Println(" - /public-api  -> https://httpbin.org/anything/public (No Auth)")
	fmt.Println(" - /private-api -> https://httpbin.org/anything/private (Auth Required)")

	log.Fatal(http.ListenAndServe(":8080", handler))
}
