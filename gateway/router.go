package gateway

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Jkenyut/nvx-go-helper/response"
)

// Middleware defines a function that wraps an http.Handler.
type Middleware func(http.Handler) http.Handler

// Route defines a mapping from a path prefix to a target URL.
type Route struct {
	PathPrefix   string // e.g., "/user"
	TargetURL    string // e.g., "http://localhost:8081"
	RequiresAuth bool
}

// RouteStore defines the interface for retrieving routes.
// Implementations can be SQL, Redis, or In-Memory.
type RouteStore interface {
	GetAllRoutes() ([]Route, error)
}

// MemoryRouteStore is a mock implementation of RouteStore for testing/development.
type MemoryRouteStore struct {
	Routes []Route
}

func (m *MemoryRouteStore) GetAllRoutes() ([]Route, error) {
	return m.Routes, nil
}

// DynamicRouter handles request routing based on dynamic configuration.
type DynamicRouter struct {
	store          RouteStore
	routes         map[string]*Route
	proxies        map[string]*httputil.ReverseProxy
	mu             sync.RWMutex
	refreshInt     time.Duration
	AuthMiddleware Middleware
}

// NewRouter creates a new DynamicRouter and starts the background refresh loop.
func NewRouter(store RouteStore, refreshInterval time.Duration) *DynamicRouter {
	router := &DynamicRouter{
		store:      store,
		routes:     make(map[string]*Route),
		proxies:    make(map[string]*httputil.ReverseProxy),
		refreshInt: refreshInterval,
	}

	// Initial load
	if err := router.RefreshRoutes(); err != nil {
		log.Printf("Failed to load initial routes: %v", err)
	}

	// Start background refresh
	go router.startRefreshLoop()

	return router
}

// startRefreshLoop periodically reloads routes from the store.
func (dr *DynamicRouter) startRefreshLoop() {
	ticker := time.NewTicker(dr.refreshInt)
	defer ticker.Stop()

	for range ticker.C {
		if err := dr.RefreshRoutes(); err != nil {
			log.Printf("Failed to refresh routes: %v", err)
		}
	}
}

// RefreshRoutes loads routes from the store and updates the internal map.
func (dr *DynamicRouter) RefreshRoutes() error {
	routes, err := dr.store.GetAllRoutes()
	if err != nil {
		return err
	}

	dr.mu.Lock()
	defer dr.mu.Unlock()

	// Clear existing maps (naive approach, serves purpose for now)
	dr.routes = make(map[string]*Route)
	dr.proxies = make(map[string]*httputil.ReverseProxy)

	for _, r := range routes {
		route := r // copy
		dr.routes[r.PathPrefix] = &route

		target, err := url.Parse(r.TargetURL)
		if err != nil {
			log.Printf("Invalid target URL for path %s: %v", r.PathPrefix, err)
			continue
		}

		proxy := httputil.NewSingleHostReverseProxy(target)

		// Optional: Customize Director to update Host header
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Host = target.Host // Important for some backend services
		}

		dr.proxies[r.PathPrefix] = proxy
	}

	// log.Printf("Routes refreshed: loaded %d routes", len(routes))
	return nil
}

// ServeHTTP implements http.Handler to route requests.
func (dr *DynamicRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dr.mu.RLock()
	defer dr.mu.RUnlock()

	// Find matching route by prefix
	// This is a simple O(N) linear search or Map lookup.
	// For production, a Radix Tree (Trie) is recommended for better performance.
	var matchedRoute *Route
	var matchedProxy *httputil.ReverseProxy

	// We iterate to find the longest matching prefix if we had multiple overlapping paths
	// For simplicity, we assume exact prefix match or simple iteration.
	for prefix, route := range dr.routes {
		if strings.HasPrefix(r.URL.Path, prefix) {
			matchedRoute = route
			matchedProxy = dr.proxies[prefix]
			break
		}
	}

	if matchedRoute == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response.NotFound(r.Context(), "route not found"))
		return
	}

	// NOTE: Authentication check is usually handled by Middleware BEFORE reaching here.
	// However, if we need route-specific auth logic (public vs private routes mixed),
	// we can check matchedRoute.RequiresAuth here or rely on the upstream middleware chain.

	// Forward the request
	// We strip the prefix if needed, or keep it depending on backend expectation.
	// Here we keep the full path but strict prefix stripping might be needed.
	// Example: Gateway /user/profile -> Backend /profile
	// proxy := http.StripPrefix(matchedRoute.PathPrefix, matchedProxy)
	// proxy.ServeHTTP(w, r)

	// For now, we forward as is (Gateway /user/profile -> Backend /user/profile)
	matchedProxy.ServeHTTP(w, r)
}
