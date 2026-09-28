package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNew_Defaults(t *testing.T) {
	mgr, err := New()
	if err != nil {
		t.Fatalf("expected New() to succeed with zero config, got error: %v", err)
	}
	defer mgr.Close()

	cfg := mgr.Config()
	if cfg.Core.ServiceName != "unknown-service" {
		t.Errorf("expected ServiceName 'unknown-service', got %q", cfg.Core.ServiceName)
	}
	if cfg.Core.Env != "development" {
		t.Errorf("expected Env 'development', got %q", cfg.Core.Env)
	}
	if cfg.Logger == nil {
		t.Error("expected non-nil default Logger")
	}
	if cfg.LogStore == nil {
		t.Error("expected non-nil default LogStore")
	}
}

func TestNew_WithOptions(t *testing.T) {
	store := &MockLogStore{}
	mgr, err := New(
		WithServiceName("payment-service"),
		WithEnv("production"),
		WithTelemetry(true),
		WithLogStore(store),
		WithSecurityKeys("pub-123", "priv-456"),
		WithRequestTimeoutMs(45000),
		WithRequestBodyLimitSize(10<<20),
		WithRequestBodyNonFileLimitSize(2<<20),
		WithTrustedProxies("10.0.0.1"),
		WithAllowedOrigins("https://example.com"),
		WithAllowedContentTypes("application/json"),
		WithAllowedHeaders("X-Custom-Header"),
		WithHeadersToRemove("Server"),
		WithSignatureTimestampExpiredMs(300000),
		WithBodyLogging(true, true),
		WithMaskKeywords("secret", "token"),
		WithResponseBodyLogLimit(1024),
		WithLogHeaders("X-Trace-Id"),
	)
	if err != nil {
		t.Fatalf("expected New() to succeed, got %v", err)
	}
	defer mgr.Close()

	cfg := mgr.Config()
	if cfg.Core.ServiceName != "payment-service" {
		t.Errorf("expected ServiceName 'payment-service', got %q", cfg.Core.ServiceName)
	}
	if cfg.Core.Env != "production" {
		t.Errorf("expected Env 'production', got %q", cfg.Core.Env)
	}
	if !cfg.Core.EnableTelemetry {
		t.Error("expected EnableTelemetry to be true")
	}
	if cfg.Security.PublicKeySignature != "pub-123" || cfg.Security.PrivateKeySignature != "priv-456" {
		t.Errorf("security keys mismatch: got pub=%s, priv=%s", cfg.Security.PublicKeySignature, cfg.Security.PrivateKeySignature)
	}
	if cfg.Limits.RequestTimeoutMs != 45000 {
		t.Errorf("expected RequestTimeoutMs 45000, got %d", cfg.Limits.RequestTimeoutMs)
	}
	if cfg.Limits.RequestBodyLimitSize != 10<<20 {
		t.Errorf("expected RequestBodyLimitSize 10MB, got %d", cfg.Limits.RequestBodyLimitSize)
	}
	if cfg.Limits.RequestBodyNonFileLimitSize != 2<<20 {
		t.Errorf("expected RequestBodyNonFileLimitSize 2MB, got %d", cfg.Limits.RequestBodyNonFileLimitSize)
	}
	if len(cfg.Security.TrustedProxies) != 1 || cfg.Security.TrustedProxies[0] != "10.0.0.1" {
		t.Errorf("unexpected TrustedProxies: %v", cfg.Security.TrustedProxies)
	}
	if len(cfg.Security.AllowedOrigins) != 1 || cfg.Security.AllowedOrigins[0] != "https://example.com" {
		t.Errorf("unexpected AllowedOrigins: %v", cfg.Security.AllowedOrigins)
	}
	if len(cfg.Security.AllowedContentTypes) != 1 || cfg.Security.AllowedContentTypes[0] != "application/json" {
		t.Errorf("unexpected AllowedContentTypes: %v", cfg.Security.AllowedContentTypes)
	}
	if !cfg.Logging.LogRequestBodies || !cfg.Logging.LogResponseBodies {
		t.Error("expected body logging to be enabled")
	}
	if cfg.Logging.ResponseBodyLogLimitSize != 1024 {
		t.Errorf("expected ResponseBodyLogLimitSize 1024, got %d", cfg.Logging.ResponseBodyLogLimitSize)
	}
	if cfg.Security.SignatureTimestampExpiredMs != 300000 {
		t.Errorf("expected SignatureTimestampExpiredMs 300000, got %d", cfg.Security.SignatureTimestampExpiredMs)
	}
}

func TestNew_WithConfig(t *testing.T) {
	baseCfg := Config{
		Core: ConfigCore{
			ServiceName: "base-service",
			Env:         "staging",
		},
		Security: ConfigSecurity{
			PublicKeySignature:  "base-pub",
			PrivateKeySignature: "base-priv",
		},
	}

	// WithConfig can also be overridden by subsequent options
	mgr, err := New(
		WithConfig(baseCfg),
		WithServiceName("overridden-service"),
	)
	if err != nil {
		t.Fatalf("expected New() to succeed, got %v", err)
	}
	defer mgr.Close()

	cfg := mgr.Config()
	if cfg.Core.ServiceName != "overridden-service" {
		t.Errorf("expected ServiceName 'overridden-service', got %q", cfg.Core.ServiceName)
	}
	if cfg.Core.Env != "staging" {
		t.Errorf("expected Env 'staging', got %q", cfg.Core.Env)
	}
	if cfg.Security.PublicKeySignature != "base-pub" {
		t.Errorf("expected PublicKeySignature 'base-pub', got %q", cfg.Security.PublicKeySignature)
	}
}

func TestSignatureMiddlewares_MissingKeys(t *testing.T) {
	// Manager created without signature keys
	mgr, err := New(WithServiceName("test-no-keys"))
	if err != nil {
		t.Fatalf("expected New() to succeed, got %v", err)
	}
	defer mgr.Close()

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("EnsureInternal returns 500 when private key missing", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/internal", nil)
		w := httptest.NewRecorder()
		mgr.EnsureInternal(dummyHandler).ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 InternalServerError, got %d", w.Code)
		}
	})

	t.Run("EnsurePublic returns 500 when public key missing", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/public", nil)
		w := httptest.NewRecorder()
		mgr.EnsurePublic(dummyHandler).ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 InternalServerError, got %d", w.Code)
		}
	})

	t.Run("EnsurePublicAuth returns 500 when public key missing", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/public-auth", nil)
		w := httptest.NewRecorder()
		mgr.EnsurePublicAuth(dummyHandler).ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 InternalServerError, got %d", w.Code)
		}
	})

	t.Run("EnsurePublicAPIKey returns 500 when public key missing", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/public-apikey", nil)
		w := httptest.NewRecorder()
		mgr.EnsurePublicAPIKey(dummyHandler).ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 InternalServerError, got %d", w.Code)
		}
	})

	t.Run("PreSignHandler returns 500 when public key missing", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/presign", nil)
		w := httptest.NewRecorder()
		mgr.PreSignHandler().ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 InternalServerError, got %d", w.Code)
		}
	})
}

func TestChainOptions(t *testing.T) {
	mgr, err := New(
		WithServiceName("chain-opt-test"),
		WithSecurityKeys("pub-key", "priv-key"),
	)
	if err != nil {
		t.Fatalf("failed to init manager: %v", err)
	}
	defer mgr.Close()

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	t.Run("PublicChain zero-config works", func(t *testing.T) {
		chain := mgr.PublicChain()(okHandler)
		req := httptest.NewRequest("GET", "/public", nil)
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, req)

		// Without signature header, EnsurePublic returns 400 or 401
		if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
			t.Errorf("expected 400/401 for unsigned public request, got %d", w.Code)
		}
	})

	t.Run("PublicChain with custom options", func(t *testing.T) {
		chain := mgr.PublicChain(
			WithChiCompress(true, 6),
			WithRateLimitPublic(false),
			WithChiStripSlashes(true),
		)(okHandler)

		req := httptest.NewRequest("GET", "/public/", nil)
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
			t.Errorf("expected 400/401, got %d", w.Code)
		}
	})

	t.Run("Chain options with millisecond settings", func(t *testing.T) {
		cfg := DefaultChainConfig()
		WithChiThrottleMs(true, 50, 20, 15000)(&cfg)
		WithRateLimitConfigMs(200, 30000)(&cfg)

		if cfg.Throttle.ThrottleTimeoutMs != 15000 {
			t.Errorf("expected ThrottleTimeoutMs 15000, got %d", cfg.Throttle.ThrottleTimeoutMs)
		}
		if cfg.Limiter.RateLimitWindowMs != 30000 {
			t.Errorf("expected RateLimitWindowMs 30000, got %d", cfg.Limiter.RateLimitWindowMs)
		}
	})
}

func TestRouteCORS_And_DefaultCORS(t *testing.T) {
	mgr, err := New(
		WithAllowedOrigins("https://global.com"),
		WithAllowedHeaders("X-Global"),
	)
	if err != nil {
		t.Fatalf("failed to init manager: %v", err)
	}
	defer mgr.Close()

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("DefaultCORS uses Manager security config", func(t *testing.T) {
		cors := mgr.DefaultCORS()(okHandler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "https://global.com")
		w := httptest.NewRecorder()
		cors.ServeHTTP(w, req)

		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://global.com" {
			t.Errorf("expected https://global.com, got %q", got)
		}
	})

	t.Run("RouteCORS overrides Manager security config", func(t *testing.T) {
		cors := mgr.RouteCORS(
			WithCORSOrigins("https://override.com"),
			WithCORSHeaders("X-Override"),
		)(okHandler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "https://override.com")
		w := httptest.NewRecorder()
		cors.ServeHTTP(w, req)

		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://override.com" {
			t.Errorf("expected https://override.com, got %q", got)
		}
		if got := w.Header().Get("Access-Control-Allow-Headers"); got != "X-Override" {
			t.Errorf("expected X-Override, got %q", got)
		}
	})
}

func TestMaxBodySize_Options(t *testing.T) {
	mgr, err := New(
		WithRequestBodyNonFileLimitSize(100), // 100 bytes default
	)
	if err != nil {
		t.Fatalf("failed to init manager: %v", err)
	}
	defer mgr.Close()

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("custom body limit override", func(t *testing.T) {
		// Override to 10 bytes limit
		limiter := mgr.MaxBodySize(WithCustomNonFileBodyLimit(10))(okHandler)

		// 20 bytes request
		req := httptest.NewRequest("POST", "/data", nil)
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = 20

		w := httptest.NewRecorder()
		limiter.ServeHTTP(w, req)

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("expected 413 PayloadTooLarge, got %d", w.Code)
		}
	})
}

func TestGraphQLChain_Options(t *testing.T) {
	mgr, err := New()
	if err != nil {
		t.Fatalf("failed to init manager: %v", err)
	}
	defer mgr.Close()

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	chain := mgr.GraphQLChain(WithGraphQLMaxDepth(2))(okHandler)

	req := httptest.NewRequest("POST", "/graphql", nil)
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)

	// Since body is empty, it proceeds to okHandler
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	t.Run("string literals with braces do not inflate depth", func(t *testing.T) {
		body := `{"query": "query { user(bio: \"{ { { {\") { name } }"}`
		req := httptest.NewRequest("POST", "/graphql", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 OK because depth is 2, got %d. Body: %s", w.Code, w.Body.String())
		}
	})

	t.Run("excessive actual depth is rejected", func(t *testing.T) {
		body := `{"query": "query { user { profile { address { street } } } }"}`
		req := httptest.NewRequest("POST", "/graphql", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 BadRequest because depth is 4 > 2, got %d", w.Code)
		}
	})
}

func TestWebSocketChain_Options(t *testing.T) {
	mgr, err := New()
	if err != nil {
		t.Fatalf("failed to init manager: %v", err)
	}
	defer mgr.Close()

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	chain := mgr.WebSocketChain(WithWSAuthenticator(func(r *http.Request) bool {
		return false // Reject
	}))(okHandler)

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", w.Code)
	}
}
