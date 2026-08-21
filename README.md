# NVX Go Middleware

A high-performance, modular, and secure HTTP middleware library for Go. Designed to be **Production-Ready** and **DDoS-Resistant** from day one. Perfect for building secure APIs with `net/http`, integrating seamlessly with Chi, gRPC, WebSockets, and GraphQL.

## 🚀 Features

- ✅ **High-Performance JSON** - Powered by `bytedance/sonic` for ultra-fast request/response parsing with JIT assembly.
- ✅ **Zero Allocation & Memory Safe** - Extensive `sync.Pool` usage and strictly bounded synchronous logging prevents OOM and Goroutine Leaks.
- ✅ **Smart Execution Chain** - DDoS & Bad Auth requests are blocked *before* hitting the logger or application, saving CPU & DB I/O.
- ✅ **Secure IP Resolution (`TrustProxy`)** - Anti-spoofing mechanism for `X-Forwarded-For`, totally immune to arbitrary header injection.
- ✅ **OpenTelemetry Tracing** - Built-in context propagation with auto-injected `trace_id` and `span_id`.
- ✅ **GraphQL Specific Protections** - Native AST depth-limiting and introspection blocking to prevent recursive query explosion.
- ✅ **Rate Limiting** - Dynamic per-route throttling based on verified IP or Auth Tokens.
- ✅ **Panic Recovery** - Graceful recovery across HTTP, gRPC, and WebSockets that logs the stack trace securely.
- ✅ **Multi-Protocol Support** - Native wrappers for **HTTP**, **gRPC** (Unary & Stream), **GraphQL**, and **WebSockets**.
- ✅ **Multi-Auth Pipelines** - Pre-built chains for Public, Auth, API Key, Internal, and Webhook endpoints.
- ✅ **Dynamic Pluggable Headers** - Fully configurable header extraction (`X-Request-Id`, `X-User-Id`, etc.) and dynamic log injection.

## 📦 Installation

```bash
go get github.com/Jkenyut/nvx-go-middleware@latest
```

## 🎯 Quick Start

```go
package main

import (
	"log"
	"net/http"
	
	mw "github.com/Jkenyut/nvx-go-middleware"
)

func main() {
	// 1. Create middleware manager safely
	mgr, err := mw.NewWithError(mw.Config{
		ServiceName:         "my-service",
		PublicKeySignature:  "your-rsa-public-key",
		PrivateKeySignature: "your-rsa-private-key",
		AllowedOrigins:      []string{"https://example.com"},
		TrustedProxies:      []string{"10.0.0.0/8"}, // Vital for accurate Anti-Spoofing!
	})
	if err != nil {
		log.Fatalf("Failed to init middleware: %v", err)
	}
	defer mgr.Close() // Gracefully close background loggers to prevent log loss on shutdown

	// 2. Load default chain behavior
	chainCfg := mw.DefaultChainConfig()
	chainCfg.UseChiRateLimitPublic = true // Enable Anti-DDoS

	mux := http.NewServeMux()

	// 3. Public Route (Rate Limited, Validated, IP Verified)
	mux.Handle("/api/v1/register", mgr.PublicChain(chainCfg)(
		mgr.MethodOnly("POST", http.HandlerFunc(registerHandler)),
	))

	// 4. Authenticated Route (JWT + Signature)
	mux.Handle("/api/v1/profile", mgr.PublicAuthChain(chainCfg)(
		mgr.MethodOnly("GET", http.HandlerFunc(profileHandler)),
	))

	log.Println("Server running on :8080")
	http.ListenAndServe(":8080", mux)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"message": "Registered"}`))
}
func profileHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"message": "Profile"}`))
}
```

## 🎛️ Dynamic Headers (Pluggable)

NVX Go Middleware allows you to fully customize or disable mandatory headers like `X-Request-Id`, `X-Transaction-Id`, etc., and dynamically configure which headers are logged without changing any code.

```go
mgr, _ := mw.NewWithError(mw.Config{
	Headers: mw.ConfigHeaders{
		// Customize default header names
		Keys: mw.HeaderKeys{
			RequestID:     "Trace-Id", // Rename X-Request-Id to Trace-Id
			TransactionID: "X-Tx-Id",
			UserID:        "X-User-Id",
		},
	},
	Logging: mw.ConfigLogging{
		// Dynamically plug/unplug headers from the logger
		LogHeaders: []string{"Trace-Id", "X-Tx-Id", "X-User-Id", "X-Custom-Header"},
	},
})
```

## 🛡️ Smart Architecture (Execution Order)

NVX Go Middleware uses a mathematically structured chain to protect your application:

1. **Outer Layer (Network)**: `CORS` and `Panic Recovery`.
2. **IP Resolution (`TrustProxy`)**: Extracts the real IP *only* if the request comes from your `TrustedProxies`.
3. **Validation (`EnsureAuth`)**: Drops invalid signatures/keys with `401 Unauthorized`.
4. **Anti-DDoS (`RateLimit`)**: Drops excessive requests with `429 Too Many Requests`.
5. **Inner Layer (`Logger`)**: Logs the request. *(Because it sits inside the rate limiter, DDoS floods will NEVER pollute your database logs!)*
6. **App Layer**: Your business logic.

## 🔗 Pre-Built Middleware Chains

Depending on your endpoint's purpose, use one of our optimized chains:

- `mgr.PublicChain()`: Unauthenticated users (Device validation & IP Rate limits).
- `mgr.PublicAuthChain()`: Authenticated users (Requires JWT/Tokens).
- `mgr.PublicAPIKeyChain()`: Server-to-Server external (Requires API Key).
- `mgr.InternalChain()`: Internal microservices (Bypasses rate limits, requires strict internal keys).
- `mgr.WebhookChain()`: Stripped down chain optimized for massive payload ingestion.

## 🔌 Advanced Protocols (gRPC, GraphQL, WebSockets)

This middleware isn't just for REST! 

**gRPC (Factory Pattern with Auto-Telemetry):**
```go
// Safely builds a grpc.Server injected with OTel Traces, Metrics, Panic Recovery & Audit Logging
grpcServer := mgr.NewGRPCServer()

// Register your service
// pb.RegisterMyServiceServer(grpcServer, &myServiceImpl{})
```

**GraphQL (With AST Depth Limiter & Telemetry):**
```go
maxDepth := 10 // Prevent deep recursive queries
// Safely wrapped with OTel Metrics and TrustProxy
mux.Handle("/graphql", mgr.GraphQLChain(maxDepth)(graphqlHandler))
```

**WebSockets (With Per-Connection Auth & Telemetry):**
```go
// Browsers cannot send headers for WebSockets, validate via Query Token
authCheck := func(r *http.Request) bool {
	return r.URL.Query().Get("token") != ""
}
// Safely wrapped with OTel Metrics and TrustProxy
mux.Handle("/ws", mgr.WebSocketChain(authCheck)(wsHandler))
```

## 📊 Custom Audit Storage

Inject your own database logger natively. The `Save` method is called synchronously by the middleware to prevent `goroutine` memory leaks under heavy load. If you require asynchronous batching, implement it safely within your `LogStore` using Kafka, Channels, or Batch queues.

```go
type DatabaseStore struct { db *sql.DB }

func (d *DatabaseStore) Save(ctx context.Context, entry *model.AuditLog) error {
	_, err := d.db.ExecContext(ctx, "INSERT INTO audit_logs ...")
	return err
}

mgr, _ := mw.NewWithError(mw.Config{
	LogStore: &DatabaseStore{db: myDB},
})
```

## 📄 License

Apache 2.0 License - see LICENSE file for details.
