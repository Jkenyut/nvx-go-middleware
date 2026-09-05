# NVX Go Middleware

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/Jkenyut/nvx-go-middleware)](https://goreportcard.com/report/github.com/Jkenyut/nvx-go-middleware)

High-performance, modular, and secure HTTP middleware library for Go. Designed for **Native `net/http` First**, enterprise-grade DDoS resilience, zero-copy kernel streaming, and zero-trust security from day one.

Seamlessly integrates with **native Go servers**, **Chi**, **gRPC**, **WebSockets**, and **GraphQL**.

---

## 🚀 Key Highlights

- ⚡ **Native `net/http` First** - 100% standard library compliance. No forced third-party router wrappers. Chi is supported as an optional auxiliary layer.
- 🏎️ **Zero-Copy & Zero-Allocation** - Implements `io.ReaderFrom` for OS kernel `sendfile` zero-copy streaming and `io.StringWriter` for allocation-free JSON writing.
- 🛡️ **Memory Safe Buffer Pooling** - Pooled body recorders (`sync.Pool`) enforce a 256KB retention threshold, preventing permanent heap bloat across GC cycles.
- 🔒 **Go 1.20+ `ResponseController` Ready** - Full `Unwrap() http.ResponseWriter` chaining across all custom wrappers (`Flusher`, `Hijacker`, deadlines, full-duplex).
- 🧱 **Smart Execution Pipeline** - DDoS and bad authentication attempts are blocked *before* reaching the logger or database layer, saving CPU and I/O.
- 🌐 **Anti-Spoofing IP Resolution (`TrustProxy`)** - Right-to-left traversal of `X-Forwarded-For` across pre-compiled CIDRs prevents spoofed `X-Real-Ip` injection.
- 📊 **Context-Preserved Audit Logging** - Uses `context.WithoutCancel` to guarantee audit trail persistence even if clients abort or requests time out.
- 🔐 **Constant-Time HMAC Signatures** - Defends against timing attacks with `crypto/subtle.ConstantTimeCompare`. Includes runnable Go & TypeScript client examples.
- 🔭 **OpenTelemetry Tracing** - Automatic context propagation with `trace_id` and `span_id` injection.
- ⚡ **Ultra-Fast JSON** - Powered by `bytedance/sonic` with native JIT assembly.

---

## 📦 Installation

```bash
go get github.com/Jkenyut/nvx-go-middleware@latest
```

---

## 🎯 Quick Start (Native `net/http`)

```go
package main

import (
	"log"
	"net/http"
	"time"

	mw "github.com/Jkenyut/nvx-go-middleware"
)

func main() {
	// 1. Initialize Middleware Manager
	mgr, err := mw.NewWithError(&mw.Config{
		Core: mw.ConfigCore{
			ServiceName: "my-service",
			Env:         "production",
		},
		Security: mw.ConfigSecurity{
			PublicKeySignature:  "your-rsa-or-hmac-key",
			PrivateKeySignature: "your-private-key",
			TrustedProxies:      []string{"10.0.0.0/8", "172.16.0.0/12"},
		},
		Limits: mw.ConfigLimits{
			RequestTimeout:       30,             // seconds
			RequestBodyLimitSize: 5 * 1024 * 1024, // 5MB
		},
		Logging: mw.ConfigLogging{
			LogRequestBodies:  true,
			LogResponseBodies: true,
		},
	})
	if err != nil {
		log.Fatalf("Failed to initialize middleware: %v", err)
	}

	// 2. Configure Execution Chain
	chainCfg := mw.ChainConfig{
		Features: mw.ChainFeatures{
			UseChiRateLimitPublic: true,
			UseChiRateLimitAuth:   true,
			UseChiCompress:        true,
		},
	}
	chainCfg.ApplyDefaults()

	// 3. Native Go 1.22+ ServeMux
	mux := http.NewServeMux()

	// Public endpoint (Anti-DDoS, IP verification, and device auth)
	mux.Handle("POST /api/v1/register", mgr.PublicChain(&chainCfg)(
		http.HandlerFunc(registerHandler),
	))

	// Authenticated endpoint (JWT/Bearer token + signature verification)
	mux.Handle("GET /api/v1/profile", mgr.PublicAuthChain(&chainCfg)(
		http.HandlerFunc(profileHandler),
	))

	// 4. Start Production Server
	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Println("Server running on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"success","message":"Registered"}`))
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"success","user_id":"12345"}`))
}
```

---

## 🛡️ Execution Pipeline Architecture

Requests flow through a mathematically ordered defense pipeline:

```text
Client Request
      │
      ▼
┌────────────────────────────────────────────────────────┐
│ 1. Outer Layer: TrustProxy (Anti-Spoofing Real IP)    │
├────────────────────────────────────────────────────────┤
│ 2. Telemetry: OpenTelemetry Span & Trace Propagation   │
├────────────────────────────────────────────────────────┤
│ 3. Resilience: Panic Recoverer                         │
├────────────────────────────────────────────────────────┤
│ 4. Perimeter Defense: DDoS Rate Limiting & Auth Checks │
│    (Bad requests drop HERE with 401/429 — NO DB load!) │
├────────────────────────────────────────────────────────┤
│ 5. Payload Guard: MaxBodySize Content-Type Validator   │
├────────────────────────────────────────────────────────┤
│ 6. Response Cleaners: RemoveHeaders (Fingerprinting)   │
├────────────────────────────────────────────────────────┤
│ 7. Observability: Audit Logger (Plaintext JSON)       │
├────────────────────────────────────────────────────────┤
│ 8. Compression: ChiCompress (Gzip to Client)           │
├────────────────────────────────────────────────────────┤
│ 9. Application Logic Handler                           │
└────────────────────────────────────────────────────────┘
```

> **Smart Logging Guarantee**: Because the Rate Limiter and Auth Validators run *outside* the Logger, malicious DDoS floods and credential-stuffing attacks are rejected before hitting your database or logging store.

---

## 🔗 Pre-Built Middleware Chains

| Chain | Use Case | Included Protections |
| :--- | :--- | :--- |
| `mgr.PublicChain(&cfg)` | Unauthenticated public endpoints | TrustProxy, MaxBodySize, Public RateLimit, AuditLog |
| `mgr.PublicAuthChain(&cfg)` | Authenticated users (JWT/Bearer) | Auth Validation, User RateLimit, Token Extraction |
| `mgr.PublicAPIKeyChain(&cfg)` | B2B & Third-party integrations | `X-Api-Key` Validation, Key-based Quotas |
| `mgr.InternalChain(&cfg)` | Service-to-service microservices | Strict internal secret check, RateLimit bypass |
| `mgr.WebhookChain(&cfg)` | Third-party webhooks | Optimized for high-throughput payload ingestion |
| `mgr.GraphQLChain(maxDepth)` | GraphQL API endpoints | AST Depth Limiter, Introspection Blocking (GET/POST) |
| `mgr.WebSocketChain(authFn)` | WebSocket upgrade connections | Connection Hijacking, Upgrade Audit, Token Auth |

---

## 🔌 Multi-Protocol Support

### gRPC Server Factory
Build an enterprise gRPC server injected with OpenTelemetry tracing, panic recovery, and logging in one call:
```go
grpcServer := mgr.NewGRPCServer()
// pb.RegisterUserServiceServer(grpcServer, &userService{})
```

### GraphQL Protection
Defends against recursive query explosion and unauthorized schema scraping:
```go
// Enforces max query depth of 10 and blocks introspection queries
mux.Handle("/graphql", mgr.GraphQLChain(10)(graphqlHandler))
```

### WebSockets
Handles connection hijacking cleanly with full telemetry:
```go
authCheck := func(r *http.Request) bool {
    return r.URL.Query().Get("token") != ""
}
mux.Handle("/ws", mgr.WebSocketChain(authCheck)(wsHandler))
```

---

## 🔑 Client Signature Verification (HMAC-SHA256)

For high-security mobile, web, and server clients, `nvx-go-middleware` supports end-to-end request signing.

Working, production-ready client signature implementations are included in [`examples/client_signature/`](file:///Users/satria/workspace/projects/nvx-go/nvx-go-middleware/examples/client_signature):
- **Go Client**: [`signature_example.go`](file:///Users/satria/workspace/projects/nvx-go/nvx-go-middleware/examples/client_signature/signature_example.go)
- **TypeScript / Node.js Client**: [`signature_example.ts`](file:///Users/satria/workspace/projects/nvx-go/nvx-go-middleware/examples/client_signature/signature_example.ts)

---

## ⚡ Performance & Benchmarks

Run benchmarks locally:
```bash
go test -bench=. -benchmem ./...
```

Measured on Apple Silicon (arm64):
```text
BenchmarkLogger-10              53070        21616 ns/op      6692 B/op      53 allocs/op
BenchmarkRecoverer-10         9794725        121.6 ns/op       576 B/op       6 allocs/op
BenchmarkResolveBodyToken-10   859600         1334 ns/op       128 B/op       2 allocs/op
BenchmarkBuildRateKey-10      2891660        417.4 ns/op       880 B/op      11 allocs/op
```

---

## 🧪 Verification & Quality Gates

This repository strictly enforces 5 automated quality gates:

```bash
gofmt -l .                   # Formatting
go vet ./...                 # Static Analysis
golangci-lint run ./...      # Linter
go test -v -race -count=1 .  # Concurrency Race Detector
govulncheck ./...            # Vulnerability Scanning
```

---

## 📄 License

Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
