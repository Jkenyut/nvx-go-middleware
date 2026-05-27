# NVX Go Middleware

A high-performance, modular, and secure HTTP middleware library for Go. Designed to be **Production-Ready** and **DDoS-Resistant** from day one. Perfect for building secure APIs with `net/http`, integrating seamlessly with Chi, gRPC, and WebSockets.

## 🚀 Features

- ✅ **High-Performance JSON** - Powered by `bytedance/sonic` for ultra-fast request/response parsing.
- ✅ **Smart Execution Chain** - DDoS & Bad Auth requests are blocked *before* hitting the logger or application, saving CPU & DB I/O.
- ✅ **Secure IP Resolution (`TrustProxy`)** - Anti-spoofing mechanism for `X-Forwarded-For`, totally immune to arbitrary header injection.
- ✅ **OOM Guard (`MaxBytesReader`)** - Safely caps request memory allocations before processing.
- ✅ **Rate Limiting** - Dynamic per-route throttling based on verified IP or Auth Tokens.
- ✅ **Panic Recovery** - Graceful recovery that logs the stack trace without leaking it to the client.
- ✅ **Audit Logging** - Asynchronous database-agnostic request/response logging.
- ✅ **Multi-Protocol Support** - Native wrappers for **HTTP**, **gRPC** (Unary & Stream), and **WebSockets**.
- ✅ **Multi-Auth Pipelines** - Pre-built chains for Public, Auth, API Key, Internal, and Webhook endpoints.
- ✅ **CORS & Security Headers** - Secure defaults for browser security.

## 📦 Installation

```bash
go get github.com/Jkenyut/nvx-go-middleware
```

## 🎯 Quick Start

```go
package main

import (
    "log"
    "net/http"
    "time"
    
    mw "github.com/Jkenyut/nvx-go-middleware"
)

func main() {
    // 1. Create middleware manager safely
    mgr, err := mw.NewWithError(mw.Config{
        PublicKeySignature:  "your-rsa-public-key",
        PrivateKeySignature: "your-rsa-private-key",
        AllowedOrigins:      []string{"https://example.com"},
        TrustedProxies:      []string{"10.0.0.0/8"}, // Vital for accurate Rate Limits!
        RequestTimeout:      60 * time.Second,
        Env:                 "production",
    })
    if err != nil {
        log.Fatalf("Failed to init middleware: %v", err)
    }

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
- `mgr.WebSocketChain()`: Handles Protocol Upgrades safely.

## 🛠 Advanced Configuration

```go
chainCfg := mw.ChainConfig{
    UseChiCompress:        true,  // Gzip compression
    UseChiTimeout:         true,  // Context cancellation on timeout
    UseChiThrottle:        true,  // Concurrent request limits
    UseChiStripSlashes:    true,  // Normalize URLs
    UseChiRateLimitPublic: true,  // Prevent abuse on public endpoints
    CompressionLevel:      5,
    ThrottleLimit:         100,
    LimiterConfig: mw.ConfigLimiter{
        RateLimitRequests: 30,
        RateLimitWindow:   1 * time.Minute,
    },
}
```
*(Note: `ChiRealIP` was intentionally removed from this library to prevent X-Forwarded-For spoofing attacks. The library uses the superior `TrustProxy` algorithm automatically).*

## 🔌 gRPC & WebSockets Integration

This middleware isn't just for REST! 

**gRPC Interceptors:**
```go
server := grpc.NewServer(
    grpc.ChainUnaryInterceptor(
        mgr.UnaryInterceptorPanicRecover(),
        mgr.UnaryInterceptorLogger(),
    ),
    grpc.ChainStreamInterceptor(
        mgr.StreamInterceptorPanicRecover(),
        mgr.StreamInterceptorLogger(),
    ),
)
```

**WebSockets:**
```go
authCheck := func(r *http.Request) bool {
    return r.Header.Get("Authorization") != ""
}
mux.Handle("/ws", mgr.WebSocketChain(authCheck)(wsHandler))
```

## 📊 Custom Audit Storage

Inject your own database logger natively:

```go
type DatabaseStore struct { db *sql.DB }

func (d *DatabaseStore) Save(ctx context.Context, entry model.AuditLog) error {
    // This executes asynchronously in a goroutine
    _, err := d.db.ExecContext(ctx, "INSERT INTO audit_logs ...")
    return err
}

mgr, _ := mw.NewWithError(mw.Config{
    LogStore: &DatabaseStore{db: myDB},
    // ...
})
```

## 📄 License

Apache 2.0 License - see LICENSE file for details.
