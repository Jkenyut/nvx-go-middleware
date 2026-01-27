# NVX Go Middleware

A comprehensive HTTP middleware library for Go that combines custom authentication, validation, and logging with Chi middleware utilities. Perfect for building secure, production-ready APIs with `net/http`.

## 🚀 Features

- ✅ **Panic Recovery** - Graceful panic handling with stack traces
- ✅ **Audit Logging** - Complete request/response logging with customizable storage
- ✅ **RSA Signature Validation** - Request signature verification for security
- ✅ **JWT Authentication** - Token-based authentication support
- ✅ **Header Validation** - Enforce required headers (NVX-* custom headers)
- ✅ **Device Validation** - Validate device info (User-Agent, Device-ID, Platform, MAC)
- ✅ **Rate Limiting** - Throttle requests per route (via Chi)
- ✅ **Compression** - Automatic gzip compression (via Chi)
- ✅ **Request Timeout** - Configurable request timeouts
- ✅ **Body Size Limiting** - Prevent DoS attacks
- ✅ **CORS Support** - Configurable CORS headers
- ✅ **Real IP Extraction** - Handle proxied requests correctly
- ✅ **Security Headers** - Automatic security header injection
- ✅ **Context Injection** - Custom context values for handlers

## 📦 Installation

```bash
go get github.com/Jkenyut/nvx-go-middleware
```

## 🎯 Quick Start

```go
package main

import (
    "net/http"
    "time"
    
    mw "github.com/Jkenyut/nvx-go-middleware"
)

func main() {
    // Create middleware manager
    mgr := mw.New(mw.Config{
        PublicKeySignature:  "your-rsa-public-key",
        PrivateKeySignature: "your-rsa-private-key",
        AllowedOrigins:      []string{"https://example.com"},
        RequestTimeout:      60 * time.Second,
        RequestBodyLimit:    3 * 1024 * 1024, // 3MB
        Env:                 "development",
    })

    // Create chain config
    chainCfg := mw.DefaultChainConfig()

    mux := http.NewServeMux()

    // Public route (device validation)
    mux.Handle("/register", mgr.PublicChain(chainCfg)(
        mw.MethodOnly("POST", http.HandlerFunc(registerHandler)),
    ))

    // Authenticated route (JWT + signature validation)
    mux.Handle("/profile", mgr.AuthChain(chainCfg)(
        mw.MethodOnly("GET", http.HandlerFunc(profileHandler)),
    ))

    http.ListenAndServe(":8080", mux)
}
```

## 📖 Usage Guide

### 1. Configuration

```go
cfg := mw.Config{
    // Required
    PublicKeySignature:  "your-rsa-public-key",
    PrivateKeySignature: "your-rsa-private-key",
    AllowedOrigins:      []string{"https://example.com"},
    
    // Optional (with defaults)
    LogStore:         &CustomLogStore{}, // Default: ConsoleStore
    Logger:           customLogger,       // Default: zerolog console
    Env:              "production",       // Default: "development"
    RequestTimeout:   30 * time.Second,   // Default: 60s
    RequestBodyLimit: 5 * 1024 * 1024,    // Default: 3MB
    TrustedProxies:   []string{"10.0.0.0/8"},
    
    // Custom context injector (optional)
    ContextInjector: func(r *http.Request) *http.Request {
        // Inject custom values into context
        return r
    },
}

mgr := mw.New(cfg)
```

### 2. Middleware Chains

#### Global Chain
Basic middleware for all requests:
```go
chainCfg := mw.DefaultChainConfig()
handler := mgr.GlobalChain(chainCfg)(yourHandler)
```

#### Public Chain
For public endpoints with device validation:
```go
handler := mgr.PublicChain(chainCfg)(yourHandler)
```

Required headers:
- `NVX-Request-ID`
- `NVX-Merchant-Key`
- `NVX-IP`
- `NVX-User-Agent`
- `NVX-Device-ID`
- `NVX-Platform` (android, ios, web, desktop)
- `NVX-Mac-Address`
- `NVX-Signature`

#### Auth Chain
For authenticated endpoints with JWT validation:
```go
handler := mgr.AuthChain(chainCfg)(yourHandler)
```

Additional required headers:
- `NVX-Token` (JWT)
- `NVX-User-ID`
- `NVX-Signature` (calculated with token + user ID)

#### Admin Chain
For admin-only endpoints:
```go
adminCheck := func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Header.Get("NVX-User-Type") != "admin" {
            w.WriteHeader(http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}

handler := mgr.AdminChain(chainCfg, adminCheck)(yourHandler)
```

### 3. Custom Chain Configuration

```go
chainCfg := mw.ChainConfig{
    UseChiRequestID:    true,  // Auto-generate request IDs
    UseChiRealIP:       true,  // Extract real IP from proxies
    UseChiCompress:     true,  // Gzip compression
    UseChiTimeout:      false, // Use custom timeout instead
    UseChiThrottle:     true,  // Rate limiting
    UseChiStripSlashes: true,  // Normalize URLs
    CompressionLevel:   9,     // 1-9, default: 5
    ThrottleLimit:      50,    // Concurrent requests, default: 100
}
```

### 4. Individual Middleware

You can also use middleware individually:

```go
handler := mw.ApplyMiddleware(
    yourHandler,
    mgr.EnsureAuth,           // JWT validation
    mgr.ChiThrottle(100),     // Rate limiting
    mgr.MaxBodySize(5*1024*1024), // Body size limit
    mgr.Logger,               // Audit logging
    mgr.Recoverer,            // Panic recovery
)
```

### 5. Custom Log Storage

Implement the `LogStore` interface to save logs to your database:

```go
type DatabaseStore struct {
    db *sql.DB
}

func (d *DatabaseStore) Save(entry model.AuditLog) error {
    _, err := d.db.Exec(`
        INSERT INTO audit_logs (method, url, status_code, latency_ms, ...)
        VALUES ($1, $2, $3, $4, ...)
    `, entry.Method, entry.FullURL, entry.StatusCode, entry.LatencyMS, ...)
    return err
}

// Use it:
mgr := mw.New(mw.Config{
    LogStore: &DatabaseStore{db: db},
    // ... other config
})
```

### 6. Signature Validation

The middleware validates request signatures using RSA:

**For Auth Requests:**
```go
signature = RSA_Sign(PrivateKey, [RequestID, MerchantKey, Token, UserID])
```

**For Public Requests:**
```go
messageSignature = RSA_Sign(PublicKey, [RequestID, MerchantKey])
signature = RSA_Sign(PublicKey, [RequestID, MerchantKey, UserAgent, DeviceID, Platform, MacAddress, messageSignature])
```

Include the signature in the `NVX-Signature` header.

## 🔧 Helper Functions

```go
// Method restriction
handler := mw.MethodOnly("POST", yourHandler)

// Apply multiple middleware
handler := mw.ApplyMiddleware(
    yourHandler,
    middleware1,
    middleware2,
)

// Health check endpoint
mux.HandleFunc("/ping", mw.Heartbeat("/ping"))

// Get Chi request ID
requestID := mw.GetChiRequestID(r)
```

## 📝 Examples

See the `examples/` directory for complete examples:

- **basic/** - Simple API with public and auth routes
- **advanced/** - Production-ready API with admin routes and custom middleware

### Running Examples

```bash
cd examples/basic
go run main.go

# Test with curl:
curl -X POST http://localhost:8080/api/register \
  -H "NVX-Request-ID: req-123" \
  -H "NVX-Merchant-Key: merchant-1" \
  -H "NVX-IP: 192.168.1.1" \
  -H "NVX-User-Agent: MyApp/1.0" \
  -H "NVX-Device-ID: device-123" \
  -H "NVX-Platform: android" \
  -H "NVX-Mac-Address: 00:11:22:33:44:55" \
  -H "NVX-Signature: your-signature" \
  -d '{"email":"test@example.com"}'
```

## 🛡️ Security Features

1. **Request Signature Validation** - Prevent tampering
2. **JWT Token Validation** - Secure authentication
3. **IP Whitelisting** - Trusted proxy support
4. **Rate Limiting** - Prevent abuse
5. **Body Size Limits** - Prevent DoS
6. **Security Headers** - XSS, clickjacking protection
7. **CORS Control** - Origin validation

## 🎨 Architecture

```
Request
  ↓
Recoverer (panic handling)
  ↓
Logger (audit logging)
  ↓
RealIP (extract client IP)
  ↓
EnsureCommonHeaders (validate required headers)
  ↓
SecureHeaders (inject security headers)
  ↓
Compress (gzip)
  ↓
MaxBodySize (limit body)
  ↓
CORS
  ↓
[Route-Specific Middleware]
  ↓
Handler
```

## 📊 Audit Log Structure

```go
type AuditLog struct {
    Method          string    // HTTP method
    FullURL         string    // Complete URL
    StatusCode      int       // Response status
    LatencyMS       int       // Request duration
    MerchantKey     string    // Client merchant key
    ClientIP        string    // Client IP address
    RequestID       string    // Request ID
    TransactionID   string    // Transaction ID
    RequestHeaders  string    // JSON of request headers
    ResponseHeaders string    // JSON of response headers
    RequestBody     string    // Request body (if JSON)
    ResponseBody    string    // Response body (if JSON)
    CreatedBy       int64     // User ID
    CreatedAt       time.Time // Timestamp
}
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT License - see LICENSE file for details.

## 🔗 Dependencies

- [github.com/go-chi/chi/v5](https://github.com/go-chi/chi) - Router and middleware utilities
- [github.com/rs/zerolog](https://github.com/rs/zerolog) - Structured logging
- Your internal helpers:
  - `github.com/Jkenyut/nvx-go-helper/activity` - Context utilities
  - `github.com/Jkenyut/nvx-go-helper/cryptoutil` - Crypto utilities
  - `github.com/Jkenyut/nvx-go-helper/format` - Formatting utilities
  - `github.com/Jkenyut/nvx-go-helper/response` - Response helpers

## 📞 Support

For issues, questions, or contributions, please open an issue on GitHub.

---

Made with ❤️ by NVX Team
