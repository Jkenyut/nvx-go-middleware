# NVX Go Middleware - Library Structure

## 📁 Complete File Structure

```
nvx-go-middleware/
├── go.mod                      # Go module definition
├── .gitignore                  # Git ignore rules
├── LICENSE                     # MIT License
├── README.md                   # Main documentation
├── CHANGELOG.md               # Version history
├── CONTRIBUTING.md            # Contribution guidelines
│
├── Core Files:
├── config.go                   # Configuration structure and defaults
├── manager.go                  # Middleware manager (main entry point)
├── middleware.go               # All custom middleware implementations
├── chain.go                    # Middleware chaining helpers + Chi integration
├── chi.go                      # Chi middleware wrappers
├── response_writer.go          # Response recorder for logging
├── store.go                    # LogStore interface and implementations
│
├── constants/
│   └── constants.go            # Constants (headers, error messages, platforms)
│
├── model/
│   └── audit_log.go            # AuditLog model structure
│
└── examples/
    ├── basic/
    │   └── main.go             # Simple example with public + auth routes
    └── advanced/
        └── main.go             # Advanced example with admin routes
```

## 📦 Core Components

### 1. **config.go**
- `Config` struct - Main configuration
- `DefaultConfig()` - Returns default configuration
- `Validate()` - Validates configuration

### 2. **manager.go**
- `Manager` struct - Main middleware manager
- `New(cfg Config)` - Creates new manager instance
- `Config()` - Returns current configuration
- `envProd()` - Checks if running in production

### 3. **middleware.go**
Contains all custom middleware:
- `Recoverer` - Panic recovery
- `Logger` - Request/response logging
- `EnsureCommonHeaders` - Validate common headers
- `EnsureAuth` - JWT authentication validation
- `EnsurePublicAuth` - Device validation
- `SecureHeaders` - Security headers injection
- `TrustProxy` - Real IP extraction
- `MaxBodySize` - Body size limiting
- `CORS` - CORS handling
- `OnlyMethod` - HTTP method restriction

Helper functions:
- `validateHeaders()` - Header validation
- `validateSignatureAuthHeaders()` - Auth signature validation
- `validateSignaturePublicHeaders()` - Public signature validation
- `FullURL()` - Get complete request URL
- `injectContext()` - Inject values into context
- `readAndRestoreBodyJSON()` - Read and restore request body

### 4. **chain.go**
Middleware chaining utilities:
- `ChainConfig` - Configuration for chains
- `DefaultChainConfig()` - Default chain config
- `GlobalChain()` - Basic middleware chain
- `PublicChain()` - Public routes chain
- `AuthChain()` - Authenticated routes chain
- `AdminChain()` - Admin routes chain
- `ApplyMiddleware()` - Apply multiple middleware
- `MethodOnly()` - Method restriction helper
- `Heartbeat()` - Health check helper

### 5. **chi.go**
Chi middleware wrappers:
- `ChiRequestID()` - Request ID generation
- `ChiRealIP()` - Real IP extraction
- `ChiCompress()` - Gzip compression
- `ChiTimeout()` - Request timeout
- `ChiThrottle()` - Rate limiting
- `ChiStripSlashes()` - URL normalization
- `ChiNoCache()` - Cache prevention
- `ChiHeartbeat()` - Health check
- `ChiProfiler()` - Debug profiler
- `GetChiRequestID()` - Extract request ID
- `WrapWithChiWriter()` - Response writer wrapper

### 6. **response_writer.go**
Response recorder for logging:
- `responseRecorder` struct - Captures response
- `wrapResponseWriter()` - Create wrapper
- `WriteHeader()` - Capture status code
- `Write()` - Capture response body
- `Flush()` - Flusher interface
- `Hijack()` - Hijacker interface
- `Status()` - Get status code
- `BytesWritten()` - Get bytes count

### 7. **store.go**
Log storage:
- `LogStore` interface - Storage contract
- `ConsoleStore` struct - Console logger
- `Save()` - Save audit log

### 8. **constants/constants.go**
- Header constants (NVX-*)
- Error messages
- Required headers lists
- Valid platforms
- Security headers

### 9. **model/audit_log.go**
- `AuditLog` struct - Audit log model

## 🚀 Usage Examples

### Basic Usage (Minimal)
```go
mgr := mw.New(mw.Config{
    PublicKeySignature:  "key",
    PrivateKeySignature: "key",
    AllowedOrigins:      []string{"*"},
})

chainCfg := mw.DefaultChainConfig()

mux := http.NewServeMux()
mux.Handle("/login", mgr.PublicChain(chainCfg)(handler))
http.ListenAndServe(":8080", mux)
```

### Advanced Usage (Production)
```go
// Custom log store
type DBStore struct { db *sql.DB }
func (d *DBStore) Save(entry model.AuditLog) error {
    // Save to database
    return nil
}

// Custom chain config
chainCfg := mw.ChainConfig{
    UseChiRequestID:    true,
    UseChiRealIP:       true,
    UseChiCompress:     true,
    UseChiThrottle:     true,
    CompressionLevel:   9,
    ThrottleLimit:      50,
}

// Create manager
mgr := mw.New(mw.Config{
    LogStore:            &DBStore{db: db},
    PublicKeySignature:  "prod-public-key",
    PrivateKeySignature: "prod-private-key",
    AllowedOrigins:      []string{"https://api.example.com"},
    TrustedProxies:      []string{"10.0.0.0/8"},
    RequestTimeout:      30 * time.Second,
    RequestBodyLimit:    5 * 1024 * 1024,
    Env:                 "production",
})

// Admin middleware
adminCheck := func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Header.Get("NVX-User-Type") != "admin" {
            w.WriteHeader(http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}

mux := http.NewServeMux()

// Routes
mux.Handle("/public", mgr.PublicChain(chainCfg)(handler))
mux.Handle("/auth", mgr.AuthChain(chainCfg)(handler))
mux.Handle("/admin", mgr.AdminChain(chainCfg, adminCheck)(handler))

http.ListenAndServe(":8080", mux)
```

## 🔑 Key Features

### 1. Middleware Chains
- **GlobalChain**: Recoverer → Logger → RealIP → Headers → Security → Compress → MaxBodySize → CORS
- **PublicChain**: GlobalChain + Device Validation
- **AuthChain**: GlobalChain + JWT Validation + Rate Limiting
- **AdminChain**: AuthChain + Custom Admin Check

### 2. Header Validation
- Common headers (all requests)
- Auth headers (authenticated requests)
- Public headers (device validation)
- Signature headers (RSA validation)

### 3. Signature Validation
Uses RSA signature for request authentication:
- Auth: Sign(PrivateKey, [RequestID, MerchantKey, Token, UserID])
- Public: Sign(PublicKey, [RequestID, MerchantKey, UserAgent, DeviceID, Platform, MAC, MessageSig])

### 4. Audit Logging
Logs complete request/response data:
- Method, URL, Status
- Headers (request + response)
- Body (request + response)
- Latency, IP, User info
- Transaction ID tracking

### 5. Chi Integration
Seamless integration with Chi middleware:
- Request ID generation
- Real IP extraction
- Gzip compression
- Rate limiting
- Timeout handling

## 🛠️ Customization

### Custom Log Store
```go
type MyStore struct{}

func (m *MyStore) Save(entry model.AuditLog) error {
    // Your custom logic
    return nil
}

mgr := mw.New(mw.Config{
    LogStore: &MyStore{},
    // ...
})
```

### Custom Context Injector
```go
mgr := mw.New(mw.Config{
    ContextInjector: func(r *http.Request) *http.Request {
        ctx := r.Context()
        ctx = context.WithValue(ctx, "custom-key", "custom-value")
        return r.WithContext(ctx)
    },
    // ...
})
```

### Custom Middleware
```go
func CustomMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Your custom logic
        next.ServeHTTP(w, r)
    })
}

handler := mw.ApplyMiddleware(
    yourHandler,
    CustomMiddleware,
    mgr.EnsureAuth,
    mgr.Logger,
)
```

## 📊 Dependencies

Required:
- `github.com/go-chi/chi/v5` - Router and middleware utilities
- `github.com/rs/zerolog` - Structured logging

Your internal dependencies:
- `github.com/Jkenyut/nvx-go-helper/activity` - Context utilities
- `github.com/Jkenyut/nvx-go-helper/cryptoutil` - Crypto (RSA signature)
- `github.com/Jkenyut/nvx-go-helper/format` - Formatting utilities
- `github.com/Jkenyut/nvx-go-helper/response` - Response helpers

## 🎯 Next Steps

1. **Install dependencies**
   ```bash
   go mod tidy
   ```

2. **Run examples**
   ```bash
   cd examples/basic
   go run main.go
   ```

3. **Read documentation**
   - README.md - Complete usage guide
   - CONTRIBUTING.md - How to contribute
   - CHANGELOG.md - Version history

4. **Customize for your needs**
   - Implement custom LogStore
   - Add custom middleware
   - Configure for production

## 💡 Tips

- Use `DefaultChainConfig()` for development
- Customize `ChainConfig` for production
- Implement database LogStore for production
- Add custom context injector if needed
- Use `envProd()` to check environment
- Enable Chi Profiler only in development
- Set appropriate timeout and body limits
- Configure trusted proxies correctly

## 🐛 Troubleshooting

**Panic not recovered?**
- Ensure Recoverer is the outermost middleware
- Check if response was already written

**Signature validation fails?**
- Verify RSA keys are correct
- Check header order matches signature calculation
- Enable dev mode to see expected signature

**Logs not saving?**
- Check LogStore implementation
- Look for panics in goroutine
- Verify async log save error handling

**Headers missing?**
- Check required headers list
- Verify client sends all headers
- Check case sensitivity (use exact header names)

---

Selamat menggunakan NVX Go Middleware! 🚀
