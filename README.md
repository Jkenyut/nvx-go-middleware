# NVX Go Middleware

`nvx-go-middleware` is a comprehensive HTTP middleware library for Go applications, designed to provide essential features such as logging, authentication, security, and request handling utilities.

## Features

- **Audit Logging**: Asynchronously logs detailed request and response information (latency, status, headers, body) to a configurable store (Console or Custom).
- **Authentication**:
    - **EnsureAuth**: Validates JWT tokens and signature headers for protected routes.
    - **EnsurePublicAuth**: Validates public clients (Device ID, Platform, User-Agent) and signatures.
- **Security**:
    - **SecureHeaders**: Adds standard security headers (XSS Protection, Content-Type Options, etc.).
    - **TrustProxy**: Securely handles `X-Forwarded-For` headers based on a configurable list of Trusted Proxies (IPs or CIDRs).
    - **CORS**: Handles Cross-Origin Resource Sharing with configurable allowed origins.
- **Resilience & Performance**:
    - **Gzip**: Transparently compresses responses using Gzip (wraps Logger to ensure logs are readable).
    - **Recoverer**: Recovers from panics and logs stack traces without crashing the server.
    - **Timeout**: Enforces request processing limits.
    - **MaxBodySize**: Limits request body size to prevent DoS attacks.
- **Utilities**:
    - **EnsureCommonHeaders**: Validates headers required for all requests (e.g., Transaction ID, IP).
    - **Context Injection**: Allows injecting custom values into the request context.

## Installation

```bash
go get github.com/Jkenyut/nvx-go-middleware
```

## Usage

### 1. Configuration

Create a `middleware.Config` struct with your settings:

```go
import (
    "time"
    "github.com/Jkenyut/nvx-go-middleware/middleware"
    "github.com/Jkenyut/nvx-go-middleware/constants"
)

cfg := middleware.Config{
    // RSA Keys for Signature Verification
    PublicKeySignature:  "-----BEGIN PUBLIC KEY... (your public key)",
    PrivateKeySignature: "-----BEGIN PRIVATE KEY... (your private key)",

    // CORS Settings
    AllowedOrigins: []string{"https://yourdomain.com", "http://localhost:3000"},

    // Trusted Proxies (Load Balancers/Gateways)
    TrustedProxies: []string{"10.0.0.1", "192.168.1.0/24"},

    // Timeout & Limits
    RequestTimeout:   60 * time.Second,
    RequestBodyLimit: 3 * 1024 * 1024, // 3MB

    // Required Headers
    RequiredCommonHeaders:     constants.RequiredCommonHeaders,
    RequiredAuthHeaders:       constants.RequiredAuthHeaders,
    RequiredPublicAuthHeaders: constants.RequiredPublicAuthHeaders,
    
    // Security Headers
    SecurityHeaders: constants.SecurityHeaders,
    
    // Optional: Custom Logger (zerolog) or LogStore
    // LogStore: myCustomLogStore{},
}
```

### 2. Initialization

Initialize the manager with the configuration:

```go
mw := middleware.New(cfg)
```

### 3. Applying Middleware

You can use the `GlobalChain` for a standard production-ready stack, or apply individual middlewares.

**Using GlobalChain:**

```go
http.Handle("/", mw.GlobalChain(myHandler))
```

**GlobalChain Order:**
`Recoverer` -> `Gzip` -> `Logger` -> `CORS` -> `SecureHeaders` -> `EnsureCommonHeaders` -> `TrustProxy` -> `MaxBodySize` -> `Timeout` -> `Next`

### 4. Protected Routes

For routes requiring authentication (JWT + Signature):

```go
protectedHandler := mw.EnsureAuth(myProtectedHandler)
http.Handle("/secure", protectedHandler)
```

For public routes checking client validity (User-Agent, Device-ID):

```go
publicHandler := mw.EnsurePublicAuth(myPublicHandler)
http.Handle("/public", publicHandler)
```

## Middleware Details

### Logger & Gzip
The `Logger` middleware captures the request and response body. To support Gzip compression without obscuring the logs, the `Gzip` middleware must wrap the `Logger`. The `GlobalChain` handles this automatically.

### TrustProxy
Configuring `TrustedProxies` is **critical** for security if you rely on the `NVX-IP` header (derived from `X-Forwarded-For`).
- If `TrustedProxies` is empty, `X-Forwarded-For` is **ignored** and `RemoteAddr` is used.
- Add your Load Balancer or Gateway IPs/CIDRs to `TrustedProxies` to securely resolve the client IP.

## License

[Add License Here]