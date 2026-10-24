# nvx-go-middleware

[![Go Reference](https://pkg.go.dev/badge/github.com/Jkenyut/nvx-go-middleware.svg)](https://pkg.go.dev/github.com/Jkenyut/nvx-go-middleware)
[![Go Report Card](https://goreportcard.com/badge/github.com/Jkenyut/nvx-go-middleware)](https://goreportcard.com/report/github.com/Jkenyut/nvx-go-middleware)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Coverage Status](https://img.shields.io/badge/coverage-88%25-brightgreen.svg)](#8-verification-testing-and-health-check)

The `nvx-go-middleware` package provides server middleware for Go microservices.
It supports HTTP, gRPC, and WebSocket transports.
The library executes fast rejection of invalid requests before audit logging.
This architecture saves CPU cycles, memory allocations, and storage operations.

---

## 1. System Architecture and Data Flows

The system architecture connects edge proxies, security middleware layers, application handlers, and telemetry sinks.

### 1.1 System Topology and Component Architecture

```mermaid
flowchart TD
    subgraph INBOUND["Inbound Client Traffic"]
        Client["HTTP Client or Web Browser"]
        Mobile["Mobile Native Application"]
        S2S["Cluster Microservice (S2S)"]
    end

    subgraph EDGE["Network Edge Layer"]
        Proxy["Reverse Proxy or Cloudflare CDN"]
    end

    subgraph PIPELINE["nvx-go-middleware Execution Engine"]
        direction TB
        subgraph OUTER["Outer Pipeline (Fast Rejection)"]
            TrustProxy["1. TrustProxy IP Resolver"]
            OTel["2. OpenTelemetry Tracing and Metrics"]
            Timeout["3. Request Timeout Guard"]
            Throttle["4. Backlog Request Throttle"]
            AuthGuard["5. Security Headers and HMAC Check"]
            RateLimit["6. Rate Limiter (httprate)"]
        end

        subgraph INNER["Inner Pipeline (Audited Execution)"]
            BodyLimit["7. Body Size and Media Type Guard"]
            Sanitize["8. Strip Slashes and Header Cleaner"]
            Compress["9. Response Compressor"]
            LogRecorder["10. Response Body Buffer Recorder"]
        end

        subgraph LOGGING["Audit Logging Layer"]
            Logger["Structured Logger Middleware"]
        end
    end

    subgraph APPLICATION["Core Application Domain"]
        Handler["Route Handler Logic"]
    end

    subgraph SINKS["Telemetry and Storage Backends"]
        LogStore["Audit Storage (PostgreSQL / ClickHouse)"]
        ConsoleOut["Standard Output (Zerolog Diode)"]
        OTelCollector["OpenTelemetry Collector (:4317 gRPC)"]
    end

    Client --> Proxy
    Mobile --> Proxy
    S2S --> Proxy

    Proxy -->|"Forward request"| TrustProxy
    TrustProxy --> OTel
    OTel --> Timeout
    Timeout --> Throttle
    Throttle --> AuthGuard
    AuthGuard --> RateLimit

    RateLimit -->|"Pass authorized request"| BodyLimit
    BodyLimit --> Sanitize
    Sanitize --> Compress
    Compress --> LogRecorder
    LogRecorder --> Logger
    Logger --> Handler

    Logger -.->|"Save audit record"| LogStore
    Logger -.->|"Write console events"| ConsoleOut
    OTel -.->|"Send spans and metrics"| OTelCollector
```

The outer pipeline checks request authenticity before logging runs.
The engine drops invalid requests at the outer layer.
This behavior prevents audit storage pollution during denial of service spikes.

---

### 1.2 Core Transaction Workflow

```mermaid
sequenceDiagram
    autonumber
    actor User as Client Application
    participant Proxy as Reverse Proxy
    participant Auth as EnsurePublicAuth
    participant Rate as RateLimit
    participant Log as Logger
    participant App as Handler
    participant Store as LogStore

    User->>Proxy: Send HTTP Request with Token and HMAC
    Proxy->>Auth: Forward Request with Proxy Headers
    Auth->>Auth: Check Required Headers and Timestamp
    alt Missing Headers or Expired Timestamp
        Auth-->>User: Return HTTP 400 Bad Request
    else Valid Headers
        Auth->>Auth: Calculate HMAC and Compare Signature
        alt Signature Mismatch
            Auth-->>User: Return HTTP 401 Unauthorized
        else Valid Signature
            Auth->>Rate: Forward Authenticated Request
            Rate->>Rate: Calculate Rate Key from Session or Token
            alt Request Quota Exceeded
                Rate-->>User: Return HTTP 429 Too Many Requests
            else Quota Available
                Rate->>Log: Forward Allowed Request
                Log->>App: Invoke Application Handler
                App-->>Log: Return Response Payload
                Log->>Store: Save Audit Log Record
                Log-->>User: Return HTTP 200 OK Response
            end
        end
    end
```

The client sends authentication tokens and cryptographic signatures in request headers.
The proxy resolver identifies the original client address.
The authentication guard rejects malformed requests immediately.
The rate limiter calculates quota limits with session keys.
The logging module records complete audit records after application execution.

---

## 2. Data Schema and Lifecycle Operations

The middleware structures audit log entries and presigned signature payloads.

### 2.1 Data Entity Relationship Model

```mermaid
erDiagram
    AUDIT_LOG {
        string id PK "Unique identifier (UUIDv7)"
        string service_name "Microservice identifier"
        string method "HTTP verb or protocol command"
        string full_url "Reconstructed target URL"
        int status_code "HTTP response status"
        int64 latency_ms "Execution latency in milliseconds"
        string ip "Resolved client address"
        string ip_origin "Connecting proxy address"
        string request_id "Request tracking ID"
        string correlation_id "Distributed trace correlation ID"
        json_raw request_headers "Masked HTTP request headers"
        json_raw response_headers "Masked HTTP response headers"
        any request_body "Masked request payload"
        any response_body "Masked response payload"
        int64 created_by "Authenticated user identifier"
        datetime created_at "UTC timestamp"
        string protocol "Transport name (HTTP, gRPC, WS)"
        string user_agent "Client user agent header"
        string error_message "Error message or panic summary"
    }

    PRESIGN_REQUEST {
        string method "Target HTTP method"
        string uri "Target path and query"
        string body "Payload string or hash token"
    }

    PRESIGN_RESPONSE {
        string signature "Calculated HMAC signature"
    }

    CONFIG_SECURITY {
        string public_key "Public HMAC secret key"
        string private_key "Private internal secret key"
        string_slice trusted_proxies "Trusted CIDR list"
        string_slice allowed_origins "Permitted CORS origins"
    }

    CONFIG_SECURITY ||--o{ AUDIT_LOG : "governs"
    PRESIGN_REQUEST ||--|| PRESIGN_RESPONSE : "generates"
```

The audit log structure captures transport, security, and timing metadata.
Sensitive fields undergo keyword masking before JSON serialization.

---

### 2.2 Request Lifecycle State Machine

```mermaid
stateDiagram-v2
    [*] --> InboundRequest: Connection Received

    state InboundRequest {
        [*] --> CheckProxy
        CheckProxy --> ResolveClientIP: Remote Address Trusted
        CheckProxy --> KeepRemoteIP: Remote Address Untrusted
    }

    InboundRequest --> SecurityPipeline: Forward Request

    state SecurityPipeline {
        [*] --> CheckHeaders
        CheckHeaders --> Drop400: Header Missing or Invalid
        CheckHeaders --> CheckSignature: Headers Valid
        CheckSignature --> Drop401: Signature Mismatch
        CheckSignature --> CheckRateLimit: Signature Matches
        CheckRateLimit --> Drop429: Quota Limit Exceeded
        CheckRateLimit --> PassedSecurity: Quota Permitted
    }

    Drop400 --> Terminate: Return JSON 400
    Drop401 --> Terminate: Return JSON 401
    Drop429 --> Terminate: Return JSON 429

    PassedSecurity --> InnerProcessing: Execute Chain

    state InnerProcessing {
        [*] --> CheckBodySize
        CheckBodySize --> Drop413: Body Exceeds Size Limit
        CheckBodySize --> RecordResponse: Limit Permitted
        RecordResponse --> RunHandler: Invoke Application
        RunHandler --> FinalizeLog: Handler Completes
    }

    Drop413 --> Terminate: Return JSON 413

    FinalizeLog --> PersistAudit: Save Record to Store
    PersistAudit --> RespondClient: Send Payload
    RespondClient --> Terminate
    Terminate --> [*]
```

The state machine enforces ordered security checkpoints.
Failed checkpoints terminate requests with standard JSON error envelopes.
Passed requests reach application handlers and persist structured audit logs.

---

## 3. Prerequisites and Tooling

Install the verified tools listed in the table below:

| Requirement | Supported Version | Functional Role |
| :--- | :--- | :--- |
| Go Toolchain | 1.24+ / 1.26+ | Compiles the middleware module and executes test suites. |
| OpenTelemetry Collector | 0.95.0+ | Receives distributed traces and server metric points. |
| Docker Engine | 26.0+ | Hosts local test containers and infrastructure. |
| Docker Compose | v2.26+ | Runs multi-container dependency environments. |
| GolangCI-Lint | v1.60+ | Executes static code analysis and lint gates. |

---

## 4. Directory Structure

The repository maintains modular separation between transports, chains, and storage backends:

```text
.
├── .github/                # Stores GitHub Actions continuous integration workflows.
│   └── workflows/
│       └── ci.yml          # Runs build, test, and race detection checks.
├── constants/              # Declares shared constants.
│   └── constants.go        # Defines headers, error messages, and defaults.
├── docs/                   # Stores technical reference documents.
│   └── ARCHITECTURE.md     # Documents pipeline mechanics and sequence diagrams.
├── examples/               # Contains runnable integration programs.
│   ├── advanced/           # Demonstrates complete Chi server configuration.
│   ├── basic/              # Demonstrates lightweight standard library routing.
│   ├── client_signature/   # Shows signature generation in TypeScript.
│   └── grpc_server/        # Shows gRPC server interceptor integration.
├── model/                  # Declares shared data schemas.
│   ├── audit_log.go        # Defines the AuditLog data struct.
│   └── presign.go          # Defines presigned request and response models.
├── chain.go                # Implements pre-built middleware chain profiles.
├── chi.go                  # Implements Chi adapters and rate limiters.
├── config.go               # Defines configuration structures and validators.
├── CONTRIBUTING.md         # Explains branch models and contribution rules.
├── go.mod                  # Declares dependencies and Go version.
├── go.sum                  # Contains dependency checksum records.
├── graphql.go              # Implements GraphQL depth and operation middleware.
├── grpc.go                 # Implements gRPC unary and stream interceptors.
├── LICENSE                 # Contains the Apache 2.0 software license.
├── logger.go               # Declares logging interfaces and Zerolog adapter.
├── Makefile                # Declares development build and test targets.
├── manager.go              # Implements the Manager struct and constructors.
├── metrics.go              # Implements OpenTelemetry HTTP server metrics.
├── middleware.go           # Implements core HTTP security and audit handlers.
├── middleware_test.go      # Validates HTTP middleware execution pipelines.
├── options.go              # Declares functional options for configurations.
├── options_test.go         # Validates option builders and configuration merging.
├── README.md               # Documents system architecture and instructions.
├── response_writer.go      # Implements pooled response body recording.
├── store.go                # Implements LogStore and multi-store broadcasting.
├── store_test.go           # Validates storage backends and concurrent persistence.
└── ws.go                   # Implements WebSocket upgrade security checks.
```

---

## 5. Configuration Parameters

Configure the middleware manager with functional options or configuration structs:

| Configuration Key | Type | Default Value | Description (ASD-STE100) |
| :--- | :--- | :--- | :--- |
| `core.env` | string | `"development"` | Sets the runtime environment name. |
| `core.serviceName` | string | `"unknown-service"` | Sets the service identifier for tracing. |
| `core.enableTelemetry` | boolean | `false` | Enables OpenTelemetry traces and metrics. |
| `security.publicKeySignature` | string | `""` | Sets the public HMAC secret key. |
| `security.privateKeySignature` | string | `""` | Sets the private internal secret key. |
| `security.trustedProxies` | string slice | `[]` | Sets trusted proxy IPs and CIDR blocks. |
| `security.allowedOrigins` | string slice | `["*"]` | Sets permitted origins for CORS checks. |
| `security.allowedContentTypes` | string slice | `["application/json", ...]` | Sets accepted HTTP request media types. |
| `security.signatureTimestampExpiredMs` | integer | `600000` | Sets permitted clock drift in milliseconds. |
| `limits.requestTimeoutMs` | integer | `60000` | Sets request context cancellation timeouts. |
| `limits.requestBodyLimitSize` | integer | `2147483648` (2 GB) | Sets maximum file upload limits. |
| `limits.requestBodyNonFileLimitSize` | integer | `3145728` (3 MB) | Sets maximum non-file request limits. |
| `logging.logRequestBodies` | boolean | `false` | Enables request payload logging. |
| `logging.logResponseBodies` | boolean | `false` | Enables response payload logging. |
| `logging.responseBodyLogLimitSize` | integer | `5242880` (5 MB) | Sets maximum logged response bytes. |
| `logging.logStoreTimeoutMs` | integer | `5000` | Sets the audit persistence timeout. |

---

## 6. Installation and Execution Procedure

Follow these procedural steps to install, configure, and execute the service.

### Step 1: Install Package Dependency

Run the Go module command in your terminal:

```bash
go get github.com/Jkenyut/nvx-go-middleware
```

### Step 2: Initialize Manager with Options

Create the manager instance in your application entry point:

```go
package main

import (
	"log"
	"net/http"

	"github.com/Jkenyut/nvx-go-middleware"
	"github.com/go-chi/chi/v5"
)

func main() {
	// Initialize the middleware manager using functional options
	mgr, err := middleware.New(
		middleware.WithServiceName("order-service"),
		middleware.WithEnv("production"),
		middleware.WithTelemetry(true),
		middleware.WithSecurityKeys("public-secret-key", "private-secret-key"),
		middleware.WithTrustedProxies("10.0.0.0/8", "172.16.0.0/12"),
		middleware.WithAllowedOrigins("https://app.example.com"),
	)
	if err != nil {
		log.Fatalf("failed to initialize middleware: %v", err)
	}
	defer mgr.Close()

	r := chi.NewRouter()

	// Apply public route chain with device checks and IP rate limits
	r.Use(mgr.PublicChain())

	r.Get("/products", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"id":"prod-1","name":"Item"}]`))
	})

	log.Println("Server listening on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}
```

---

## 7. API and Operational Interface

The table summarizes primary middleware functions and pre-built chains:

| Function Interface | Operational Area | Functional Role (ASD-STE100) |
| :--- | :--- | :--- |
| `middleware.New(opts...)` | Manager Lifecycle | Starts the manager with functional options. |
| `middleware.NewWithError(cfg)` | Manager Lifecycle | Starts the manager from a configuration struct. |
| `mgr.PublicChain(opts...)` | Route Chain | Creates a chain for unauthenticated routes. |
| `mgr.PublicAuthChain(opts...)` | Route Chain | Creates a chain for authenticated user routes. |
| `mgr.PublicAPIKeyChain(opts...)` | Route Chain | Creates a chain for external API key routes. |
| `mgr.InternalChain(opts...)` | Route Chain | Creates a chain for service-to-service routes. |
| `mgr.PreSignChain(opts...)` | Route Chain | Creates a chain for request presigning endpoints. |
| `mgr.WebhookChain(opts...)` | Route Chain | Creates a chain for high-volume webhook ingestion. |
| `mgr.GraphQLChain(opts...)` | GraphQL Adapter | Applies depth checks and extracts operation names. |
| `mgr.WebSocketChain(opts...)` | WebSocket Adapter | Enforces pre-upgrade origin and authentication checks. |
| `mgr.NewGRPCServer(opts...)` | gRPC Factory | Creates a server with traces, metrics, and recovery. |
| `mgr.ServerMetrics()` | Observability | Records latency histograms and request counters. |
| `mgr.DefaultCORS()` | Security | Handles CORS preflight and origin verification. |
| `mgr.MaxBodySize(opts...)` | Security | Rejects request payloads that exceed limits. |
| `middleware.MultiLogStore(s...)` | Persistence | Broadcasts audit logs concurrently across multiple stores. |

### Advanced Transport Integrations

#### gRPC Service Factory
```go
// Creates a gRPC server configured with trace handlers and interceptors
grpcServer := mgr.NewGRPCServer()
```

#### GraphQL Endpoint Adapter
```go
// Applies query depth limits and logs GraphQL operations
router.Handle("/graphql", mgr.GraphQLChain(
	middleware.WithGraphQLMaxDepth(10),
)(graphqlHandler))
```

#### WebSocket Upgrade Adapter
```go
// Checks origin headers and credentials before upgrading connection
router.Handle("/ws", mgr.WebSocketChain(
	middleware.WithWSAuthenticator(func(r *http.Request) bool {
		return r.URL.Query().Get("token") != ""
	}),
)(wsHandler))
```

---

## 8. Verification, Testing and Health Check

Execute verified commands to check correctness, memory safety, and code style.

### Step 1: Run Unit Tests with Race Detection

Execute the unit test suite:

```bash
go test -count=1 -race ./...
```

### Step 2: Run Micro-Benchmarks

Measure execution speed and memory allocations:

```bash
go test -run=^$ -bench=. -benchmem ./...
```

### Step 3: Run Static Code Analysis

Execute static analysis checks:

```bash
go vet ./...
```

---

## 9. Troubleshooting and Fault Isolation

Review the table below to resolve common configuration and runtime errors:

| Observed Symptom | Probable Root Cause | Corrective Action (ASD-STE100) |
| :--- | :--- | :--- |
| `missing required headers` | Client request omitted mandatory tracking headers. | Send `X-Request-Id`, `X-Platform`, and `X-Timestamp`. |
| `invalid request signature` | HMAC signature mismatch or clock drift exceeded. | Check the secret key and synchronize the device clock. |
| `request payload too large` | Request body exceeded configured size limits. | Increase `RequestBodyLimitSize` or reduce payload size. |
| `cross-origin websocket forbidden` | WebSocket handshake sent an unlisted origin header. | Add the client origin to `AllowedOrigins`. |
| Audit logs show missing response body. | Response body size exceeded logging byte limits. | Increase `ResponseBodyLogLimitSize` in configuration. |
| High Prometheus memory consumption. | Unparameterized URL paths entered metric labels. | Inject route patterns using `WithRoutePattern`. |
| Buffer dropped warning in console logs. | High traffic saturated the diode ring buffer. | Increase diode ring capacity or use async stores. |

---

## 10. License

This project is licensed under the Apache License 2.0. Refer to [LICENSE](LICENSE) for full legal terms.
