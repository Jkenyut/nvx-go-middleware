# Client-Side Request Signing Guide

This guide explains how frontend web applications (React, Next.js, Vue), mobile apps (Flutter, React Native, iOS, Android), and backend API clients generate cryptographic HMAC-SHA256 signatures required by the NVX Go Middleware without requiring an insecure server-side presign endpoint (which prevents Chosen-Plaintext Signing Oracle vulnerabilities).

---

## 1. Why Generate Signatures on the Client?

Exposing a server endpoint (like `/api/presign`) that signs arbitrary requests using the server's key creates a **Signing Oracle**: an attacker can ask the server to sign any request (e.g. `POST /admin/delete-database`), completely defeating signature verification.

Instead, the client (or BFF / API Gateway) generates the signature directly following the deterministic canonical algorithm.

---

## 2. Canonical Signature Structure

The server validates public requests using the following sequence of values:

| Step | Component | Description | Example |
| :--- | :--- | :--- | :--- |
| 1 | **HTTP Method** | Uppercase method name | `POST`, `GET`, `PUT`, `DELETE` |
| 2 | **Request URI** | Full path and query string | `/api/v1/users?page=1` |
| 3 | **X-Request-Id** | Unique UUID v4 or v7 | `0191a2b3-c4d5-7e8f-9a0b-1c2d3e4f5a6b` |
| 4 | **X-Platform** | Allowed platform identifier (`mobile`, `web`, `desktop`, `server`, `other`) | `web` |
| 5 | **X-Timestamp** | Unix timestamp in seconds (string) | `1757053600` |
| 6 | **Body Token** | Canonical body representation (see below) | `EMPTY`, `UNSIGNED`, or SHA-256 hex |

> [!IMPORTANT]
> Steps 3–5 above reflect the **server default configuration**. The exact headers included — and their order — are controlled by the server-side `requiredSignaturePublicHeaders` config field (see [Section 5](#5-server-configuration--header-order)). If the server has a customised header list, the client **must** mirror that exact sequence to produce a matching signature. When in doubt, confirm the active config with your backend team.

> [!NOTE]
> `X-App-Id` is **no longer required** in NVX Go Middleware and has been removed from required headers and rate limiting.

### Body Token Calculation Rules
1. **Multipart Requests (`multipart/form-data`)**:
   - Return constant string `"UNSIGNED"`.
2. **Binary Requests (`application/octet-stream`, `image/*`, `audio/*`, `video/*`, `application/pdf`, `application/zip`, `application/gzip`, `application/wasm`, etc.)**:
   - Return constant string `"UNSIGNED"`.
3. **Empty Requests (e.g., `GET` or bodyless `POST`)**:
   - Return constant string `"EMPTY"`.
4. **JSON / Text / Other Content**:
   - Compute `sha256(rawBodyBytes)` and encode as a lowercase hexadecimal string.

---

## 3. HMAC-SHA256 Computation

Initialize an HMAC-SHA256 hasher with the shared secret key (`PublicKeySignature`). Feed each canonical part **sequentially** (not concatenated into a single string) into the hasher:

```
hmac = HMAC_SHA256(secretKey)
hmac.update(Method)        ← always first
hmac.update(RequestURI)    ← always second
hmac.update(X-Request-Id)  ← from requiredSignaturePublicHeaders[0]
hmac.update(X-Platform)    ← from requiredSignaturePublicHeaders[1]
hmac.update(X-Timestamp)   ← from requiredSignaturePublicHeaders[2]
hmac.update(BodyToken)     ← always last

signature = hex(hmac.digest())
```

> [!WARNING]
> Each part is fed into the HMAC hasher **individually** via successive `Write`/`update` calls — **do not** concatenate parts into a single string before hashing. Concatenation produces a different digest and will fail signature validation.

Attach the resulting hex string to the `X-Signature` request header.

---

## 4. Code Examples

- **Node.js & Web Crypto (Browser)**: See [`signature_example.ts`](./signature_example.ts)
- **Go Client**: See [`signature_example.go`](./signature_example.go)
- **Postman Pre-request Script**: See [`postman/pre-request.js`](./postman/pre-request.js) — auto-injects all NVX headers per request

---

## 5. Server Configuration & Header Order

The NVX middleware server controls which headers are included in the canonical signature — and in what order — via the `requiredSignaturePublicHeaders` configuration field.

### Default Configuration (YAML)

```yaml
headers:
  requiredSignaturePublicHeaders:
    - X-Request-Id   # canonical part [0]
    - X-Platform     # canonical part [1]
    - X-Timestamp    # canonical part [2]
```

This default is applied automatically when `requiredSignaturePublicHeaders` is empty or omitted.

### Canonical String Layout (default)

```
HMAC_SHA256(secret,
  METHOD +            ← always position 0
  REQUEST_URI +       ← always position 1
  X-Request-Id +      ← position 2  (requiredSignaturePublicHeaders[0])
  X-Platform +        ← position 3  (requiredSignaturePublicHeaders[1])
  X-Timestamp +       ← position 4  (requiredSignaturePublicHeaders[2])
  BODY_TOKEN          ← always last
)
```

### Customising Headers

If your deployment requires additional or differently-ordered headers (e.g., a tenant ID or API version header), update the server config **and** the client signing code together:

```yaml
# Example: add X-Tenant-Id between X-Request-Id and X-Platform
headers:
  requiredSignaturePublicHeaders:
    - X-Request-Id
    - X-Tenant-Id   # ← new header added
    - X-Platform
    - X-Timestamp
```

The client must then include `X-Tenant-Id` in its canonical parts in the same position:

```
hmac.update(X-Request-Id)
hmac.update(X-Tenant-Id)   ← must match server config order
hmac.update(X-Platform)
hmac.update(X-Timestamp)
```

> [!CAUTION]
> **Order is critical.** Adding a header at the wrong position produces a completely different HMAC digest and will fail validation. Always align client and server configs simultaneously, treating them as a single atomic change.

---

## 6. Verification & Debugging

### Quick local test (Go)

Run the included example directly to print the generated signature and headers:

```bash
go run ./examples/client_signature/signature_example.go
```

### Quick local test (TypeScript / Node.js)

```bash
npx ts-node ./examples/client_signature/signature_example.ts
# or compile first:
tsc signature_example.ts && node signature_example.js
```

### Diagnosing a signature mismatch

If the server returns `401 invalid request signature`, check the following in order:

| # | Check | Common mistake |
|---|-------|---------------|
| 1 | **Header order** | Client uses different order than `requiredSignaturePublicHeaders` |
| 2 | **`requestURI` value** | Using `/path` instead of `/path?query=string` (must include query string) |
| 3 | **Method casing** | Sending `post` instead of `POST` (must be uppercase) |
| 4 | **Body token** | Hashing a parsed/re-serialised body instead of the raw bytes sent on the wire |
| 5 | **Timestamp drift** | Timestamp is more than 600 seconds from server time (server rejects stale requests) |
| 6 | **Secret key** | Client using `PrivateKeySignature` instead of `PublicKeySignature` |
| 7 | **Encoding** | Parts concatenated as a single string instead of fed individually into the HMAC hasher |
