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

> [!NOTE]
> `X-App-Id` is **no longer required** in NVX Go Middleware and has been removed from required headers and rate limiting.

### Body Token Calculation Rules
1. **Multipart Requests (`multipart/form-data`)**:
   - Return constant string `"UNSIGNED"`.
2. **Empty Requests (e.g., `GET` or bodyless `POST`)**:
   - Return constant string `"EMPTY"`.
3. **JSON / Other Content**:
   - Compute `sha256(rawBodyBytes)` and encode as a lowercase hexadecimal string.

---

## 3. HMAC-SHA256 Computation

Initialize an HMAC-SHA256 hasher with the shared secret key (`PublicKeySignature`). Feed each canonical part sequentially into the hasher:

```
hmac = HMAC_SHA256(secretKey)
hmac.update(Method)
hmac.update(RequestURI)
hmac.update(X-Request-Id)
hmac.update(X-Platform)
hmac.update(X-Timestamp)
hmac.update(BodyToken)

signature = hex(hmac.digest())
```

Attach the resulting hex string to the `X-Signature` request header.

---

## 4. Code Examples

- **Node.js & Web Crypto (Browser)**: See [`signature_example.ts`](./signature_example.ts)
- **Go Client**: See [`signature_example.go`](./signature_example.go)
