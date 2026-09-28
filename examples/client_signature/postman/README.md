# NVX Middleware — Postman Integration

This directory contains a ready-to-use **Pre-request Script** that auto-generates and injects NVX HMAC-SHA256 request signatures into every Postman request.

---

## Files

| File | Purpose |
|------|---------|
| [`pre-request.js`](./pre-request.js) | Pre-request script — paste into Collection or Request |

---

## Setup

### 1. Create Collection Variables

In your Postman Collection → **Variables** tab, add:

| Variable | Initial Value | Description |
|----------|--------------|-------------|
| `NVX_SECRET` | `my-public-signature-key` | `PublicKeySignature` from server config |
| `NVX_PLATFORM` | `server` | `mobile` \| `web` \| `desktop` \| `server` \| `other` |

> **Tip**: Use a Postman **Environment** instead of Collection Variables if you need different secrets per environment (dev / staging / prod).

### 2. Paste the Pre-request Script

Copy the entire contents of [`pre-request.js`](./pre-request.js) and paste it into:

- **Collection → Pre-request Script** tab — applies to *all* requests in the collection, or
- **Individual Request → Pre-request Script** tab — applies only to that request.

### 3. Send any request

Postman will automatically:
1. Generate a fresh `X-Request-Id` (UUID v4) for each send.
2. Set `X-Timestamp` to the current Unix time in seconds.
3. Compute the body token from the raw request body.
4. Compute the HMAC-SHA256 signature.
5. Inject `X-Request-Id`, `X-Platform`, `X-Timestamp`, and `X-Signature` headers.

You do **not** need to set these headers manually on individual requests.

---

## Environment Setup Example

```
Postman Environment: NVX Dev
├── NVX_SECRET   = super-secret-dev-key
└── NVX_PLATFORM = web

Postman Environment: NVX Prod
├── NVX_SECRET   = super-secret-prod-key
└── NVX_PLATFORM = server
```

---

## Debugging

Open the **Postman Console** (`Cmd+Alt+C` / `Ctrl+Alt+C`) to see the canonical parts printed before each request:

```
[NVX Signature] Canonical parts:
  Method      : POST
  RequestURI  : /api/v1/users
  X-Request-Id: 0191a2b3-c4d5-7e8f-9a0b-1c2d3e4f5a6b
  X-Platform  : web
  X-Timestamp : 1757053600
  Body token  : a9f3d2e1c4b5...  (SHA-256 of raw body)
[NVX Signature] X-Signature: de201a4a167d...
```

If the server returns `401 invalid request signature`, compare these values against the server-side debug log and see the [troubleshooting table](../README.md#6-verification--debugging) in the main README.

---

## How It Works

The script uses **CryptoJS** which is available globally in the Postman sandbox (no external imports needed).

```
CryptoJS.HmacSHA256(concatenated_wordarray, secret)
  where concatenated_wordarray = Method + RequestURI + X-Request-Id + X-Platform + X-Timestamp + BodyToken
```

This is byte-level equivalent to Go's sequential `hmac.Write()` calls because CryptoJS WordArray concatenation operates on the raw byte stream before the HMAC is finalised.

> If the server customises `requiredSignaturePublicHeaders`, update the `parts` array in the script to match the same order.
