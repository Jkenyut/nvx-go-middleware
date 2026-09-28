import * as crypto from 'crypto';

/**
 * Interface representing the required headers and request payload to sign.
 */
export interface SignaturePayload {
  method: string;
  requestURI: string; // e.g. "/api/v1/users" or "/api/v1/users?page=1"
  requestId: string;
  platform: 'web' | 'mobile' | 'desktop' | 'server' | 'other';
  timestamp: string; // Unix timestamp in seconds (as string)
  contentType?: string;
  body?: string | Buffer | null;
}

/**
 * Checks whether the Content-Type indicates a multipart/form-data body.
 */
export function isMultipart(contentType?: string): boolean {
  const ct = (contentType || '').trim().toLowerCase();
  return ct.startsWith('multipart/');
}

/**
 * Checks whether the Content-Type indicates a binary payload.
 */
export function isBinary(contentType?: string): boolean {
  let ct = (contentType || '').trim().toLowerCase();
  if (!ct) return false;
  const idx = ct.indexOf(';');
  if (idx !== -1) {
    ct = ct.substring(0, idx).trim();
  }
  return (
    ct.startsWith('application/octet-stream') ||
    ct.startsWith('image/') ||
    ct.startsWith('audio/') ||
    ct.startsWith('video/') ||
    ct.startsWith('application/pdf') ||
    ct.startsWith('application/zip') ||
    ct.startsWith('application/gzip') ||
    ct.startsWith('application/x-gzip') ||
    ct.startsWith('application/x-tar') ||
    ct.startsWith('application/wasm')
  );
}

/**
 * Resolves the canonical body token for NVX signature generation:
 * - Multipart -> "UNSIGNED"
 * - Binary    -> "UNSIGNED"
 * - Empty body -> "EMPTY"
 * - Raw body   -> SHA-256 hex string of the body
 */
export function resolveBodyToken(contentType?: string, body?: string | Buffer | null): string {
  if (isMultipart(contentType) || isBinary(contentType)) {
    return 'UNSIGNED';
  }

  if (!body || (typeof body === 'string' && body.length === 0) || (Buffer.isBuffer(body) && body.length === 0)) {
    return 'EMPTY';
  }

  const hash = crypto.createHash('sha256');
  hash.update(body);
  return hash.digest('hex');
}

/**
 * Generates an NVX-compliant HMAC-SHA256 signature for Node.js / TypeScript.
 *
 * The canonical string is built by feeding each part **individually** into the
 * HMAC hasher (not concatenated into a single string). The order mirrors the
 * server-side `requiredSignaturePublicHeaders` config (default: X-Request-Id,
 * X-Platform, X-Timestamp), sandwiched between Method+URI (always first two)
 * and BodyToken (always last).
 *
 * If the server overrides `requiredSignaturePublicHeaders`, mirror that order
 * in the `parts` array below exactly.
 *
 * @param secret  The PublicKeySignature secret configured on the server.
 * @param payload Request details (method, URI, headers, body).
 * @returns       Hex-encoded HMAC-SHA256 signature string.
 */
export function generateClientSignature(secret: string, payload: SignaturePayload): string {
  const method = payload.method.toUpperCase();
  const bodyToken = resolveBodyToken(payload.contentType, payload.body);

  // Canonical parts sequence (default server config: requiredSignaturePublicHeaders):
  // 1. Method (UPPERCASE)                               — always first
  // 2. RequestURI (full path + query string if present) — always second
  // 3. X-Request-Id                                     — requiredSignaturePublicHeaders[0]
  // 4. X-Platform                                       — requiredSignaturePublicHeaders[1]
  // 5. X-Timestamp                                      — requiredSignaturePublicHeaders[2]
  // 6. Body Token ("EMPTY", "UNSIGNED", or SHA-256 hex) — always last
  const parts: string[] = [
    method,
    payload.requestURI,
    payload.requestId,
    payload.platform,
    payload.timestamp,
    bodyToken,
  ];

  const hmac = crypto.createHmac('sha256', secret);
  for (const part of parts) {
    hmac.update(part); // each part fed individually — do NOT pre-concatenate
  }

  return hmac.digest('hex');
}

/**
 * Browser-compatible implementation using the standard Web Crypto API (SubtleCrypto).
 * Works in React, Vue, Next.js, React Native, Vite, Angular, etc.
 */
export async function generateBrowserSignature(
  secret: string,
  payload: SignaturePayload
): Promise<string> {
  const encoder = new TextEncoder();
  const method = payload.method.toUpperCase();

  // 1. Resolve body token
  let bodyToken = 'EMPTY';
  if (isMultipart(payload.contentType) || isBinary(payload.contentType)) {
    bodyToken = 'UNSIGNED';
  } else if (payload.body && (typeof payload.body === 'string' ? payload.body.length > 0 : payload.body.byteLength > 0)) {
    const rawData = typeof payload.body === 'string' ? encoder.encode(payload.body) : payload.body;
    const bodyHashBuffer = await crypto.subtle.digest('SHA-256', rawData);
    bodyToken = Array.from(new Uint8Array(bodyHashBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // 2. Prepare canonical parts (same order as generateClientSignature)
  const parts = [
    method,
    payload.requestURI,
    payload.requestId,
    payload.platform,
    payload.timestamp,
    bodyToken,
  ];

  // 3. Import HMAC key
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // Concatenate parts sequentially exactly as Go's hmac.Write does
  const totalLength = parts.reduce((acc, p) => acc + encoder.encode(p).length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    const bytes = encoder.encode(part);
    combined.set(bytes, offset);
    offset += bytes.length;
  }

  const signatureBuffer = await crypto.subtle.sign('HMAC', key, combined);
  return Array.from(new Uint8Array(signatureBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ---------------------------------------------------------------------------
// Demo / local verification
// Run with:  npx ts-node signature_example.ts
//        or: tsc signature_example.ts && node signature_example.js
// ---------------------------------------------------------------------------

function main(): void {
  const secretKey  = 'my-public-signature-key';
  const method     = 'POST';
  const requestURI = '/api/v1/users';
  const body       = '{"name":"John Doe","email":"john@example.com"}';
  const bodyBuffer = Buffer.from(body, 'utf8');

  const requestId  = crypto.randomUUID();
  const platform: SignaturePayload['platform'] = 'web'; // mobile | web | desktop | server | other
  const timestamp  = String(Math.floor(Date.now() / 1000));
  const bodyToken  = resolveBodyToken('application/json', bodyBuffer);

  const payload: SignaturePayload = {
    method,
    requestURI,
    requestId,
    platform,
    timestamp,
    contentType: 'application/json',
    body: bodyBuffer,
  };

  const signature = generateClientSignature(secretKey, payload);

  // Headers to attach to the outgoing request
  // (Notice: X-App-Id is NO LONGER required)
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent':   'TS-Client/1.0',
    'X-Request-Id': requestId,
    'X-Platform':   platform,
    'X-Timestamp':  timestamp,
    'X-Signature':  signature,
  };

  console.log('Canonical parts:');
  console.log(`  Method:       ${method.toUpperCase()}`);
  console.log(`  RequestURI:   ${requestURI}`);
  console.log(`  X-Request-Id: ${requestId}`);
  console.log(`  X-Platform:   ${platform}`);
  console.log(`  X-Timestamp:  ${timestamp}`);
  console.log(`  Body token:   ${bodyToken}`);
  console.log('');
  console.log(`Generated NVX Signature: ${signature}`);
  console.log('Headers to attach:');
  for (const [k, v] of Object.entries(headers)) {
    console.log(`  ${k}: ${v}`);
  }
}

main();
