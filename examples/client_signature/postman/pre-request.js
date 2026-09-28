// =============================================================================
// NVX Middleware — Postman Pre-request Script
// =============================================================================
// Paste this into: Collection → Pre-request Script  (applies to all requests)
// OR:              Individual Request → Pre-request Script tab
//
// Required Variables (set in your Environment or Collection Variables):
//   NVX_SECRET    — PublicKeySignature value from the server config
//   NVX_PLATFORM  — (optional) defaults to "server"
//                    Allowed: mobile | web | desktop | server | other
//
// Auto-injected request headers:
//   X-Request-Id, X-Platform, X-Timestamp, X-Signature
//
// Open Postman Console (Cmd+Alt+C / Ctrl+Alt+C) to see canonical debug output.
// =============================================================================

// ---------- helpers ----------------------------------------------------------

function isMultipart(ct) {
    return (ct || '').trim().toLowerCase().startsWith('multipart/');
}

function isBinary(ct) {
    var s = (ct || '').trim().toLowerCase();
    var semi = s.indexOf(';');
    if (semi !== -1) s = s.substring(0, semi).trim();
    return s === 'application/octet-stream' ||
           s.startsWith('image/')     ||
           s.startsWith('audio/')     ||
           s.startsWith('video/')     ||
           s === 'application/pdf'    ||
           s === 'application/zip'    ||
           s === 'application/gzip'   ||
           s === 'application/x-gzip'||
           s === 'application/x-tar' ||
           s === 'application/wasm';
}

// Mirrors server-side ResolveBodyToken()
function resolveBodyToken(contentType, rawBody) {
    if (isMultipart(contentType) || isBinary(contentType)) return 'UNSIGNED';
    if (!rawBody || rawBody.length === 0) return 'EMPTY';
    // CryptoJS is available globally in the Postman sandbox
    return CryptoJS.SHA256(
        CryptoJS.enc.Utf8.parse(rawBody)
    ).toString(CryptoJS.enc.Hex);
}

// UUID v4 generator
function uuidv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

// HMAC-SHA256 over sequentially-fed parts.
// Mirrors Go's per-part hmac.Write() by concatenating WordArrays before
// passing to CryptoJS.HmacSHA256 (byte-level equivalent).
function hmacSHA256(secret, parts) {
    var combined = CryptoJS.enc.Utf8.parse('');
    for (var i = 0; i < parts.length; i++) {
        combined = combined.concat(CryptoJS.enc.Utf8.parse(parts[i]));
    }
    return CryptoJS.HmacSHA256(combined, secret).toString(CryptoJS.enc.Hex);
}

// ---------- collect request context ------------------------------------------

var secret    = pm.collectionVariables.get('NVX_SECRET')
             || pm.environment.get('NVX_SECRET')
             || pm.globals.get('NVX_SECRET')
             || '';

var platform  = pm.collectionVariables.get('NVX_PLATFORM')
             || pm.environment.get('NVX_PLATFORM')
             || 'server';

var requestId = uuidv4();
var timestamp = String(Math.floor(Date.now() / 1000));
var method    = pm.request.method.toUpperCase();

// Build full request URI including query string (mirrors r.RequestURI on server)
var url         = pm.request.url;
var pathParts   = url.path || [];
var path        = '/' + pathParts.join('/');
var qs          = url.getQueryString();
var requestURI  = qs ? (path + '?' + qs) : path;

// Resolve body and Content-Type
var rawBody     = '';
var contentType = (pm.request.headers.get('Content-Type') || '').split(';')[0].trim();

if (pm.request.body) {
    var mode = pm.request.body.mode;
    if (mode === 'raw') {
        rawBody = pm.request.body.raw || '';
    } else if (mode === 'graphql') {
        // GraphQL body is serialised as JSON on the wire
        rawBody     = JSON.stringify(pm.request.body.graphql);
        contentType = 'application/json';
    } else if (mode === 'formdata' || mode === 'urlencoded') {
        contentType = 'multipart/form-data'; // force UNSIGNED
    } else if (mode === 'file') {
        contentType = 'application/octet-stream'; // force UNSIGNED
    }
}

var bodyToken = resolveBodyToken(contentType, rawBody);

// ---------- build canonical parts & sign ------------------------------------
//
// Order MUST match server's requiredSignaturePublicHeaders (default):
//   [X-Request-Id, X-Platform, X-Timestamp]
// sandwiched between Method+URI (always first) and BodyToken (always last).
//
var parts = [
    method,
    requestURI,
    requestId,
    platform,
    timestamp,
    bodyToken
];

var signature = hmacSHA256(secret, parts);

// ---------- inject headers ---------------------------------------------------

pm.request.headers.upsert({ key: 'X-Request-Id', value: requestId });
pm.request.headers.upsert({ key: 'X-Platform',   value: platform });
pm.request.headers.upsert({ key: 'X-Timestamp',  value: timestamp });
pm.request.headers.upsert({ key: 'X-Signature',  value: signature });

// ---------- debug (Postman Console) ------------------------------------------

console.log('[NVX Signature] Canonical parts:');
console.log('  Method      :', method);
console.log('  RequestURI  :', requestURI);
console.log('  X-Request-Id:', requestId);
console.log('  X-Platform  :', platform);
console.log('  X-Timestamp :', timestamp);
console.log('  Body token  :', bodyToken);
console.log('[NVX Signature] X-Signature:', signature);
