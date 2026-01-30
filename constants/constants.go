package constants

// Header constants
const (
	HeaderTransactionID = "NVX-Transaction-ID"
	HeaderRequestID     = "NVX-Request-ID"
	HeaderAPIKey        = "NVX-API-Key"
	HeaderUserID        = "NVX-User-ID"
	HeaderIP            = "NVX-IP"
	HeaderUserType      = "NVX-User-Type"
	HeaderToken         = "NVX-Token"
	HeaderTimestamp     = "NVX-Timestamp"
	HeaderSignature     = "NVX-Signature"
	HeaderPlatform      = "NVX-Platform"
	HeaderDeviceID      = "NVX-Device-ID"
	HeaderMacAddress    = "NVX-Mac-Address"
	HeaderUserAgent     = "NVX-User-Agent"
	HeaderMessage       = "NVX-Message"
	HeaderXHashBody     = "NVX-Hash-Body"
)

// Error messages
const (
	ErrMsgMissingHeaders         = "Missing required headers"
	ErrMsgInvalidIP              = "Invalid IP address format"
	ErrMsgInvalidToken           = "Invalid or missing authentication token"
	ErrMsgInvalidSignature       = "Invalid request signature"
	ErrMsgInvalidPlatform        = "Invalid platform"
	ErrMsgMethodNotAllowed       = "Method not allowed"
	ErrMsgPayloadTooLarge        = "Request payload too large"
	ErrMsgRequestTimeout         = "Request timeout"
	ErrMsgInvalidTimestamp       = "Invalid timestamp format"
	ErrMsgUnsupportedContentType = "Unsupported content type"
)

// Required headers for different request types
var (
	RequiredCommonHeaders = []string{
		HeaderRequestID,
		HeaderAPIKey,
		HeaderPlatform,
		HeaderTimestamp,
		HeaderSignature,
	}

	// RequiredAuthHeaders are headers required for authenticated requests
	RequiredAuthHeaders = []string{
		HeaderToken,
	}

	// RequiredPublicHeaders are headers required for public requests
	RequiredPublicHeaders = []string{
		HeaderXHashBody,
	}

	// RequiredSignatureHeadersAuth are headers required for signature validation for auth requests
	RequiredSignatureHeadersAuth = []string{
		HeaderToken,
		HeaderRequestID,
		HeaderAPIKey,
		HeaderPlatform,
		HeaderTimestamp,
	}

	// RequiredSignatureHeadersPublic are headers required for signature validation for public requests
	RequiredSignatureHeadersPublic = []string{
		HeaderRequestID,
		HeaderAPIKey,
		HeaderPlatform,
		HeaderTimestamp,
	}
)

// Valid platforms
var CheckPlatform = []string{
	"android",
	"ios",
	"web",
	"desktop",
}

// Default security headers
var SecurityHeaders = map[string]string{
	"X-Content-Type-Options":    "nosniff",
	"X-Frame-Options":           "DENY",
	"X-XSS-Protection":          "1; mode=block",
	"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	"Content-Security-Policy":   "default-src 'self'",
}
