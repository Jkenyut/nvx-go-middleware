package constants

// Header constants
// Header constants define the standard headers used across the NVX middleware.
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
	HeaderUserAgent     = "User-Agent"
	HeaderXHashBody     = "NVX-Hash-Body"
	HeaderAuthType      = "NVX-Auth-Type"
	HeaderRateKey       = "NVX-Rate-Key"
	HeaderAppID         = "NVX-App-ID"
	AuthTypePublic      = "public"
	AuthTypePublicAuth  = "public_auth"
	AuthTypeInternal    = "internal"
)

// Error messages
// Error messages for common middleware failures.
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
	ErrMsgInvalidRequest         = "Invalid request"
	ErrMsgSignatureInvalid       = "Signature invalid"
)

// Configuration defaults and limits.
const (
	RequestBodyLimitSize        = 2 * 1024 * 1024 * 1024 // 2 GB
	RequestBodyNonFileLimitSize = 3 * 1024 * 1024        // 3 MB
	ResponseBodyLogLimitSize    = 5 * 1024 * 1024        // 5 MB

	// DefaultCompressionLevel is the default gzip compression level
	DefaultCompressionLevel = 5
	// DefaultThrottleLimit is the default concurrent request limit
	DefaultThrottleLimit = 100
	// MaxHeaderSize is the maximum size for header values
	MaxHeaderSize    = 8192
	TimestampExpired = 600 // seconds
)

// Required headers for different request types
var (
	// RequiredPublicHeaders are headers required for public requests
	RequiredPublicHeaders = []string{
		HeaderRequestID,
		HeaderAppID,
		HeaderPlatform,
		HeaderUserAgent,
		HeaderXHashBody,
		HeaderTimestamp,
		HeaderSignature,
	}

	// RequiredPublicAuthHeaders are headers required for authenticated public requests
	RequiredPublicAuthHeaders = []string{
		HeaderRequestID,
		HeaderAppID,
		HeaderPlatform,
		HeaderToken,
		HeaderTimestamp,
		HeaderSignature,
	}

	// RequiredPublicAPIKeyHeaders are headers required for authenticated public requests
	RequiredPublicAPIKeyHeaders = []string{
		HeaderRequestID,
		HeaderAppID,
		HeaderPlatform,
		HeaderAPIKey,
		HeaderTimestamp,
		HeaderSignature,
	}

	// RequiredInternalHeaders are headers required for internal requests
	RequiredInternalHeaders = []string{
		HeaderRequestID,
		HeaderPlatform,
		HeaderTimestamp,
		HeaderSignature,
	}

	// RequiredSignatureHeadersPublicAuth are headers required for signature validation for public authenticated requests
	RequiredSignatureHeadersPublicAuth = []string{
		HeaderToken,
		HeaderAPIKey,
		HeaderRequestID,
		HeaderAppID,
		HeaderPlatform,
		HeaderUserAgent,
		HeaderTimestamp,
	}

	// RequiredSignatureHeadersPublic are headers required for signature validation for public requests
	RequiredSignatureHeadersPublic = []string{
		HeaderRequestID,
		HeaderAppID,
		HeaderPlatform,
		HeaderUserAgent,
		HeaderTimestamp,
	}

	// RequiredSignatureHeadersInternal are headers required for signature validation for internal requests
	RequiredSignatureHeadersInternal = []string{
		HeaderRequestID,
		HeaderPlatform,
		HeaderTimestamp,
		HeaderSignature,
	}
)

// Valid platforms
// CheckPlatform defines the list of valid client platforms.
var CheckPlatform = []string{
	"android",
	"ios",
	"web",
	"desktop",
	"internal",
}

// Default security headers
// SecurityHeaders defines the default security headers applied to responses.
var SecurityHeaders = map[string]string{
	"X-Content-Type-Options":    "nosniff",
	"X-Frame-Options":           "DENY",
	"X-XSS-Protection":          "1; mode=block",
	"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	"Content-Security-Policy":   "default-src 'self'",
}
