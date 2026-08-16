// Package constants provides common constants used throughout the NVX middleware.
package constants

// Header constants
// Header constants define the standard headers used across the NVX middleware.
const (
	HeaderTransactionID  = "Transaction-ID"
	HeaderRequestID      = "Request-ID"
	HeaderAPIKey         = "API-Key"
	HeaderUserID         = "User-ID"
	HeaderIP             = "IP"
	HeaderIPOrigin       = "IP-Origin"
	HeaderToken          = "Token"
	HeaderTimestamp      = "Timestamp"
	HeaderSignature      = "Signature"
	HeaderPlatform       = "Platform"
	HeaderUserAgent      = "User-Agent"
	HeaderAuthType       = "Auth-Type"
	HeaderRateKey        = "Rate-Key"
	HeaderAppID          = "App-ID"
	AuthTypePublic       = "public"
	AuthTypePublicAuth   = "public-auth"
	AuthTypePublicAPIKey = "public-api-key"
	AuthTypeInternal     = "internal"
)

// Error messages
// Error messages for common middleware failures.
const (
	ErrMsgMissingHeaders = "missing required headers"

	ErrMsgInvalidToken     = "invalid or missing authentication token"
	ErrMsgInvalidSignature = "invalid request signature"
	ErrMsgInvalidPlatform  = "invalid platform"
	ErrMsgMethodNotAllowed = "method not allowed"
	ErrMsgPayloadTooLarge  = "request payload too large"

	ErrMsgInvalidTimestamp       = "invalid timestamp format"
	ErrMsgUnsupportedContentType = "unsupported content type"
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
	// DefaultThrottleTimeout is the default concurrent request timeout
	DefaultThrottleTimeout = 30
	// DefaultThrottleBacklog is the default concurrent request backlog
	DefaultThrottleBacklog = 100
	// DefaultRateLimitRequests is the default rate limit requests
	DefaultRateLimitRequests = 100
	// DefaultRateLimitWindow is the default rate limit window
	DefaultRateLimitWindow = 1

	// MaxHeaderSize is the maximum size for header values
	MaxHeaderSize    = 8192
	TimestampExpired = 600 // seconds
	RequestTimeout   = 60  // seconds
)

// Required headers for different request types
var (
	// RequiredPublicHeaders are headers required for public requests
	RequiredPublicHeaders = []string{
		HeaderRequestID,
		HeaderAppID,
		HeaderPlatform,
		HeaderUserAgent,
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

	// RequiredSignatureInternalHeaders are headers required for signature validation for internal requests
	RequiredSignatureInternalHeaders = []string{
		HeaderRequestID,
		HeaderPlatform,
		HeaderTimestamp,
	}

	// RequiredSignaturePublicHeaders are headers required for signature validation for public requests
	RequiredSignaturePublicHeaders = []string{
		HeaderRequestID,
		HeaderAppID,
		HeaderPlatform,
		HeaderTimestamp,
	}
)

// CheckPlatform defines the list of valid client platforms.
var CheckPlatform = []string{
	"mobile",  // andriod, ios, windows
	"web",     // web browser
	"desktop", // desktop computer
	"server",  // server to server (S2S), integration partner (B2B), webhook, or internal microservices.
	"other",   // IoT, Smart TV, Wearable, dll.
}
