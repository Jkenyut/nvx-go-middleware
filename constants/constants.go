package constants

// Header constants
const (
	HeaderTransactionID = "NVX-Transaction-ID"
	HeaderRequestID     = "NVX-Request-ID"
	HeaderMerchantKey   = "NVX-Merchant-Key"
	HeaderUserID        = "NVX-User-ID"
	HeaderIP            = "NVX-IP"
	HeaderUserType      = "NVX-User-Type"
	HeaderToken         = "NVX-Token"
	HeaderSignature     = "NVX-Signature"
	HeaderUserAgent     = "NVX-User-Agent"
	HeaderDeviceID      = "NVX-Device-ID"
	HeaderPlatform      = "NVX-Platform"
	HeaderMacAddress    = "NVX-Mac-Address"
	HeaderDatetime      = "NVX-Datetime"
	HeaderMessage       = "NVX-Message"
)

// Error messages
const (
	ErrMsgMissingHeaders    = "Missing required headers"
	ErrMsgInvalidIP         = "Invalid IP address format"
	ErrMsgInvalidToken      = "Invalid or missing authentication token"
	ErrMsgInvalidSignature  = "Invalid request signature"
	ErrMsgInvalidMacAddress = "Invalid MAC address format"
	ErrMsgInvalidPlatform   = "Invalid platform"
	ErrMsgMethodNotAllowed  = "Method not allowed"
	ErrMsgPayloadTooLarge   = "Request payload too large"
	ErrMsgRequestTimeout    = "Request timeout"
	ErrMsgInvalidDatetime   = "Invalid datetime format"
)

// Required headers for different request types
var (
	RequiredCommonHeaders = []string{
		HeaderRequestID,
		HeaderMerchantKey,
		HeaderDatetime,
		HeaderSignature,
	}

	// RequiredAuthHeaders are headers required for authenticated requests
	RequiredAuthHeaders = []string{
		HeaderToken,
	}

	// RequiredPublicAuthHeaders are headers required for public authenticated requests
	RequiredPublicAuthHeaders = []string{
		HeaderToken,
		HeaderUserAgent,
		HeaderDeviceID,
		HeaderPlatform,
		HeaderMacAddress,
		HeaderMessage,
	}

	// RequiredSignatureAuthHeaders are headers required for signature authenticated requests
	RequiredSignatureAuthHeaders = []string{
		HeaderToken,
		HeaderIP,
		HeaderRequestID,
		HeaderMerchantKey,
		HeaderDatetime,
	}

	// RequiredSignatureMessagePublicHeaders are headers required for signature message public authenticated requests
	RequiredSignatureMessagePublicHeaders = []string{
		HeaderUserAgent,
		HeaderDeviceID,
		HeaderPlatform,
		HeaderMacAddress,
	}

	// RequiredSignaturePublicHeaders are headers required for signature public authenticated requests
	RequiredSignaturePublicHeaders = []string{
		HeaderToken,
		HeaderIP,
		HeaderRequestID,
		HeaderMerchantKey,
		HeaderDatetime,
		HeaderMessage,
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
