package constants

const (
	// HeaderSignature is the header key for the request signature.
	HeaderSignature = "NVX-Signature"
	// HeaderToken is the header key for the authorization token.
	HeaderToken = "NVX-Token"
	// HeaderPlatform is the header key for the client platform (e.g., ios, android, web).
	HeaderPlatform = "NVX-Platform"
	// HeaderMacAddress is the header key for the client's MAC address.
	HeaderMacAddress = "NVX-Mac-Address"
	// HeaderUserAgent is the header key for the user agent string.
	HeaderUserAgent = "NVX-User-Agent"
	// HeaderDeviceID is the header key for the unique device identifier.
	HeaderDeviceID = "NVX-Device-ID"
	// HeaderMessage is the header key for a cleartext message used in signature verification.
	HeaderMessage = "NVX-Message"
	// HeaderMerchantKey is the header key for the merchant identifier.
	HeaderMerchantKey = "NVX-Merchant-Key"
	// HeaderDatetime is the header key for the request timestamp.
	HeaderDatetime = "NVX-Datetime"
	// HeaderIP is the header key for the client's IP address (internal use).
	HeaderIP = "NVX-IP"
	// HeaderRequestID is the header key for the unique request identifier.
	HeaderRequestID = "NVX-Request-ID"
	// HeaderTransactionID is the header key for the unique transaction identifier.
	HeaderTransactionID = "NVX-Transaction-ID"
	// HeaderUserType is the header key for the type of user.
	HeaderUserType = "NVX-User-Type"
	// HeaderUserID is the header key for the user identifier.
	HeaderUserID = "NVX-User-ID"
)

var (

	// RequiredCommonHeaders are headers required for all requests (Public & Private)
	RequiredCommonHeaders = []string{
		HeaderIP,
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

	// SecurityHeaders map defines the security headers to be set
	SecurityHeaders = map[string]string{
		"X-XSS-Protection":        "1; mode=block",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"Content-Security-Policy": "default-src 'self'",
	}

	CheckPlatform = []string{
		"ios",
		"android",
		"web",
	}
)

const (
	// ErrMsgMethodNotAllowed is the error message for invalid HTTP methods.
	ErrMsgMethodNotAllowed = "method not allowed"
	// ErrMsgInvalidPlatform is the error message for unsupported client platforms.
	ErrMsgInvalidPlatform = "invalid platform"
	// ErrMsgMissingHeaders is the error message when required headers are missing.
	ErrMsgMissingHeaders = "missing public auth headers"
	// ErrMsgInvalidToken is the error message for invalid or expired auth tokens.
	ErrMsgInvalidToken = "invalid or expired token"
	// ErrMsgInvalidSignature is the error message when signature verification fails.
	ErrMsgInvalidSignature = "invalid signature"
	// ErrMsgRequestTimeout is the error message when a request exceeds the timeout limit.
	ErrMsgRequestTimeout = "request timeout"
	// ErrMsgPayloadTooLarge is the error message when the request body exceeds the size limit.
	ErrMsgPayloadTooLarge = "payload too large"
	// ErrMsgInvalidIP is the error message for malformed IP addresses.
	ErrMsgInvalidIP = "invalid ip address"
	// ErrMsgInvalidMacAddress is the error message for malformed MAC addresses.
	ErrMsgInvalidMacAddress = "invalid mac address"
)
