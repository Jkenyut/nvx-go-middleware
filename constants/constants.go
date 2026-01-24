package constants

var (
	// RequiredCommonHeaders are headers required for all requests (Public & Private)
	RequiredCommonHeaders = []string{
		"NVX-IP",
		"NVX-Request-ID",
		"NVX-Merchant-ID",
		"NVX-Datetime",
		"NVX-Signature",
	}

	// RequiredAuthHeaders are headers required for authenticated requests
	RequiredAuthHeaders = []string{
		"NVX-Token",
	}

	// RequiredPublicAuthHeaders are headers required for public authenticated requests
	RequiredPublicAuthHeaders = []string{
		"NVX-Token",
		"NVX-User-Agent",
		"NVX-Device-ID",
		"NVX-Platform",
		"NVX-Mac-Address",
		"NVX-Message",
	}

	// RequiredSignatureAuthHeaders are headers required for signature authenticated requests
	RequiredSignatureAuthHeaders = []string{
		"NVX-Token",
		"NVX-IP",
		"NVX-Request-ID",
		"NVX-Merchant-ID",
		"NVX-Datetime",
	}

	// RequiredSignatureMessagePublicHeaders are headers required for signature message public authenticated requests
	RequiredSignatureMessagePublicHeaders = []string{
		"NVX-User-Agent",
		"NVX-Device-ID",
		"NVX-Platform",
		"NVX-Mac-Address",
	}

	// RequiredSignaturePublicHeaders are headers required for signature public authenticated requests
	RequiredSignaturePublicHeaders = []string{
		"NVX-Token",
		"NVX-IP",
		"NVX-Request-ID",
		"NVX-Merchant-ID",
		"NVX-Datetime",
		"NVX-Message",
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

	HeaderGetSignature     = "NVX-Signature"
	HeaderGetToken         = "NVX-Token"
	HeaderGetPlatform      = "NVX-Platform"
	HeaderGetMacAddress    = "NVX-Mac-Address"
	HeaderGetUserAgent     = "NVX-User-Agent"
	HeaderGetDeviceID      = "NVX-Device-ID"
	HeaderGetMessage       = "NVX-Message"
	HeaderGetMerchantID    = "NVX-Merchant-ID"
	HeaderGetDatetime      = "NVX-Datetime"
	HeaderGetIP            = "NVX-IP"
	HeaderGetRequestID     = "NVX-Request-ID"
	HeaderGetTransactionID = "NVX-Transaction-ID"
)

const (
	ErrMsgMethodNotAllowed = "method not allowed"
	ErrMsgInvalidPlatform  = "invalid platform"
	ErrMsgMissingHeaders   = "missing public auth headers"
	ErrMsgInvalidToken     = "invalid or expired token"
	ErrMsgInvalidSignature = "invalid signature"
)
