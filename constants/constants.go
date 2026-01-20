package constants

var (
	// RequiredCommonHeaders are headers required for all requests (Public & Private)
	RequiredCommonHeaders = []string{
		"NVX-Signature",
		"NVX-IP",
		"NVX-Request-ID",
		"NVX-Merchant-ID",
		"NVX-Datetime",
	}

	// RequiredAuthHeaders are headers required for authenticated requests
	RequiredAuthHeaders = []string{
		"NVX-Token",
	}

	// SecurityHeaders map defines the security headers to be set
	SecurityHeaders = map[string]string{
		"X-XSS-Protection":        "1; mode=block",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"Content-Security-Policy": "default-src 'self'",
	}
)

const (
	ErrMsgMissingHeaders   = "missing required headers"
	ErrMsgMethodNotAllowed = "method not allowed"
)
