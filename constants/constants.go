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

	RequiredPublicAuthHeaders = []string{
		"NVX-User-Agent",
		"NVX-Device-ID",
		"NVX-Platform",
		"NVX-Mac-Address",
		"NVX-Message",
	}

	// Context Keys (Internal)
	CtxUserID = "user_id"
	CtxRole   = "role"

	// Forwarded Headers (External)
	HeaderForwardedUserID = "X-User-ID"
	HeaderForwardedRole   = "X-Role"
)

const (
	ErrMsgMethodNotAllowed = "method not allowed"
	ErrMsgInvalidPlatform  = "invalid platform"
	ErrMsgMissingHeaders   = "missing public auth headers"
	ErrMsgInvalidToken     = "invalid or expired token"
)
