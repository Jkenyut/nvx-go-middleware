package model

// validator 10 = required
// PresignRequest represents the data required to generate a pre-signed signature.
// It includes details about the request to be signed.
type PresignRequest struct {
	// Method is the HTTP method of the request to sign.
	Method string `json:"method" validate:"required"`
	// Uri is the URI path of the request to sign.
	Uri string `json:"uri" validate:"required"`
	// ContentType is the Content-Type header of the request to sign.
	ContentType string `json:"content_type" validate:"required"`
	// Body is the request body to sign (or a representation of it).
	Body string `json:"body" validate:"required"`
}

// PresignResponse represents the response containing the generated signature.
type PresignResponse struct {
	// Signature is the generated cryptographic signature.
	Signature string `json:"signature"`
}
