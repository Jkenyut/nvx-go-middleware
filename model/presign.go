// Package model provides data structures for the middleware.
package model

// PresignRequest represents the data required to generate a pre-signed signature.
// It includes details about the request to be signed.
type PresignRequest struct {
	// Method is the HTTP method of the request to sign.
	Method string `json:"method" validate:"required"`
	// URI is the URI path of the request to sign.
	URI string `json:"uri" validate:"required"`
	// Body is the request body to sign (or a representation of it).
	Body string `json:"body" validate:"required"`
}

// PresignResponse represents the response containing the generated signature.
type PresignResponse struct {
	// Signature is the generated cryptographic signature.
	Signature string `json:"signature"`
}
