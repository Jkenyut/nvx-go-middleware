package model

// validator 10 = required
type PresignRequest struct {
	Method      string `json:"method" validate:"required"`
	Uri         string `json:"uri" validate:"required"`
	ContentType string `json:"content_type" validate:"required"`
	Body        string `json:"body" validate:"required"`
}

type PresignResponse struct {
	Signature string `json:"signature"`
}
