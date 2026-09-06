package middleware

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/Jkenyut/nvx-go-helper/activity"
)

// ConfigCore holds the configuration for the middleware manager.
// It includes core settings, logging configuration, security parameters, and header requirements.
// ConfigCore holds core settings for the middleware.
type ConfigCore struct {
	Env             string `yaml:"env" default:"development"`
	ServiceName     string `yaml:"serviceName" default:"unknown-service"`
	EnableTelemetry bool   `yaml:"enableTelemetry" default:"false"`
}

// ConfigLimits holds timeout and limit configurations.
type ConfigLimits struct {
	RequestTimeout              int   `yaml:"requestTimeout" default:"30"`                   // seconds
	RequestBodyLimitSize        int64 `yaml:"requestBodyLimitSize" default:"2147483648"`     // 2GB
	RequestBodyNonFileLimitSize int64 `yaml:"requestBodyNonFileLimitSize" default:"3145728"` // 3MB
}

// ConfigLogging holds logging configurations.
type ConfigLogging struct {
	LogRequestBodies         bool     `yaml:"logRequestBodies" default:"false"`
	LogResponseBodies        bool     `yaml:"logResponseBodies" default:"false"`
	ResponseBodyLogLimitSize int64    `yaml:"responseBodyLogLimitSize" default:"5242880"` // 5MB
	MaskKeywords             []string `yaml:"maskKeywords" default:"[]"`
	LogHeaders               []string `yaml:"logHeaders" default:"[\"X-Request-Id\", \"X-Transaction-Id\", \"X-Forwarded-For\", \"X-Ip-Origin\", \"X-User-Id\"]"`
}

// ConfigSecurity holds security-related configurations.
type ConfigSecurity struct {
	PublicKeySignature        string   `yaml:"publicKeySignature"`
	PrivateKeySignature       string   `yaml:"privateKeySignature"`
	TrustedProxies            []string `yaml:"trustedProxies" default:"[]"`
	AllowedOrigins            []string `yaml:"allowedOrigins" default:"[]"`
	AllowedContentTypes       []string `yaml:"allowedContentTypes" default:"[]"`
	AllowedHeaders            []string `yaml:"allowedHeaders" default:"[]"`
	HeadersToRemove           []string `yaml:"headersToRemove" default:"[]"`
	SignatureTimestampExpired int64    `yaml:"signatureTimestampExpired" default:"600"`
}

// HeaderKeys defines the names of headers to be extracted into the context.
type HeaderKeys struct {
	RequestID     string `yaml:"requestID" default:"X-Request-Id"`
	TransactionID string `yaml:"transactionID" default:"X-Transaction-Id"`
	IP            string `yaml:"ip" default:"X-Forwarded-For"`
	IPOrigin      string `yaml:"ipOrigin" default:"X-Ip-Origin"`
	UserID        string `yaml:"userID" default:"X-User-Id"`
	APIKey        string `yaml:"apiKey" default:"X-Api-Key"`
	AuthType      string `yaml:"authType" default:"X-Auth-Type"`
}

// ConfigHeaders holds configuration for required headers.
type ConfigHeaders struct {
	RequiredPublicAuthHeaders        []string   `yaml:"requiredPublicAuthHeaders" default:"[]"`
	RequiredPublicHeaders            []string   `yaml:"requiredPublicHeaders" default:"[]"`
	RequiredInternalHeaders          []string   `yaml:"requiredInternalHeaders" default:"[]"`
	RequiredPublicAPIKeyHeaders      []string   `yaml:"requiredPublicAPIKeyHeaders" default:"[]"`
	RequiredSignaturePublicHeaders   []string   `yaml:"requiredSignaturePublicHeaders" default:"[]"`
	RequiredSignatureInternalHeaders []string   `yaml:"requiredSignatureInternalHeaders" default:"[]"`
	Keys                             HeaderKeys `yaml:"keys"`
}

// Config holds the configuration for the middleware manager.
// It includes core settings, logging configuration, security parameters, and header requirements.
type Config struct {
	Core     ConfigCore     `yaml:"core"`
	Limits   ConfigLimits   `yaml:"limits"`
	Logging  ConfigLogging  `yaml:"logging"`
	Security ConfigSecurity `yaml:"security"`
	Headers  ConfigHeaders  `yaml:"headers"`

	// Interfaces / Unmarshallable
	LogStore        LogStore                            `yaml:"-"`
	Logger          *slog.Logger                        `yaml:"-"`
	ContextInjector func(r *http.Request) *http.Request `yaml:"-"`
}

// Validate checks that required Config fields are present.
func (c *Config) Validate() error {
	if c.Security.PublicKeySignature == "" || c.Security.PrivateKeySignature == "" {
		return ErrMissingKeys
	}
	return nil
}

// ErrMissingKeys is returned when PublicKeySignature or PrivateKeySignature are empty.
var ErrMissingKeys = errors.New("PublicKeySignature and PrivateKeySignature are required")

// WithActivityContext injects standard NVX context values from request headers.
// Exported so protocol-specific adapters (WebSocket, gRPC) can reuse it.
func WithActivityContext(r *http.Request, keys *HeaderKeys) *http.Request {
	if keys == nil {
		return r
	}
	h := r.Header
	ctx := activity.WithActivity(r.Context(), activity.Activity{
		TransactionID: h.Get(keys.TransactionID),
		RequestID:     h.Get(keys.RequestID),
		UserID:        h.Get(keys.UserID),
		UserIP:        h.Get(keys.IP),
		UserIPOrigin:  h.Get(keys.IPOrigin),
	})
	return r.WithContext(ctx)
}
