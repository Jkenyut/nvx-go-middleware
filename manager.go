package middleware

import (
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Jkenyut/nvx-go-middleware/constants"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/diode"
)

var initZerologGlobalOnce sync.Once

// Manager holds the middleware configuration and provides middleware methods.
// It is the central entry point for creating and managing middleware chains.
type Manager struct {
	cfg          Config
	logCloser    io.Closer
	trustedCIDRs []*net.IPNet
}

// NewWithError creates a new Middleware Manager, returning an error instead of panicking
// if the configuration is invalid. Prefer this over New for production use.
func NewWithError(cfg *Config) (*Manager, error) {
	// Validate required fields BEFORE applying defaults that might mask missing values.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	closer := applyDefaults(cfg)

	var cidrs []*net.IPNet
	for _, proxy := range cfg.Security.TrustedProxies {
		if _, ipNet, err := net.ParseCIDR(proxy); err == nil {
			cidrs = append(cidrs, ipNet)
		}
	}

	return &Manager{cfg: *cfg, logCloser: closer, trustedCIDRs: cidrs}, nil
}

// applyDefaults fills in all missing Config fields with safe defaults.
// It returns an io.Closer if it created any resources that need to be closed.
func applyDefaults(cfg *Config) io.Closer {
	var logCloser io.Closer

	if cfg.Logger == nil {
		env := cfg.Core.Env // defaults to "development" if empty

		var writer io.Writer
		isProd := env == "production" || env == "prod"

		if isProd {
			// JSON output for log aggregation systems
			writer = os.Stdout
		} else {
			// Pretty, colored output for local development and staging
			writer = zerolog.ConsoleWriter{
				Out:     os.Stderr,
				NoColor: false,
			}
		}

		// Initialize global format settings only once to avoid concurrent write races.
		initZerologGlobalOnce.Do(func() {
			zerolog.TimeFieldFormat = time.RFC3339
		})

		level := zerolog.DebugLevel
		if isProd {
			level = zerolog.InfoLevel
		}
		if levelStr := os.Getenv("LOG_LEVEL"); levelStr != "" {
			if parsed, err := zerolog.ParseLevel(levelStr); err == nil {
				level = parsed
			}
		}

		wr := diode.NewWriter(writer, 1000, 10*time.Millisecond, func(_ int) {})
		logCloser = wr
		logContext := zerolog.New(wr).
			Level(level).
			With().
			Timestamp().
			Str("service", cfg.Core.ServiceName)

		// Caller is expensive. Only enable it in non-production environments.
		if !isProd {
			logContext = logContext.Caller()
		}

		log := logContext.Logger()
		cfg.Logger = NewZerologLogger(&log)
	}

	if cfg.LogStore == nil {
		cfg.LogStore = &ConsoleStore{logger: cfg.Logger}
	}

	if cfg.Limits.RequestTimeout == 0 {
		cfg.Limits.RequestTimeout = constants.RequestTimeout
	}
	if cfg.Limits.RequestBodyLimitSize == 0 {
		cfg.Limits.RequestBodyLimitSize = constants.RequestBodyLimitSize
	}
	if cfg.Limits.RequestBodyNonFileLimitSize == 0 {
		cfg.Limits.RequestBodyNonFileLimitSize = constants.RequestBodyNonFileLimitSize
	}
	if cfg.Logging.ResponseBodyLogLimitSize == 0 {
		cfg.Logging.ResponseBodyLogLimitSize = constants.ResponseBodyLogLimitSize
	}
	if cfg.Core.ServiceName == "" {
		cfg.Core.ServiceName = "unknown-service"
	}
	if cfg.Core.Env == "" {
		cfg.Core.Env = "development"
	}

	if len(cfg.Headers.RequiredPublicAuthHeaders) == 0 {
		cfg.Headers.RequiredPublicAuthHeaders = constants.RequiredPublicAuthHeaders
	}
	if len(cfg.Headers.RequiredPublicHeaders) == 0 {
		cfg.Headers.RequiredPublicHeaders = constants.RequiredPublicHeaders
	}
	if len(cfg.Headers.RequiredInternalHeaders) == 0 {
		cfg.Headers.RequiredInternalHeaders = constants.RequiredInternalHeaders
	}
	if len(cfg.Headers.RequiredPublicAPIKeyHeaders) == 0 {
		cfg.Headers.RequiredPublicAPIKeyHeaders = constants.RequiredPublicAPIKeyHeaders
	}
	if len(cfg.Headers.RequiredSignaturePublicHeaders) == 0 {
		cfg.Headers.RequiredSignaturePublicHeaders = constants.RequiredSignaturePublicHeaders
	}
	if len(cfg.Headers.RequiredSignatureInternalHeaders) == 0 {
		cfg.Headers.RequiredSignatureInternalHeaders = constants.RequiredSignatureInternalHeaders
	}
	if len(cfg.Security.TrustedProxies) == 0 {
		cfg.Security.TrustedProxies = []string{}
	}
	if len(cfg.Security.AllowedOrigins) == 0 {
		cfg.Security.AllowedOrigins = []string{"*"}
	}
	if len(cfg.Security.AllowedContentTypes) == 0 {
		cfg.Security.AllowedContentTypes = []string{"application/json", "multipart/form-data"}
	}
	if len(cfg.Security.AllowedHeaders) == 0 {
		cfg.Security.AllowedHeaders = uniqueStrings(
			[]string{"Accept", "Authorization", "Content-Type"},
			cfg.Headers.RequiredPublicAuthHeaders,
			cfg.Headers.RequiredPublicHeaders,
			cfg.Headers.RequiredInternalHeaders,
			cfg.Headers.RequiredPublicAPIKeyHeaders,
		)
	}
	if cfg.Headers.Keys.RequestID == "" {
		cfg.Headers.Keys.RequestID = constants.HeaderRequestID
	}
	if cfg.Headers.Keys.TransactionID == "" {
		cfg.Headers.Keys.TransactionID = constants.HeaderTransactionID
	}
	if cfg.Headers.Keys.IP == "" {
		cfg.Headers.Keys.IP = constants.HeaderIP
	}
	if cfg.Headers.Keys.IPOrigin == "" {
		cfg.Headers.Keys.IPOrigin = constants.HeaderIPOrigin
	}
	if cfg.Headers.Keys.UserID == "" {
		cfg.Headers.Keys.UserID = constants.HeaderUserID
	}
	if cfg.Headers.Keys.APIKey == "" {
		cfg.Headers.Keys.APIKey = constants.HeaderAPIKey
	}
	if cfg.Headers.Keys.AuthType == "" {
		cfg.Headers.Keys.AuthType = constants.HeaderAuthType
	}
	if len(cfg.Security.HeadersToRemove) == 0 {
		cfg.Security.HeadersToRemove = []string{}
	}
	if cfg.Security.SignatureTimestampExpired == 0 {
		cfg.Security.SignatureTimestampExpired = constants.TimestampExpired
	}

	if len(cfg.Logging.LogHeaders) == 0 {
		cfg.Logging.LogHeaders = []string{
			cfg.Headers.Keys.RequestID,
			cfg.Headers.Keys.TransactionID,
			cfg.Headers.Keys.IP,
			cfg.Headers.Keys.IPOrigin,
			cfg.Headers.Keys.UserID,
		}
	}

	if len(cfg.Logging.MaskKeywords) == 0 {
		cfg.Logging.MaskKeywords = []string{
			// Authentication & Base Secrets
			"password", "password_cbo", "passphrase", "secret", "client_secret", "client_secret_encrypted",
			"token", "access_token", "refresh_token", "id_token", "jwt",
			"apikey", "api_key", "x-api-key", "client_id", "authorization",

			// Session & OTP
			"session_id", "session_token", "auth_code", "verification_code", "otp",

			// PIN & Pass Numbers
			"pin", "mpin", "transaction_pin", "encrypted_pin_number",
			"pass_number", "pass_number_cbo", "encrypted_pass_number", "encrypted_pass_number_cbo",
			"pass_number_of_account", "encrypted_pass_number_of_account",

			// Signatures & Hashes
			"hash", "checksum", "signature", "signature_hash", "private_key", "tls_key", "certificate_key",

			// Accounts & Cards
			"account_number_encrypted", "account_number_cbo", "account_number_encrypted_cbo",
			"card_number", "card_number_cbo", "encrypted_card_number", "encrypted_card_number_cbo",
			"credit_card_number", "credit_card_number_cbo", "encrypted_credit_card_number", "encrypted_credit_card_number_cbo",
			"cvv", "cvc", "cvv2", "cvc2",

			// PII & Identification
			"nik", "ktp", "ssn", "national_id", "id_card_number", "npwp", "tax_id",
			"mother_maiden_name", "dob", "date_of_birth",
			"phone", "phone_number", "mobile_number", "email", "email_address",

			// General Encrypted Data
			"encrypted_data",
		}
	}

	return logCloser
}

// Config returns a copy of the manager's configuration.
func (m *Manager) Config() Config {
	return m.cfg
}

// Close cleans up any resources created by the Manager (e.g. background logger).
// Call this during graceful shutdown to prevent log loss.
func (m *Manager) Close() error {
	if m.logCloser != nil {
		return m.logCloser.Close()
	}
	return nil
}

func (m *Manager) envProd() bool {
	return m.cfg.Core.Env == "prod" || m.cfg.Core.Env == "production"
}

func uniqueStrings(items ...[]string) []string {
	totalLen := 0
	for _, list := range items {
		totalLen += len(list)
	}
	seen := make(map[string]struct{}, totalLen)
	out := make([]string, 0, totalLen)
	for _, list := range items {
		for _, v := range list {
			if _, ok := seen[v]; !ok {
				seen[v] = struct{}{}
				out = append(out, v)
			}
		}
	}
	return out
}

// SetHeaderAuthType sets the Auth-Type header to identify the authentication context.
func (m *Manager) SetHeaderAuthType(next http.Handler, authType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(m.cfg.Headers.Keys.AuthType, authType)
		next.ServeHTTP(w, r)
	})
}

// addLogHeaders dynamically adds headers to the log context based on the LogHeaders config.
func (m *Manager) addLogHeaders(event LogEvent, r *http.Request) LogEvent {
	for _, h := range m.cfg.Logging.LogHeaders {
		if val := r.Header.Get(h); val != "" {
			event = event.Str(h, val)
		}
	}
	return event
}
