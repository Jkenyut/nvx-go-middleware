package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ResolveBodyToken mirrors the server-side ResolveBodyToken algorithm:
// - Multipart bodies -> "UNSIGNED"
// - Empty bodies     -> "EMPTY"
// - All other bodies -> hex-encoded SHA-256 of raw bytes
func ResolveBodyToken(contentType string, body []byte) string {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if strings.HasPrefix(ct, "multipart/") {
		return "UNSIGNED"
	}
	if len(body) == 0 {
		return "EMPTY"
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// GenerateClientSignature generates an HMAC-SHA256 signature matching NVX middleware validation.
func GenerateClientSignature(secret, method, requestURI, requestID, platform, timestamp, bodyToken string) string {
	h := hmac.New(sha256.New, []byte(secret))
	parts := []string{
		strings.ToUpper(method),
		requestURI,
		requestID,
		platform,
		timestamp,
		bodyToken,
	}
	for _, part := range parts {
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func main() {
	secretKey := "my-public-signature-key"
	method := "POST"
	requestURI := "/api/v1/users"
	payload := `{"name":"John Doe","email":"john@example.com"}`
	bodyBytes := []byte(payload)

	requestID := uuid.NewString()
	platform := "web" // mobile, web, desktop, server, other
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	bodyToken := ResolveBodyToken("application/json", bodyBytes)

	signature := GenerateClientSignature(secretKey, method, requestURI, requestID, platform, timestamp, bodyToken)

	req, err := http.NewRequest(method, "http://localhost:8081"+requestURI, bytes.NewReader(bodyBytes))
	if err != nil {
		panic(err)
	}

	// Attach NVX Required Headers (Notice: X-App-Id is NO LONGER required)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Go-Client/1.0")
	req.Header.Set("X-Request-Id", requestID)
	req.Header.Set("X-Platform", platform)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", signature)

	fmt.Printf("Generated NVX Signature: %s\n", signature)
	fmt.Printf("Headers attached:\n")
	for k, v := range req.Header {
		fmt.Printf("  %s: %s\n", k, v[0])
	}
	_ = io.Discard
}
