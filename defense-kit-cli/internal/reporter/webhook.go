package reporter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const webhookSignatureHeader = "X-Defense-Kit-Signature"

// WebhookAlerter delivers AlertReports to an arbitrary HTTP endpoint, signing
// each request body with HMAC-SHA256 when a secret is configured.
type WebhookAlerter struct {
	url        string
	hmacSecret string
	requireTLS bool
	client     *http.Client
}

// NewWebhookAlerter returns a WebhookAlerter with default http.Client settings.
// If requireTLS is true, Send will return an error for non-HTTPS URLs.
func NewWebhookAlerter(url, hmacSecret string, requireTLS bool) *WebhookAlerter {
	return &WebhookAlerter{
		url:        url,
		hmacSecret: hmacSecret,
		requireTLS: requireTLS,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// NewWebhookAlerterWithClient returns a WebhookAlerter using the supplied
// *http.Client. This is intended for testing with httptest.Server TLS clients.
func NewWebhookAlerterWithClient(url, hmacSecret string, requireTLS bool, client *http.Client) *WebhookAlerter {
	return &WebhookAlerter{
		url:        url,
		hmacSecret: hmacSecret,
		requireTLS: requireTLS,
		client:     client,
	}
}

// Name returns the identifier for this alerter.
func (w *WebhookAlerter) Name() string { return "webhook" }

// Send marshals the AlertReport as JSON, computes an HMAC-SHA256 signature,
// and POSTs to the configured URL with the signature in a custom header.
func (w *WebhookAlerter) Send(ctx context.Context, report AlertReport) error {
	if w.requireTLS && !strings.HasPrefix(w.url, "https") {
		return fmt.Errorf("webhook: requireTLS is enabled but URL is not HTTPS: %s", w.url)
	}

	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("webhook: marshal report: %w", err)
	}

	sig := computeHMAC(body, w.hmacSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webhookSignatureHeader, "sha256="+sig)

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// computeHMAC returns the hex-encoded HMAC-SHA256 of data keyed by secret.
// If secret is empty, it returns the SHA256 of data (unsigned).
func computeHMAC(data []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
