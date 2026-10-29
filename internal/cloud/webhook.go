package cloud

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/riccivr/bugrouter/internal/httpx"
)

// WebhookNotifier dispatches audit event notifications to an HTTP webhook endpoint.
type WebhookNotifier struct {
	httpClient *httpx.Client
	webhookURL string
	secret     string
}

// NewWebhookNotifier initializes a webhook notifier with SSRF protection and HMAC signing.
func NewWebhookNotifier(client *httpx.Client, webhookURL string, secret string) *WebhookNotifier {
	if client == nil {
		client = httpx.NewClient(0)
	}
	if webhookURL == "" {
		webhookURL = os.Getenv("BUGROUTER_WEBHOOK_URL")
	}
	if secret == "" {
		secret = os.Getenv("BUGROUTER_WEBHOOK_SECRET")
	}
	return &WebhookNotifier{
		httpClient: client,
		webhookURL: webhookURL,
		secret:     secret,
	}
}

// Notify delivers the audit event to the configured webhook endpoint.
func (n *WebhookNotifier) Notify(ctx context.Context, ev AuditEvent) error {
	if n == nil || n.webhookURL == "" {
		return nil
	}

	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal webhook event: %w", err)
	}

	headers := make(map[string]string)
	if n.secret != "" {
		mac := hmac.New(sha256.New, []byte(n.secret))
		mac.Write(payload)
		sig := hex.EncodeToString(mac.Sum(nil))
		headers["X-Bugrouter-Signature"] = "sha256=" + sig
	}

	notifyCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if _, err := n.httpClient.PostBytes(notifyCtx, n.webhookURL, "application/json", payload, headers); err != nil {
		return fmt.Errorf("dispatch webhook to %s: %w", n.webhookURL, err)
	}
	return nil
}
