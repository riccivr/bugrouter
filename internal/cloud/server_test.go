package cloud

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/version"
)

func postWithHeader(url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return http.DefaultClient.Do(req)
}

type mockSubmitter struct {
	submittedURL string
	err          error
}

func (m *mockSubmitter) Submit(ctx context.Context, draft *adapter.StagedDraft) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.submittedURL, nil
}

func TestServerHealth(t *testing.T) {
	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	srv := NewServer(":0", store, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatalf("GET /api/v1/health failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var res map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if res["status"] != "ok" {
		t.Errorf("status = %q, want ok", res["status"])
	}
	if res["version"] != version.Version {
		t.Errorf("version = %q, want %s", res["version"], version.Version)
	}
}

func TestServerDraftsAndApproval(t *testing.T) {
	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	submitter := &mockSubmitter{
		submittedURL: "https://github.enterprise.corp/org/repo/issues/42",
	}
	srv := NewServer(":0", store, submitter)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Initially empty
	resp, err := http.Get(ts.URL + "/api/v1/drafts")
	if err != nil {
		t.Fatalf("GET /api/v1/drafts failed: %v", err)
	}
	defer resp.Body.Close()

	var drafts []*adapter.StagedDraft
	if err := json.NewDecoder(resp.Body).Decode(&drafts); err != nil {
		t.Fatalf("decode empty drafts list: %v", err)
	}
	if len(drafts) != 0 {
		t.Errorf("expected 0 drafts, got %d", len(drafts))
	}

	// Create and save a draft
	d, err := adapter.BuildDraft(adapter.DraftInput{
		Target: resolver.Target{
			CanonicalName: "auth-svc",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitHub,
				URL:      "https://github.enterprise.corp/org/repo/issues",
			},
		},
		Title:   "Token expired",
		Summary: "Handshake failed",
	})
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}
	if _, err := store.Save(d); err != nil {
		t.Fatalf("Save draft failed: %v", err)
	}

	// List drafts again
	resp2, err := http.Get(ts.URL + "/api/v1/drafts")
	if err != nil {
		t.Fatalf("GET /api/v1/drafts failed: %v", err)
	}
	defer resp2.Body.Close()

	var drafts2 []*adapter.StagedDraft
	if err := json.NewDecoder(resp2.Body).Decode(&drafts2); err != nil {
		t.Fatalf("decode drafts list: %v", err)
	}
	if len(drafts2) != 1 {
		t.Fatalf("expected 1 draft, got %d", len(drafts2))
	}
	if drafts2[0].ID != d.ID {
		t.Errorf("draft ID = %s, want %s", drafts2[0].ID, d.ID)
	}

	// Approve draft
	approveURL := fmt.Sprintf("%s/api/v1/drafts/%s/approve", ts.URL, d.ID)
	respApprove, err := postWithHeader(approveURL, map[string]string{"X-Bugrouter-Request": "1"})
	if err != nil {
		t.Fatalf("POST /approve failed: %v", err)
	}
	defer respApprove.Body.Close()

	if respApprove.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(respApprove.Body)
		if readErr != nil {
			t.Fatalf("POST /approve status = %d, failed to read body: %v", respApprove.StatusCode, readErr)
		}
		t.Fatalf("POST /approve status = %d, body = %s", respApprove.StatusCode, string(body))
	}

	var approveRes map[string]any
	if err := json.NewDecoder(respApprove.Body).Decode(&approveRes); err != nil {
		t.Fatalf("decode approve response: %v", err)
	}
	if approveRes["status"] != "submitted" {
		t.Errorf("status = %v, want submitted", approveRes["status"])
	}
	if approveRes["issue_url"] != submitter.submittedURL {
		t.Errorf("issue_url = %v, want %s", approveRes["issue_url"], submitter.submittedURL)
	}

	// Verify draft status in store is updated
	updatedDraft, err := store.Get(d.ID)
	if err != nil {
		t.Fatalf("Get updated draft failed: %v", err)
	}
	if updatedDraft.Status != "submitted" {
		t.Errorf("draft status in store = %q, want submitted", updatedDraft.Status)
	}
	if updatedDraft.SubmissionURL != submitter.submittedURL {
		t.Errorf("submission URL = %q, want %s", updatedDraft.SubmissionURL, submitter.submittedURL)
	}

	// Discard another draft
	d2, err := adapter.BuildDraft(adapter.DraftInput{
		Target: resolver.Target{CanonicalName: "billing-svc"},
		Title:  "Duplicate issue",
	})
	if err != nil {
		t.Fatalf("BuildDraft d2 failed: %v", err)
	}
	if _, err := store.Save(d2); err != nil {
		t.Fatalf("Save d2 failed: %v", err)
	}

	discardURL := fmt.Sprintf("%s/api/v1/drafts/%s/discard", ts.URL, d2.ID)
	respDiscard, err := postWithHeader(discardURL, map[string]string{"X-Bugrouter-Request": "1"})
	if err != nil {
		t.Fatalf("POST /discard failed: %v", err)
	}
	defer respDiscard.Body.Close()
	if respDiscard.StatusCode != http.StatusOK {
		t.Errorf("POST /discard status = %d, want 200", respDiscard.StatusCode)
	}

	discardedDraft, err := store.Get(d2.ID)
	if err != nil {
		t.Fatalf("Get discarded draft failed: %v", err)
	}
	if discardedDraft.Status != "discarded" {
		t.Errorf("discardedDraft.Status = %q, want discarded", discardedDraft.Status)
	}
}

func TestServerIndexHTML(t *testing.T) {
	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	srv := NewServer(":0", store, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "bugrouter") || !strings.Contains(html, "Cloud Control Plane") {
		t.Errorf("index HTML missing expected title markers: %s", html)
	}
	if !strings.Contains(html, "audit-container") || !strings.Contains(html, "/api/v1/audit") {
		t.Errorf("index HTML missing audit table container or audit fetch endpoint")
	}
}

func TestServerPathTraversalRejected(t *testing.T) {
	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	srv := NewServer(":0", store, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	badIDs := []string{"bad..id", "bad-id!", "bad_id$", "bad%20id"}
	for _, bad := range badIDs {
		resp, err := postWithHeader(ts.URL+"/api/v1/drafts/"+bad+"/approve", map[string]string{"X-Bugrouter-Request": "1"})
		if err != nil {
			t.Fatalf("POST failed for id %q: %v", bad, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for bad id %q, got: %d", bad, resp.StatusCode)
		}
	}
}

func TestServerIndexHTMLDOMXSSGuard(t *testing.T) {
	srv := NewServer(":0", nil, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "startsWith('https://')") || !strings.Contains(html, "escapeHTML(u)") {
		t.Errorf("index HTML missing URL scheme validation or escaping guards")
	}
}

func TestServerIndexHTMLPotentialDuplicates(t *testing.T) {
	srv := NewServer(":0", nil, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "potential_duplicates") || !strings.Contains(html, "Potential Upstream Duplicates") {
		t.Errorf("index HTML missing duplicate rendering logic")
	}
}

func TestServerBearerAuthEnforcement(t *testing.T) {
	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	token := "secure-cloud-token-test-xyz"
	srv := NewServer(":0", store, nil).WithAuthToken(token)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. GET / remains public
	respRoot, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	respRoot.Body.Close()
	if respRoot.StatusCode != http.StatusOK {
		t.Errorf("GET / status = %d, want 200", respRoot.StatusCode)
	}

	// 2. GET /api/v1/health remains public
	respHealth, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	respHealth.Body.Close()
	if respHealth.StatusCode != http.StatusOK {
		t.Errorf("GET /api/v1/health status = %d, want 200", respHealth.StatusCode)
	}

	// 3. GET /api/v1/drafts without token returns 401
	respNoAuth, err := http.Get(ts.URL + "/api/v1/drafts")
	if err != nil {
		t.Fatalf("GET /drafts no auth: %v", err)
	}
	defer respNoAuth.Body.Close()
	if respNoAuth.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/drafts status = %d, want 401", respNoAuth.StatusCode)
	}
	var errBody map[string]string
	if err := json.NewDecoder(respNoAuth.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode 401 body: %v", err)
	}
	if errBody["error"] != "unauthorized" {
		t.Errorf("error body = %v, want unauthorized", errBody)
	}

	// 4. GET /api/v1/audit without token returns 401
	respAuditNoAuth, err := http.Get(ts.URL + "/api/v1/audit")
	if err != nil {
		t.Fatalf("GET /audit no auth: %v", err)
	}
	respAuditNoAuth.Body.Close()
	if respAuditNoAuth.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/audit status = %d, want 401", respAuditNoAuth.StatusCode)
	}

	// 5. GET /api/v1/drafts with invalid token returns 401
	reqBad, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/drafts", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	reqBad.Header.Set("Authorization", "Bearer invalid-wrong-token")
	respBad, err := http.DefaultClient.Do(reqBad)
	if err != nil {
		t.Fatalf("GET /drafts bad token: %v", err)
	}
	respBad.Body.Close()
	if respBad.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/drafts with bad token status = %d, want 401", respBad.StatusCode)
	}

	// 6. GET /api/v1/drafts with valid token returns 200
	reqGood, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/drafts", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	reqGood.Header.Set("Authorization", "Bearer "+token)
	respGood, err := http.DefaultClient.Do(reqGood)
	if err != nil {
		t.Fatalf("GET /drafts good token: %v", err)
	}
	respGood.Body.Close()
	if respGood.StatusCode != http.StatusOK {
		t.Errorf("GET /api/v1/drafts with good token status = %d, want 200", respGood.StatusCode)
	}
}

func TestServerCSRFProtection(t *testing.T) {
	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	d, err := adapter.BuildDraft(adapter.DraftInput{
		Target: resolver.Target{CanonicalName: "csrf-svc"},
		Title:  "CSRF Test",
	})
	if err != nil {
		t.Fatalf("BuildDraft: %v", err)
	}
	if _, err := store.Save(d); err != nil {
		t.Fatalf("Save: %v", err)
	}

	token := "csrf-token-abc"
	srv := NewServer(":0", store, nil).WithAuthToken(token)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	discardURL := fmt.Sprintf("%s/api/v1/drafts/%s/discard", ts.URL, d.ID)

	// 1. Missing both X-Bugrouter-Request and Authorization -> 401 or 403
	respNoHeaders, err := http.Post(discardURL, "application/json", nil)
	if err != nil {
		t.Fatalf("POST without headers: %v", err)
	}
	respNoHeaders.Body.Close()
	if respNoHeaders.StatusCode != http.StatusUnauthorized && respNoHeaders.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 401 or 403", respNoHeaders.StatusCode)
	}

	// 2. Unauthenticated server: POST without X-Bugrouter-Request -> 403
	srvUnauth := NewServer(":0", store, nil).WithAuthToken("")
	tsUnauth := httptest.NewServer(srvUnauth.Handler())
	defer tsUnauth.Close()

	unauthDiscardURL := fmt.Sprintf("%s/api/v1/drafts/%s/discard", tsUnauth.URL, d.ID)
	respUnauthNoCSRF, err := http.Post(unauthDiscardURL, "application/json", nil)
	if err != nil {
		t.Fatalf("POST unauth without CSRF header: %v", err)
	}
	respUnauthNoCSRF.Body.Close()
	if respUnauthNoCSRF.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 Forbidden for missing CSRF guard", respUnauthNoCSRF.StatusCode)
	}

	// 3. Mismatched Origin header -> 403 Forbidden
	reqBadOrigin, err := http.NewRequest(http.MethodPost, unauthDiscardURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	reqBadOrigin.Header.Set("Origin", "https://malicious-attacker.site")
	reqBadOrigin.Header.Set("X-Bugrouter-Request", "1")
	respBadOrigin, err := http.DefaultClient.Do(reqBadOrigin)
	if err != nil {
		t.Fatalf("POST bad origin: %v", err)
	}
	respBadOrigin.Body.Close()
	if respBadOrigin.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 Forbidden for mismatched origin", respBadOrigin.StatusCode)
	}

	// 4. Matching Origin header and X-Bugrouter-Request: 1 -> 200 OK
	u, _ := url.Parse(tsUnauth.URL)
	reqGoodOrigin, err := http.NewRequest(http.MethodPost, unauthDiscardURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	reqGoodOrigin.Header.Set("Origin", "http://"+u.Host)
	reqGoodOrigin.Header.Set("X-Bugrouter-Request", "1")
	respGoodOrigin, err := http.DefaultClient.Do(reqGoodOrigin)
	if err != nil {
		t.Fatalf("POST good origin: %v", err)
	}
	respGoodOrigin.Body.Close()
	if respGoodOrigin.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 OK for valid origin and custom header", respGoodOrigin.StatusCode)
	}

	// 5. Authenticated request with valid Authorization satisfies CSRF guard without X-Bugrouter-Request
	d2, _ := adapter.BuildDraft(adapter.DraftInput{
		Target: resolver.Target{CanonicalName: "auth-csrf-svc"},
		Title:  "Auth CSRF Test",
	})
	if _, err := store.Save(d2); err != nil {
		t.Fatalf("Save d2: %v", err)
	}

	reqBearerOnly, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/v1/drafts/%s/discard", ts.URL, d2.ID), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	reqBearerOnly.Header.Set("Authorization", "Bearer "+token)
	respBearerOnly, err := http.DefaultClient.Do(reqBearerOnly)
	if err != nil {
		t.Fatalf("POST bearer only: %v", err)
	}
	respBearerOnly.Body.Close()
	if respBearerOnly.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 OK when valid Bearer token provided", respBearerOnly.StatusCode)
	}
}

func TestServerAuditLogAndRetrieval(t *testing.T) {
	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	auditFile := filepath.Join(tempDir, "audit.log")
	logger := NewAuditLogger(auditFile)

	srv := NewServer(":0", store, nil).WithAuditLogger(logger)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	d1, err := adapter.BuildDraft(adapter.DraftInput{
		Target:  resolver.Target{CanonicalName: "svc-alpha"},
		Title:   "Approve me",
		Summary: "Summary alpha",
	})
	if err != nil {
		t.Fatalf("BuildDraft d1: %v", err)
	}
	if _, err := store.Save(d1); err != nil {
		t.Fatalf("Save d1: %v", err)
	}

	d2, err := adapter.BuildDraft(adapter.DraftInput{
		Target:  resolver.Target{CanonicalName: "svc-beta"},
		Title:   "Discard me",
		Summary: "Summary beta",
	})
	if err != nil {
		t.Fatalf("BuildDraft d2: %v", err)
	}
	if _, err := store.Save(d2); err != nil {
		t.Fatalf("Save d2: %v", err)
	}

	// 1. Approve d1
	approveURL := fmt.Sprintf("%s/api/v1/drafts/%s/approve", ts.URL, d1.ID)
	respApprove, err := postWithHeader(approveURL, map[string]string{"X-Bugrouter-Request": "1"})
	if err != nil {
		t.Fatalf("approve d1: %v", err)
	}
	respApprove.Body.Close()
	if respApprove.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d, want 200", respApprove.StatusCode)
	}

	// 2. Discard d2
	discardURL := fmt.Sprintf("%s/api/v1/drafts/%s/discard", ts.URL, d2.ID)
	respDiscard, err := postWithHeader(discardURL, map[string]string{"X-Bugrouter-Request": "1"})
	if err != nil {
		t.Fatalf("discard d2: %v", err)
	}
	respDiscard.Body.Close()
	if respDiscard.StatusCode != http.StatusOK {
		t.Fatalf("discard status = %d, want 200", respDiscard.StatusCode)
	}

	// 3. Verify audit log file permissions on disk (0600)
	info, err := os.Stat(auditFile)
	if err != nil {
		t.Fatalf("stat audit log: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("audit log permissions = %04o, want 0600", perm)
	}

	// 4. Retrieve audit log via GET /api/v1/audit
	respAudit, err := http.Get(ts.URL + "/api/v1/audit")
	if err != nil {
		t.Fatalf("GET /api/v1/audit: %v", err)
	}
	defer respAudit.Body.Close()
	if respAudit.StatusCode != http.StatusOK {
		t.Fatalf("audit status = %d, want 200", respAudit.StatusCode)
	}

	var events []AuditEvent
	if err := json.NewDecoder(respAudit.Body).Decode(&events); err != nil {
		t.Fatalf("decode audit events: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 audit events, got %d", len(events))
	}
	// Reverse chronological: newest first (d2 discarded, then d1 approved)
	if events[0].Action != "draft.discarded" || events[0].DraftID != d2.ID {
		t.Errorf("events[0] = %+v, want discarded for d2", events[0])
	}
	if events[1].Action != "draft.approved" || events[1].DraftID != d1.ID {
		t.Errorf("events[1] = %+v, want approved for d1", events[1])
	}
}

func TestServerWebhookNotification(t *testing.T) {
	webhookSecret := "whsec_test_secret_389271"
	var receivedPayloads [][]byte
	var receivedSignatures []string

	tsWebhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusInternalServerError)
			return
		}
		receivedPayloads = append(receivedPayloads, body)
		receivedSignatures = append(receivedSignatures, r.Header.Get("X-Bugrouter-Signature"))
		w.WriteHeader(http.StatusOK)
	}))
	defer tsWebhook.Close()

	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	testClient := httpx.NewTestClient(0)
	notifier := NewWebhookNotifier(testClient, tsWebhook.URL, webhookSecret)

	srv := NewServer(":0", store, nil).WithWebhookNotifier(notifier)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	d, err := adapter.BuildDraft(adapter.DraftInput{
		Target:  resolver.Target{CanonicalName: "webhook-target"},
		Title:   "Webhook Test Draft",
		Summary: "Testing webhook delivery",
	})
	if err != nil {
		t.Fatalf("BuildDraft: %v", err)
	}
	if _, err := store.Save(d); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Trigger approval
	approveURL := fmt.Sprintf("%s/api/v1/drafts/%s/approve", ts.URL, d.ID)
	resp, err := postWithHeader(approveURL, map[string]string{"X-Bugrouter-Request": "1"})
	if err != nil {
		t.Fatalf("approve POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d, want 200", resp.StatusCode)
	}

	if len(receivedPayloads) != 1 {
		t.Fatalf("expected 1 webhook received, got %d", len(receivedPayloads))
	}

	// Verify HMAC-SHA256 signature
	body := receivedPayloads[0]
	sigHeader := receivedSignatures[0]
	expectedPrefix := "sha256="
	if !strings.HasPrefix(sigHeader, expectedPrefix) {
		t.Fatalf("signature header %q missing prefix %s", sigHeader, expectedPrefix)
	}

	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(body)
	expectedSig := expectedPrefix + hex.EncodeToString(mac.Sum(nil))
	if sigHeader != expectedSig {
		t.Errorf("webhook signature = %q, want %q", sigHeader, expectedSig)
	}

	var ev AuditEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		t.Fatalf("unmarshal webhook body: %v", err)
	}
	if ev.Action != "draft.approved" || ev.DraftID != d.ID {
		t.Errorf("unexpected event payload: %+v", ev)
	}
}

func TestAuditLoggerUnit(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "test-audit.log")
	logger := NewAuditLogger(logPath)

	// List on non-existent file returns empty slice without error
	events, err := logger.ListRecent(10)
	if err != nil {
		t.Fatalf("ListRecent on non-existent file: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}

	// Record 3 events
	for i := 1; i <= 3; i++ {
		ev := AuditEvent{
			Timestamp: time.Now().UTC(),
			Action:    "draft.approved",
			DraftID:   fmt.Sprintf("draft-%d", i),
			Target:    "target-pkg",
		}
		if err := logger.Record(ev); err != nil {
			t.Fatalf("Record event %d: %v", i, err)
		}
	}

	// Verify limit
	recent2, err := logger.ListRecent(2)
	if err != nil {
		t.Fatalf("ListRecent(2): %v", err)
	}
	if len(recent2) != 2 {
		t.Fatalf("expected 2 events, got %d", len(recent2))
	}
	if recent2[0].DraftID != "draft-3" || recent2[1].DraftID != "draft-2" {
		t.Errorf("unexpected order: %+v", recent2)
	}

	// Default path resolution via XDG_STATE_HOME
	t.Setenv("XDG_STATE_HOME", tempDir)
	xdgLogger := NewAuditLogger("")
	expectedPath := filepath.Join(tempDir, "bugrouter", "audit.log")
	if xdgLogger.Path() != expectedPath {
		t.Errorf("xdgLogger.Path() = %q, want %q", xdgLogger.Path(), expectedPath)
	}
}

func TestWebhookNotifierUnit(t *testing.T) {
	// Nil notifier or empty URL is no-op
	var nilNotifier *WebhookNotifier
	if err := nilNotifier.Notify(context.Background(), AuditEvent{}); err != nil {
		t.Errorf("nil notifier error = %v, want nil", err)
	}

	emptyNotifier := NewWebhookNotifier(nil, "", "")
	if err := emptyNotifier.Notify(context.Background(), AuditEvent{}); err != nil {
		t.Errorf("empty URL error = %v, want nil", err)
	}

	// Env var fallback
	t.Setenv("BUGROUTER_WEBHOOK_URL", "https://example.com/webhook")
	t.Setenv("BUGROUTER_WEBHOOK_SECRET", "env-secret")
	envNotifier := NewWebhookNotifier(nil, "", "")
	if envNotifier.webhookURL != "https://example.com/webhook" {
		t.Errorf("webhookURL = %q, want https://example.com/webhook", envNotifier.webhookURL)
	}
	if envNotifier.secret != "env-secret" {
		t.Errorf("secret = %q, want env-secret", envNotifier.secret)
	}
}
