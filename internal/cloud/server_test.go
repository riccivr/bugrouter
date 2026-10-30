package cloud

import (
	"bytes"
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
	calls        int
}

func (m *mockSubmitter) Submit(ctx context.Context, draft *adapter.StagedDraft) (string, error) {
	m.calls++
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

	// Verify idempotent approval returns 409 Conflict without re-submitting
	respApproveAgain, err := postWithHeader(approveURL, map[string]string{"X-Bugrouter-Request": "1"})
	if err != nil {
		t.Fatalf("POST /approve again failed: %v", err)
	}
	defer respApproveAgain.Body.Close()

	if respApproveAgain.StatusCode != http.StatusConflict {
		t.Errorf("second POST /approve status = %d, want 409 Conflict", respApproveAgain.StatusCode)
	}
	var conflictRes map[string]string
	if err := json.NewDecoder(respApproveAgain.Body).Decode(&conflictRes); err != nil {
		t.Fatalf("decode conflict response: %v", err)
	}
	if conflictRes["error"] != "draft already submitted" {
		t.Errorf("conflict error = %q, want 'draft already submitted'", conflictRes["error"])
	}
	if conflictRes["issue_url"] != submitter.submittedURL {
		t.Errorf("conflict issue_url = %q, want %s", conflictRes["issue_url"], submitter.submittedURL)
	}
	if submitter.calls != 1 {
		t.Errorf("submitter called %d times, want 1", submitter.calls)
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

func TestServerStackEndpoint(t *testing.T) {
	tempDir := t.TempDir()
	pkgJsonContent := `{
		"dependencies": {
			"https://github.com/myorg/worker": "1.0.0"
		}
	}`
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(pkgJsonContent), 0600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	wf := resolver.NewWaterfall(time.Second, resolver.NewDirectProbe())
	srv := NewServer(":0", nil, nil).WithStackScanner(wf, nil, tempDir)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Unauthenticated request to /api/v1/stack (no auth token configured on server)
	resp, err := http.Get(ts.URL + "/api/v1/stack")
	if err != nil {
		t.Fatalf("GET /api/v1/stack failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var report struct {
		RootDir  string `json:"root_dir"`
		Total    int    `json:"total"`
		Resolved int    `json:"resolved"`
		Entries  []any  `json:"entries"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if report.Total != 1 || report.Resolved != 1 {
		t.Errorf("expected 1 total and resolved, got total=%d resolved=%d", report.Total, report.Resolved)
	}

	// 2. Auth token enforcement on /api/v1/stack
	srvAuth := NewServer(":0", nil, nil).
		WithAuthToken("super-secret-token").
		WithStackScanner(wf, nil, tempDir)
	tsAuth := httptest.NewServer(srvAuth.Handler())
	defer tsAuth.Close()

	// 2a. Request without token -> 401
	respNoAuth, err := http.Get(tsAuth.URL + "/api/v1/stack")
	if err != nil {
		t.Fatalf("GET /api/v1/stack without auth failed: %v", err)
	}
	respNoAuth.Body.Close()
	if respNoAuth.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got: %d", respNoAuth.StatusCode)
	}

	// 2b. Request with valid Bearer token -> 200
	req, err := http.NewRequest(http.MethodGet, tsAuth.URL+"/api/v1/stack", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer super-secret-token")
	respAuth, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do request with auth failed: %v", err)
	}
	respAuth.Body.Close()
	if respAuth.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK with Bearer token, got: %d", respAuth.StatusCode)
	}

	// 3. Verify HTML includes Connected Tech Stack & Downstream Radar table
	respHTML, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer respHTML.Body.Close()
	htmlData, err := io.ReadAll(respHTML.Body)
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	htmlStr := string(htmlData)
	if !strings.Contains(htmlStr, "Connected Tech Stack &amp; Downstream Radar") {
		t.Errorf("expected stack radar header in indexHTML")
	}
	if !strings.Contains(htmlStr, "stack-table") || !strings.Contains(htmlStr, "fetchStack") {
		t.Errorf("expected stack-table and fetchStack in indexHTML")
	}
}

func TestServerCreateDraftEndpoint(t *testing.T) {
	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	auditFile := filepath.Join(tempDir, "audit.jsonl")
	logger := NewAuditLogger(auditFile)

	srv := NewServer(":0", store, nil).WithAuditLogger(logger)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Success case: 201 Created with high-quality draft
	createReq := CreateDraftRequest{
		Query:            "https://github.com/myorg/myapp",
		Title:            "Null pointer dereference during connection pool initialization",
		Summary:          "When initializing the connection pool with zero max connections, a panic occurs.",
		StepsToReproduce: "1. Instantiate pool with MaxConns=0\n2. Call pool.Acquire()\n3. Observe panic",
		Logs:             "panic: runtime error: invalid memory address or nil pointer dereference",
		IncludeTelemetry: true,
		StrictQuality:    true,
	}
	bodyBytes, err := json.Marshal(createReq)
	if err != nil {
		t.Fatalf("marshal createReq: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/drafts", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bugrouter-Request", "1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/drafts failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			// drain
		}
		t.Fatalf("expected status 201 Created, got %d: %s", resp.StatusCode, string(respBody))
	}

	var created adapter.StagedDraft
	if decodeErr := json.NewDecoder(resp.Body).Decode(&created); decodeErr != nil {
		t.Fatalf("decode created draft: %v", decodeErr)
	}

	if created.ID == "" {
		t.Error("expected non-empty draft ID")
	}
	if created.Title != "Null pointer dereference during connection pool initialization" {
		t.Errorf("title = %q, want expected title", created.Title)
	}
	if created.Telemetry == nil {
		t.Error("expected telemetry attached to created draft")
	}
	if !created.Quality.Passed {
		t.Errorf("expected quality passed=true, got false (issues: %v)", created.Quality.Issues)
	}

	// Verify draft was saved to draftStore
	saved, getErr := store.Get(created.ID)
	if getErr != nil || saved == nil {
		t.Fatalf("store.Get(%s) failed: %v", created.ID, getErr)
	}

	// Verify audit trail recorded draft.created
	events, listErr := logger.ListRecent(10)
	if listErr != nil {
		t.Fatalf("ListRecent audit failed: %v", listErr)
	}
	foundAuditEvent := false
	for _, ev := range events {
		if ev.Action == "draft.created" && ev.DraftID == created.ID {
			foundAuditEvent = true
			break
		}
	}
	if !foundAuditEvent {
		t.Errorf("expected draft.created audit event, got: %+v", events)
	}

	// 2. Strict quality failure case: 422 Unprocessable Entity
	badReq := CreateDraftRequest{
		Query:            "https://github.com/myorg/myapp",
		Title:            "crash",
		Summary:          "as an ai, i hope this message finds you well",
		StepsToReproduce: "repro",
		StrictQuality:    true,
	}
	badBytes, err := json.Marshal(badReq)
	if err != nil {
		t.Fatalf("marshal badReq: %v", err)
	}

	reqBad, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/drafts", bytes.NewReader(badBytes))
	if err != nil {
		t.Fatalf("new bad request: %v", err)
	}
	reqBad.Header.Set("Content-Type", "application/json")
	reqBad.Header.Set("X-Bugrouter-Request", "1")

	respBad, err := http.DefaultClient.Do(reqBad)
	if err != nil {
		t.Fatalf("POST /api/v1/drafts bad request failed: %v", err)
	}
	defer respBad.Body.Close()

	if respBad.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected status 422 Unprocessable Entity, got %d", respBad.StatusCode)
	}

	var quality adapter.QualityReport
	if decodeErr := json.NewDecoder(respBad.Body).Decode(&quality); decodeErr != nil {
		t.Fatalf("decode quality report: %v", decodeErr)
	}
	if quality.Passed {
		t.Error("expected quality.Passed=false")
	}
	if len(quality.Issues) == 0 {
		t.Error("expected quality issues list to be populated")
	}

	// 3. Verify HTML includes New Guided Report button and modal
	respHTML, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer respHTML.Body.Close()
	htmlData, err := io.ReadAll(respHTML.Body)
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	htmlStr := string(htmlData)
	if !strings.Contains(htmlStr, "New Guided Report") {
		t.Errorf("expected 'New Guided Report' button in indexHTML")
	}
	if !strings.Contains(htmlStr, "composer-modal") || !strings.Contains(htmlStr, "submitGuidedDraft") {
		t.Errorf("expected composer-modal and submitGuidedDraft in indexHTML")
	}
}

func TestServerServicesCatalogEndpoints(t *testing.T) {
	tempDir := t.TempDir()
	servicesFile := filepath.Join(tempDir, "services.json")
	auditFile := filepath.Join(tempDir, "audit.jsonl")
	logger := NewAuditLogger(auditFile)

	srv := NewServer(":0", nil, nil).
		WithServicesFile(servicesFile).
		WithAuditLogger(logger)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Initial GET /api/v1/services returns empty list
	resp, err := http.Get(ts.URL + "/api/v1/services")
	if err != nil {
		t.Fatalf("GET /api/v1/services failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	var services []resolver.ServiceEntry
	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		t.Fatalf("decode empty services list: %v", err)
	}
	if len(services) != 0 {
		t.Errorf("expected 0 services, got %d", len(services))
	}

	// 2. POST /api/v1/services validation: empty name rejected
	badBody := []byte(`{"name": ""}`)
	reqBad, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/services", bytes.NewReader(badBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	reqBad.Header.Set("Content-Type", "application/json")
	reqBad.Header.Set("X-Bugrouter-Request", "1")

	respBad, err := http.DefaultClient.Do(reqBad)
	if err != nil {
		t.Fatalf("POST bad service failed: %v", err)
	}
	respBad.Body.Close()
	if respBad.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", respBad.StatusCode)
	}

	// 3. POST /api/v1/services success case: upsert service
	stripeEntry := resolver.ServiceEntry{
		Name:          "stripe",
		RepositoryURL: "https://github.com/stripe/stripe-node",
	}
	bodyBytes, err := json.Marshal(stripeEntry)
	if err != nil {
		t.Fatalf("marshal stripeEntry: %v", err)
	}

	reqPost, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/services", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	reqPost.Header.Set("Content-Type", "application/json")
	reqPost.Header.Set("X-Bugrouter-Request", "1")

	respPost, err := http.DefaultClient.Do(reqPost)
	if err != nil {
		t.Fatalf("POST service failed: %v", err)
	}
	defer respPost.Body.Close()

	if respPost.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(respPost.Body)
		t.Fatalf("expected 200 OK, got %d: %s", respPost.StatusCode, string(respBytes))
	}

	var savedEntry resolver.ServiceEntry
	if err := json.NewDecoder(respPost.Body).Decode(&savedEntry); err != nil {
		t.Fatalf("decode savedEntry: %v", err)
	}
	if savedEntry.Name != "stripe" {
		t.Errorf("expected name stripe, got %q", savedEntry.Name)
	}
	if savedEntry.Tracker.Protocol != resolver.ProtocolGitHub {
		t.Errorf("expected auto-classified protocol github, got %q", savedEntry.Tracker.Protocol)
	}
	if !strings.Contains(savedEntry.Tracker.URL, "github.com/stripe/stripe-node/issues") {
		t.Errorf("expected auto-classified tracker URL, got %q", savedEntry.Tracker.URL)
	}

	// Verify file was written with 0600 permissions
	fi, err := os.Stat(servicesFile)
	if err != nil {
		t.Fatalf("stat services.json failed: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("expected 0600 permissions, got %04o", perm)
	}

	// 4. GET /api/v1/services returns 1 service
	respGet, err := http.Get(ts.URL + "/api/v1/services")
	if err != nil {
		t.Fatalf("GET /api/v1/services failed: %v", err)
	}
	defer respGet.Body.Close()

	var svcList []resolver.ServiceEntry
	if err := json.NewDecoder(respGet.Body).Decode(&svcList); err != nil {
		t.Fatalf("decode svcList: %v", err)
	}
	if len(svcList) != 1 || svcList[0].Name != "stripe" {
		t.Fatalf("expected 1 service 'stripe', got %v", svcList)
	}

	// 5. Audit logger recorded service.upserted
	events, err := logger.ListRecent(10)
	if err != nil {
		t.Fatalf("ListRecent audit failed: %v", err)
	}
	foundUpsert := false
	for _, ev := range events {
		if ev.Action == "service.upserted" && ev.Target == "stripe" {
			foundUpsert = true
			break
		}
	}
	if !foundUpsert {
		t.Errorf("missing service.upserted audit event: %+v", events)
	}

	// 6. DELETE /api/v1/services/stripe
	reqDel, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/services/stripe", nil)
	if err != nil {
		t.Fatalf("new delete request: %v", err)
	}
	reqDel.Header.Set("X-Bugrouter-Request", "1")

	respDel, err := http.DefaultClient.Do(reqDel)
	if err != nil {
		t.Fatalf("DELETE /api/v1/services/stripe failed: %v", err)
	}
	respDel.Body.Close()

	if respDel.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on delete, got %d", respDel.StatusCode)
	}

	// Verify service is gone
	respGet2, err := http.Get(ts.URL + "/api/v1/services")
	if err != nil {
		t.Fatalf("GET /api/v1/services failed: %v", err)
	}
	defer respGet2.Body.Close()
	var svcList2 []resolver.ServiceEntry
	if err := json.NewDecoder(respGet2.Body).Decode(&svcList2); err != nil {
		t.Fatalf("decode svcList2: %v", err)
	}
	if len(svcList2) != 0 {
		t.Errorf("expected 0 services after delete, got %d", len(svcList2))
	}

	// 7. DELETE nonexistent returns 404
	reqDelNon, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/services/nonexistent", nil)
	if err != nil {
		t.Fatalf("new delete request: %v", err)
	}
	reqDelNon.Header.Set("X-Bugrouter-Request", "1")

	respDelNon, err := http.DefaultClient.Do(reqDelNon)
	if err != nil {
		t.Fatalf("DELETE nonexistent failed: %v", err)
	}
	respDelNon.Body.Close()
	if respDelNon.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 Not Found, got %d", respDelNon.StatusCode)
	}

	// 8. Verify indexHTML includes WorkOS-style sections
	respHTML, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer respHTML.Body.Close()
	htmlBytes, err := io.ReadAll(respHTML.Body)
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "Connected Dependencies &amp; Downstream Services") {
		t.Errorf("expected Connected Dependencies header in indexHTML")
	}
	if !strings.Contains(htmlStr, "services-grid") || !strings.Contains(htmlStr, "service-detail-modal") {
		t.Errorf("expected services-grid and service-detail-modal in indexHTML")
	}
	if !strings.Contains(htmlStr, "PRESETS") || !strings.Contains(htmlStr, "fetchServices") {
		t.Errorf("expected PRESETS and fetchServices in indexHTML script")
	}
}

func TestServerPatchEndpoints(t *testing.T) {
	tempDir := t.TempDir()
	patchFile := filepath.Join(tempDir, "patches.json")
	patchStore := adapter.NewPatchStore(patchFile)
	auditFile := filepath.Join(tempDir, "audit.jsonl")
	logger := NewAuditLogger(auditFile)

	srv := NewServer(":0", nil, nil).
		WithPatchStore(patchStore).
		WithAuditLogger(logger)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Initial GET /api/v1/patches returns empty list
	resp, err := http.Get(ts.URL + "/api/v1/patches")
	if err != nil {
		t.Fatalf("GET /api/v1/patches failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	var patches []adapter.DependencyPatch
	if err := json.NewDecoder(resp.Body).Decode(&patches); err != nil {
		t.Fatalf("decode empty patches: %v", err)
	}
	if len(patches) != 0 {
		t.Errorf("expected 0 patches, got %d", len(patches))
	}

	// 2. POST /api/v1/patches validation: missing required fields rejected
	badBody := []byte(`{"dependency": ""}`)
	reqBad, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/patches", bytes.NewReader(badBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	reqBad.Header.Set("Content-Type", "application/json")
	reqBad.Header.Set("X-Bugrouter-Request", "1")

	respBad, err := http.DefaultClient.Do(reqBad)
	if err != nil {
		t.Fatalf("POST bad payload: %v", err)
	}
	respBad.Body.Close()
	if respBad.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request on empty dependency, got %d", respBad.StatusCode)
	}

	// 3. POST /api/v1/patches valid payload
	validBody := []byte(`{
		"dependency": "sharp",
		"ecosystem": "npm",
		"patch_target": "patches/sharp+0.33.0.patch",
		"manifest_file": "package.json",
		"upstream_issue_url": "https://github.com/lovell/sharp/issues/1234",
		"reason": "Fix musl SIGSEGV in libvips"
	}`)
	reqValid, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/patches", bytes.NewReader(validBody))
	if err != nil {
		t.Fatalf("new valid request: %v", err)
	}
	reqValid.Header.Set("Content-Type", "application/json")
	reqValid.Header.Set("X-Bugrouter-Request", "1")

	respValid, err := http.DefaultClient.Do(reqValid)
	if err != nil {
		t.Fatalf("POST valid patch failed: %v", err)
	}
	defer respValid.Body.Close()
	if respValid.StatusCode != http.StatusCreated {
		respBytes, _ := io.ReadAll(respValid.Body)
		t.Fatalf("expected 201 Created, got %d: %s", respValid.StatusCode, string(respBytes))
	}

	var recorded adapter.DependencyPatch
	if err := json.NewDecoder(respValid.Body).Decode(&recorded); err != nil {
		t.Fatalf("decode recorded patch: %v", err)
	}
	if recorded.Dependency != "sharp" {
		t.Errorf("expected dependency sharp, got %q", recorded.Dependency)
	}
	if recorded.PatchTarget != "patches/sharp+0.33.0.patch" {
		t.Errorf("expected patch target patches/sharp+0.33.0.patch, got %q", recorded.PatchTarget)
	}

	// Verify file was written with 0600 permissions
	fi, err := os.Stat(patchFile)
	if err != nil {
		t.Fatalf("stat patches.json failed: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("expected 0600 permissions, got %04o", perm)
	}

	// 4. GET /api/v1/patches returns recorded patch
	respGet, err := http.Get(ts.URL + "/api/v1/patches")
	if err != nil {
		t.Fatalf("GET /api/v1/patches failed: %v", err)
	}
	defer respGet.Body.Close()

	var patchList []adapter.DependencyPatch
	if err := json.NewDecoder(respGet.Body).Decode(&patchList); err != nil {
		t.Fatalf("decode patchList: %v", err)
	}
	if len(patchList) != 1 || patchList[0].ID != recorded.ID {
		t.Fatalf("expected 1 patch %s, got %+v", recorded.ID, patchList)
	}

	// 5. Audit logger recorded patch.recorded
	events, err := logger.ListRecent(10)
	if err != nil {
		t.Fatalf("ListRecent audit failed: %v", err)
	}
	foundRecorded := false
	for _, ev := range events {
		if ev.Action == "patch.recorded" && ev.Target == "sharp" {
			foundRecorded = true
			break
		}
	}
	if !foundRecorded {
		t.Errorf("missing patch.recorded audit event: %+v", events)
	}

	// 6. DELETE /api/v1/patches/{id}
	reqDel, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/patches/"+recorded.ID, nil)
	if err != nil {
		t.Fatalf("new delete request: %v", err)
	}
	reqDel.Header.Set("X-Bugrouter-Request", "1")

	respDel, err := http.DefaultClient.Do(reqDel)
	if err != nil {
		t.Fatalf("DELETE patch failed: %v", err)
	}
	respDel.Body.Close()

	if respDel.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on delete, got %d", respDel.StatusCode)
	}

	// Verify patch is gone
	respGet2, err := http.Get(ts.URL + "/api/v1/patches")
	if err != nil {
		t.Fatalf("GET /api/v1/patches failed: %v", err)
	}
	defer respGet2.Body.Close()
	var patchList2 []adapter.DependencyPatch
	if err := json.NewDecoder(respGet2.Body).Decode(&patchList2); err != nil {
		t.Fatalf("decode patchList2: %v", err)
	}
	if len(patchList2) != 0 {
		t.Errorf("expected 0 patches after delete, got %d", len(patchList2))
	}

	// 7. DELETE nonexistent returns 404
	reqDelNon, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/patches/nonexistent", nil)
	if err != nil {
		t.Fatalf("new delete nonexistent request: %v", err)
	}
	reqDelNon.Header.Set("X-Bugrouter-Request", "1")

	respDelNon, err := http.DefaultClient.Do(reqDelNon)
	if err != nil {
		t.Fatalf("DELETE nonexistent failed: %v", err)
	}
	respDelNon.Body.Close()
	if respDelNon.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 Not Found, got %d", respDelNon.StatusCode)
	}

	// 8. Verify indexHTML includes Active Patches banner and modal
	respHTML, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer respHTML.Body.Close()
	htmlBytes, err := io.ReadAll(respHTML.Body)
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "Active Dependency Patches (Temporary Forks)") {
		t.Errorf("expected Active Dependency Patches header in indexHTML")
	}
	if !strings.Contains(htmlStr, "add-patch-modal") || !strings.Contains(htmlStr, "fetchPatches") {
		t.Errorf("expected add-patch-modal and fetchPatches in indexHTML")
	}

	// 9. Red-team verification: no duplicate let currentPatches, no lowercase escapeHtml, overlay modal style
	if count := strings.Count(htmlStr, "let currentPatches"); count != 1 {
		t.Errorf("expected exactly 1 'let currentPatches' declaration in indexHTML, got %d", count)
	}
	if strings.Contains(htmlStr, "escapeHtml(") {
		t.Errorf("found undefined lowercase escapeHtml in indexHTML")
	}
	if !strings.Contains(htmlStr, `id="add-patch-modal" style="display: none; position: fixed;`) {
		t.Errorf("expected #add-patch-modal to have overlay styling in indexHTML")
	}
}
