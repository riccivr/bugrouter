package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/version"
)

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
	respApprove, err := http.Post(approveURL, "application/json", nil)
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
	respDiscard, err := http.Post(discardURL, "application/json", nil)
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
}

func TestServerPathTraversalRejected(t *testing.T) {
	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	srv := NewServer(":0", store, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	badIDs := []string{"bad..id", "bad-id!", "bad_id$", "bad%20id"}
	for _, bad := range badIDs {
		resp, err := http.Post(ts.URL+"/api/v1/drafts/"+bad+"/approve", "application/json", nil)
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
