package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/resolver"
)

func TestForgeClientGitHub(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-gh-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/repos/org/repo/issues" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"html_url": "https://github.enterprise.corp/org/repo/issues/101"}`)
	}))
	defer ts.Close()

	client := NewForgeClient(httpx.NewTestClient(time.Second)).
		WithToken(resolver.ProtocolGitHub, "test-gh-token").
		WithBaseURL(resolver.ProtocolGitHub, ts.URL)

	draft := &adapter.StagedDraft{
		Target: resolver.Target{
			CanonicalName: "repo",
			RepositoryURL: "https://github.enterprise.corp/org/repo",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitHub,
				URL:      "https://github.enterprise.corp/org/repo/issues",
			},
		},
		Title:        "Memory leak in worker",
		MarkdownBody: "## Summary\nWorker fails to free buffer",
	}

	url, err := client.Submit(context.Background(), draft)
	if err != nil {
		t.Fatalf("Submit GitHub failed: %v", err)
	}
	expectedURL := "https://github.enterprise.corp/org/repo/issues/101"
	if url != expectedURL {
		t.Errorf("url = %q, want %q", url, expectedURL)
	}
}

func TestForgeClientGitLab(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "test-gl-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !strings.Contains(r.URL.EscapedPath(), "api/v4/projects/group%2Fsubgroup%2Fproject/issues") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"web_url": "https://gitlab.corp/group/subgroup/project/-/issues/202"}`)
	}))
	defer ts.Close()

	client := NewForgeClient(httpx.NewTestClient(time.Second)).
		WithToken(resolver.ProtocolGitLab, "test-gl-token").
		WithBaseURL(resolver.ProtocolGitLab, ts.URL)

	draft := &adapter.StagedDraft{
		Target: resolver.Target{
			CanonicalName: "project",
			RepositoryURL: "https://gitlab.corp/group/subgroup/project",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitLab,
				URL:      "https://gitlab.corp/group/subgroup/project/-/issues",
			},
		},
		Title:        "Panic on startup",
		MarkdownBody: "## Steps\n1. Run binary",
	}

	url, err := client.Submit(context.Background(), draft)
	if err != nil {
		t.Fatalf("Submit GitLab failed: %v", err)
	}
	expectedURL := "https://gitlab.corp/group/subgroup/project/-/issues/202"
	if url != expectedURL {
		t.Errorf("url = %q, want %q", url, expectedURL)
	}
}

func TestForgeClientJira(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") && !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/rest/api/2/issue" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"key": "PROJ-303", "self": "https://jira.corp/rest/api/2/issue/303"}`)
	}))
	defer ts.Close()

	client := NewForgeClient(httpx.NewTestClient(time.Second)).
		WithToken(resolver.ProtocolJira, "admin:secretpassword").
		WithBaseURL(resolver.ProtocolJira, ts.URL)

	draft := &adapter.StagedDraft{
		Target: resolver.Target{
			CanonicalName: "PROJ",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolJira,
				URL:      ts.URL,
			},
		},
		Title:        "Database deadlocks under load",
		MarkdownBody: "## Expected\nNon-blocking transactions",
	}

	url, err := client.Submit(context.Background(), draft)
	if err != nil {
		t.Fatalf("Submit Jira failed: %v", err)
	}
	expectedPrefix := ts.URL + "/browse/PROJ-303"
	if url != expectedPrefix {
		t.Errorf("url = %q, want %q", url, expectedPrefix)
	}
}

func TestForgeClientLinear(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "test-lin-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data": {"issueCreate": {"success": true, "issue": {"id": "lin-404", "url": "https://linear.app/myteam/issue/ENG-404"}}}}`)
	}))
	defer ts.Close()

	t.Setenv("LINEAR_TEAM_ID", "team-123")
	client := NewForgeClient(httpx.NewTestClient(time.Second)).
		WithToken(resolver.ProtocolLinear, "test-lin-key").
		WithLinearURL(ts.URL)

	draft := &adapter.StagedDraft{
		Target: resolver.Target{
			CanonicalName: "frontend",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolLinear,
				URL:      "https://linear.app/myteam",
			},
		},
		Title:        "Dark mode contrast failure",
		MarkdownBody: "Contrast ratio < 4.5:1",
	}

	url, err := client.Submit(context.Background(), draft)
	if err != nil {
		t.Fatalf("Submit Linear failed: %v", err)
	}
	expectedURL := "https://linear.app/myteam/issue/ENG-404"
	if url != expectedURL {
		t.Errorf("url = %q, want %q", url, expectedURL)
	}
}

func TestForgeClientBlocksLoopbackByDefault(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"html_url": "https://example.com/issue/1"}`)
	}))
	defer ts.Close()

	client := NewForgeClient(httpx.NewClient(time.Second)).
		WithToken(resolver.ProtocolGitHub, "test-token").
		WithBaseURL(resolver.ProtocolGitHub, ts.URL)

	draft := &adapter.StagedDraft{
		Target: resolver.Target{
			CanonicalName: "repo",
			RepositoryURL: "https://github.com/org/repo",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitHub,
				URL:      "https://github.com/org/repo/issues",
			},
		},
		Title: "Test SSRF loopback block",
	}

	_, err := client.Submit(context.Background(), draft)
	if err == nil {
		t.Fatal("expected SSRF block error on loopback server, got nil")
	}
	if !strings.Contains(err.Error(), "blocked connection") && !strings.Contains(err.Error(), "loopback") {
		t.Errorf("expected error containing 'blocked connection' or 'loopback', got: %v", err)
	}
}

func TestForgeClientMissingToken(t *testing.T) {
	client := NewForgeClient(httpx.NewTestClient(time.Second))
	draft := &adapter.StagedDraft{
		Target: resolver.Target{
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitHub,
				URL:      "https://github.com/org/repo/issues",
			},
		},
		Title: "Test without token",
	}

	_, err := client.Submit(context.Background(), draft)
	if err == nil {
		t.Fatal("expected error on missing token, got nil")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("expected error containing 'missing', got: %v", err)
	}
}
