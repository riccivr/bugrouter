package adapter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/riccivr/bugrouter/internal/httpx"
)

func TestCheckPatchUpstreamStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/owner/github-open/issues/101"):
			fmt.Fprint(w, `{"state": "open"}`)
		case strings.HasPrefix(r.URL.Path, "/repos/owner/github-closed/issues/102"):
			fmt.Fprint(w, `{"state": "closed"}`)
		case strings.Contains(r.URL.RequestURI(), "group%2Fgitlab-open/issues/201") || strings.Contains(r.URL.Path, "group/gitlab-open/issues/201"):
			fmt.Fprint(w, `{"state": "opened"}`)
		case strings.Contains(r.URL.RequestURI(), "group%2Fgitlab-closed/issues/202") || strings.Contains(r.URL.Path, "group/gitlab-closed/issues/202"):
			fmt.Fprint(w, `{"state": "closed"}`)
		case strings.HasPrefix(r.URL.Path, "/api/v1/repos/owner/gitea-open/issues/301"):
			fmt.Fprint(w, `{"state": "open"}`)
		case strings.HasPrefix(r.URL.Path, "/api/v1/repos/owner/gitea-closed/issues/302"):
			fmt.Fprint(w, `{"state": "closed"}`)
		case strings.HasPrefix(r.URL.Path, "/rest/bug/401"):
			fmt.Fprint(w, `{"bugs": [{"id": 401, "status": "CONFIRMED"}]}`)
		case strings.HasPrefix(r.URL.Path, "/rest/bug/402"):
			fmt.Fprint(w, `{"bugs": [{"id": 402, "status": "RESOLVED"}]}`)
		case strings.HasPrefix(r.URL.Path, "/repos/owner/github-error/"):
			http.Error(w, "server error", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client := httpx.NewTestClient(5 * time.Second)

	patches := []DependencyPatch{
		{
			ID:               "p1",
			Dependency:       "gh-open",
			UpstreamIssueURL: fmt.Sprintf("%s/repos/owner/github-open/issues/101", ts.URL),
		},
		{
			ID:               "p2",
			Dependency:       "gh-closed",
			UpstreamIssueURL: fmt.Sprintf("%s/repos/owner/github-closed/issues/102", ts.URL),
		},
		{
			ID:               "p3",
			Dependency:       "gl-open",
			UpstreamIssueURL: fmt.Sprintf("%s/group/gitlab-open/-/issues/201", ts.URL),
		},
		{
			ID:               "p4",
			Dependency:       "gl-closed",
			UpstreamIssueURL: fmt.Sprintf("%s/group/gitlab-closed/-/issues/202", ts.URL),
		},
		{
			ID:               "p5",
			Dependency:       "gitea-open",
			UpstreamIssueURL: fmt.Sprintf("%s/api/v1/repos/owner/gitea-open/issues/301", ts.URL),
		},
		{
			ID:               "p6",
			Dependency:       "gitea-closed",
			UpstreamIssueURL: fmt.Sprintf("%s/api/v1/repos/owner/gitea-closed/issues/302", ts.URL),
		},
		{
			ID:               "p7",
			Dependency:       "bz-open",
			UpstreamIssueURL: fmt.Sprintf("%s/show_bug.cgi?id=401", ts.URL),
		},
		{
			ID:               "p8",
			Dependency:       "bz-closed",
			UpstreamIssueURL: fmt.Sprintf("%s/show_bug.cgi?id=402", ts.URL),
		},
		{
			ID:               "p9",
			Dependency:       "no-url",
			UpstreamIssueURL: "",
		},
		{
			ID:               "p10",
			Dependency:       "err-url",
			UpstreamIssueURL: fmt.Sprintf("%s/repos/owner/github-error/issues/500", ts.URL),
		},
	}

	results, err := CheckPatchUpstreamStatus(context.Background(), client, patches)
	if err != nil {
		t.Fatalf("CheckPatchUpstreamStatus failed: %v", err)
	}

	if len(results) != len(patches) {
		t.Fatalf("expected %d results, got %d", len(patches), len(results))
	}

	expected := []struct {
		dep       string
		state     string
		canRevert bool
	}{
		{"gh-open", "open", false},
		{"gh-closed", "closed", true},
		{"gl-open", "open", false},
		{"gl-closed", "closed", true},
		{"gitea-open", "open", false},
		{"gitea-closed", "closed", true},
		{"bz-open", "open", false},
		{"bz-closed", "closed", true},
		{"no-url", "no_url", false},
		{"err-url", "unknown", false},
	}

	for i, exp := range expected {
		r := results[i]
		if r.Patch.Dependency != exp.dep {
			t.Errorf("[%d] expected dep %q, got %q", i, exp.dep, r.Patch.Dependency)
		}
		if r.UpstreamState != exp.state {
			t.Errorf("[%d] expected state %q, got %q (err: %s)", i, exp.state, r.UpstreamState, r.CheckError)
		}
		if r.CanRevert != exp.canRevert {
			t.Errorf("[%d] expected canRevert %t, got %t", i, exp.canRevert, r.CanRevert)
		}
	}
}
