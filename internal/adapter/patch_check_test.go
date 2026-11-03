package adapter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestCheckPatchUpstreamStatusTokenGuards(t *testing.T) {
	var capturedAuth string
	var capturedPrivateToken string
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		capturedAuth = r.Header.Get("Authorization")
		capturedPrivateToken = r.Header.Get("PRIVATE-TOKEN")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"state": "open"}`)
	}))
	defer ts.Close()

	client := httpx.NewTestClient(5 * time.Second)

	t.Setenv("GITHUB_TOKEN", "leak-github-token")
	t.Setenv("GH_TOKEN", "leak-gh-token")
	t.Setenv("BUGROUTER_GITHUB_TOKEN", "")

	patch := DependencyPatch{
		ID:               "gh-leak-check",
		Dependency:       "leak-dep",
		UpstreamIssueURL: fmt.Sprintf("%s/repos/owner/repo/issues/1", ts.URL),
	}

	res, err := CheckPatchUpstreamStatus(context.Background(), client, []DependencyPatch{patch})
	if err != nil {
		t.Fatalf("CheckPatchUpstreamStatus failed: %v", err)
	}
	if len(res) != 1 || res[0].UpstreamState != "open" {
		t.Fatalf("unexpected result: %+v", res)
	}

	mu.Lock()
	if capturedAuth != "" {
		t.Errorf("GITHUB_TOKEN was leaked to non-github host %s: %q", ts.URL, capturedAuth)
	}
	mu.Unlock()

	t.Setenv("BUGROUTER_GITHUB_TOKEN", "explicit-token")
	_, err = CheckPatchUpstreamStatus(context.Background(), client, []DependencyPatch{patch})
	if err != nil {
		t.Fatalf("CheckPatchUpstreamStatus failed: %v", err)
	}

	mu.Lock()
	if capturedAuth != "Bearer explicit-token" {
		t.Errorf("expected explicit BUGROUTER_GITHUB_TOKEN, got %q", capturedAuth)
	}
	mu.Unlock()

	t.Setenv("GITLAB_TOKEN", "leak-gitlab-token")
	t.Setenv("GL_TOKEN", "leak-gl-token")
	t.Setenv("BUGROUTER_GITLAB_TOKEN", "")

	glPatch := DependencyPatch{
		ID:               "gl-leak-check",
		Dependency:       "gl-dep",
		UpstreamIssueURL: fmt.Sprintf("%s/group/project/-/issues/1", ts.URL),
	}

	_, err = CheckPatchUpstreamStatus(context.Background(), client, []DependencyPatch{glPatch})
	if err != nil {
		t.Fatalf("CheckPatchUpstreamStatus failed: %v", err)
	}

	mu.Lock()
	if capturedPrivateToken != "" {
		t.Errorf("GITLAB_TOKEN was leaked to non-gitlab host %s: %q", ts.URL, capturedPrivateToken)
	}
	mu.Unlock()

	t.Setenv("BUGROUTER_GITLAB_TOKEN", "explicit-gl-token")
	_, err = CheckPatchUpstreamStatus(context.Background(), client, []DependencyPatch{glPatch})
	if err != nil {
		t.Fatalf("CheckPatchUpstreamStatus failed: %v", err)
	}

	mu.Lock()
	if capturedPrivateToken != "explicit-gl-token" {
		t.Errorf("expected explicit BUGROUTER_GITLAB_TOKEN, got %q", capturedPrivateToken)
	}
	mu.Unlock()

	t.Setenv("GITEA_TOKEN", "leak-gitea-token")
	t.Setenv("CODEBERG_TOKEN", "leak-codeberg-token")
	t.Setenv("BUGROUTER_GITEA_TOKEN", "")

	giteaPatch := DependencyPatch{
		ID:               "gitea-leak-check",
		Dependency:       "gitea-dep",
		UpstreamIssueURL: fmt.Sprintf("%s/api/v1/repos/owner/repo/issues/1", ts.URL),
	}

	_, err = CheckPatchUpstreamStatus(context.Background(), client, []DependencyPatch{giteaPatch})
	if err != nil {
		t.Fatalf("CheckPatchUpstreamStatus failed: %v", err)
	}

	mu.Lock()
	if capturedAuth != "" {
		t.Errorf("GITEA/CODEBERG token was leaked to non-gitea host %s: %q", ts.URL, capturedAuth)
	}
	mu.Unlock()

	t.Setenv("BUGROUTER_GITEA_TOKEN", "explicit-gitea-token")
	_, err = CheckPatchUpstreamStatus(context.Background(), client, []DependencyPatch{giteaPatch})
	if err != nil {
		t.Fatalf("CheckPatchUpstreamStatus failed: %v", err)
	}

	mu.Lock()
	if capturedAuth != "token explicit-gitea-token" {
		t.Errorf("expected explicit BUGROUTER_GITEA_TOKEN, got %q", capturedAuth)
	}
	mu.Unlock()
}

func TestAuthHeaderResolution(t *testing.T) {
	t.Setenv("BUGROUTER_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "gh-tok")
	t.Setenv("GH_TOKEN", "")
	if hName, hVal := gitHubAuthHeader("github.com"); hName != "Authorization" || hVal != "Bearer gh-tok" {
		t.Errorf("expected Bearer gh-tok for github.com, got %s=%s", hName, hVal)
	}
	if hName, hVal := gitHubAuthHeader("api.github.com"); hName != "Authorization" || hVal != "Bearer gh-tok" {
		t.Errorf("expected Bearer gh-tok for api.github.com, got %s=%s", hName, hVal)
	}
	if hName, hVal := gitHubAuthHeader("untrusted.org"); hName != "" || hVal != "" {
		t.Errorf("expected no auth for untrusted.org, got %s=%s", hName, hVal)
	}
	t.Setenv("BUGROUTER_GITHUB_TOKEN", "br-gh")
	if hName, hVal := gitHubAuthHeader("untrusted.org"); hName != "Authorization" || hVal != "Bearer br-gh" {
		t.Errorf("expected Bearer br-gh for untrusted.org with BUGROUTER_GITHUB_TOKEN, got %s=%s", hName, hVal)
	}

	t.Setenv("BUGROUTER_GITLAB_TOKEN", "")
	t.Setenv("GITLAB_TOKEN", "gl-tok")
	t.Setenv("GL_TOKEN", "")
	if hName, hVal := gitLabAuthHeader("gitlab.com"); hName != "PRIVATE-TOKEN" || hVal != "gl-tok" {
		t.Errorf("expected PRIVATE-TOKEN gl-tok for gitlab.com, got %s=%s", hName, hVal)
	}
	if hName, hVal := gitLabAuthHeader("untrusted.org"); hName != "" || hVal != "" {
		t.Errorf("expected no auth for untrusted.org, got %s=%s", hName, hVal)
	}
	t.Setenv("BUGROUTER_GITLAB_TOKEN", "br-gl")
	if hName, hVal := gitLabAuthHeader("untrusted.org"); hName != "PRIVATE-TOKEN" || hVal != "br-gl" {
		t.Errorf("expected PRIVATE-TOKEN br-gl for untrusted.org with BUGROUTER_GITLAB_TOKEN, got %s=%s", hName, hVal)
	}

	t.Setenv("BUGROUTER_GITEA_TOKEN", "")
	t.Setenv("CODEBERG_TOKEN", "cb-tok")
	t.Setenv("GITEA_TOKEN", "gt-tok")
	if hName, hVal := giteaAuthHeader("codeberg.org"); hName != "Authorization" || hVal != "token cb-tok" {
		t.Errorf("expected token cb-tok for codeberg.org, got %s=%s", hName, hVal)
	}
	if hName, hVal := giteaAuthHeader("gitea.example.com"); hName != "Authorization" || hVal != "token gt-tok" {
		t.Errorf("expected token gt-tok for gitea.example.com, got %s=%s", hName, hVal)
	}
	if hName, hVal := giteaAuthHeader("forgejo.internal"); hName != "Authorization" || hVal != "token gt-tok" {
		t.Errorf("expected token gt-tok for forgejo.internal, got %s=%s", hName, hVal)
	}
	if hName, hVal := giteaAuthHeader("projects.blender.org"); hName != "Authorization" || hVal != "token gt-tok" {
		t.Errorf("expected token gt-tok for blender.org, got %s=%s", hName, hVal)
	}
	if hName, hVal := giteaAuthHeader("untrusted.org"); hName != "" || hVal != "" {
		t.Errorf("expected no auth for untrusted.org, got %s=%s", hName, hVal)
	}
	t.Setenv("BUGROUTER_GITEA_TOKEN", "br-gt")
	if hName, hVal := giteaAuthHeader("untrusted.org"); hName != "Authorization" || hVal != "token br-gt" {
		t.Errorf("expected token br-gt for untrusted.org with BUGROUTER_GITEA_TOKEN, got %s=%s", hName, hVal)
	}
}
