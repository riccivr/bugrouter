package introspector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/resolver"
)

func TestIntrospectGitHub(t *testing.T) {
	var dirCalls int32
	var rawCalls int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/example-org/my-tool/contents/.github/ISSUE_TEMPLATE":
			atomic.AddInt32(&dirCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			// Return two templates: feature_request.md and bug_report.yml
			fmt.Fprintf(w, `[
				{"name": "feature_request.md", "download_url": "http://%s/raw/feature.md", "type": "file"},
				{"name": "bug_report.yml", "download_url": "http://%s/raw/bug.yml", "type": "file"}
			]`, r.Host, r.Host)

		case "/raw/bug.yml":
			atomic.AddInt32(&rawCalls, 1)
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, `
name: Bug Report
description: Submit a bug
title: "[BUG]: "
body:
  - type: textarea
    id: what-happened
    attributes:
      label: What happened?
`)

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client := httpx.NewTestClient(time.Second)
	intro := New(client).WithEndpoints(Endpoints{
		GitHubAPIBaseURL: ts.URL,
	})

	target := resolver.Target{
		CanonicalName: "my-tool",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolGitHub,
			URL:      "https://github.com/example-org/my-tool/issues",
		},
	}

	schema, err := intro.Introspect(context.Background(), target)
	if err != nil {
		t.Fatalf("Introspect failed: %v", err)
	}

	if schema.Format != FormatGitHubForm {
		t.Errorf("Format = %v, want %v", schema.Format, FormatGitHubForm)
	}
	if schema.FileName != "bug_report.yml" {
		t.Errorf("FileName = %q, want bug_report.yml (selected over feature_request.md)", schema.FileName)
	}
	if schema.TitlePrefix != "[BUG]: " {
		t.Errorf("TitlePrefix = %q, want [BUG]: ", schema.TitlePrefix)
	}
	if len(schema.Fields) != 1 || schema.Fields[0].ID != "what-happened" {
		t.Errorf("Fields unexpected: %+v", schema.Fields)
	}
}

func TestIntrospectGitLab(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped := r.URL.EscapedPath()
		switch {
		case strings.Contains(escaped, "repository/tree"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[
				{"name": "Feature.md", "path": ".gitlab/issue_templates/Feature.md", "type": "blob"},
				{"name": "Bug.md", "path": ".gitlab/issue_templates/Bug.md", "type": "blob"}
			]`)

		case strings.Contains(escaped, "repository/files") && strings.HasSuffix(escaped, "/raw"):
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, `## Description
Describe the issue.

## Steps to Reproduce
1. Run application
`)

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client := httpx.NewTestClient(time.Second)
	intro := New(client).WithEndpoints(Endpoints{
		GitLabBaseURL: ts.URL,
	})

	target := resolver.Target{
		CanonicalName: "project",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolGitLab,
			URL:      "https://gitlab.com/group/subgroup/project/-/issues",
		},
	}

	schema, err := intro.Introspect(context.Background(), target)
	if err != nil {
		t.Fatalf("Introspect GitLab failed: %v", err)
	}

	if schema.Format != FormatGitLabMarkdown {
		t.Errorf("Format = %v, want %v", schema.Format, FormatGitLabMarkdown)
	}
	if schema.FileName != "Bug.md" {
		t.Errorf("FileName = %q, want Bug.md", schema.FileName)
	}
	if len(schema.Fields) != 2 {
		t.Fatalf("Fields len = %d, want 2", len(schema.Fields))
	}
}

func TestIntrospectBugzilla(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/product":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"products": [
					{
						"name": "Bugzilla",
						"description": "Bug tracker",
						"components": [{"name": "UI"}],
						"versions": [{"name": "5.0"}]
					}
				]
			}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client := httpx.NewTestClient(time.Second)
	intro := New(client)

	target := resolver.Target{
		CanonicalName: "bugzilla",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolBugzilla,
			URL:      ts.URL + "/enter_bug.cgi",
		},
	}

	schema, err := intro.Introspect(context.Background(), target)
	if err != nil {
		t.Fatalf("Introspect Bugzilla failed: %v", err)
	}

	if schema.Format != FormatBugzillaSchema {
		t.Errorf("Format = %v, want %v", schema.Format, FormatBugzillaSchema)
	}
	if len(schema.Fields) != 4 {
		t.Fatalf("Fields len = %d, want 4", len(schema.Fields))
	}
	if schema.Fields[0].Value != "Bugzilla" {
		t.Errorf("Product value = %q, want Bugzilla", schema.Fields[0].Value)
	}
}

func TestIntrospectBugzillaFallbackToFieldBug(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/product":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"products": []}`)
		case "/rest/field/bug":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"fields": [
					{
						"name": "product",
						"values": [{"name": "Core"}, {"name": "Firefox"}]
					},
					{
						"name": "component",
						"values": [{"name": "General"}]
					}
				]
			}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client := httpx.NewTestClient(time.Second)
	intro := New(client)

	target := resolver.Target{
		CanonicalName: "firefox",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolBugzilla,
			URL:      ts.URL + "/enter_bug.cgi",
		},
	}

	schema, err := intro.Introspect(context.Background(), target)
	if err != nil {
		t.Fatalf("Introspect Bugzilla fallback failed: %v", err)
	}
	if schema.Format != FormatBugzillaSchema {
		t.Errorf("Format = %v, want %v", schema.Format, FormatBugzillaSchema)
	}
	if schema.Fields[0].Value != "Core" {
		t.Errorf("Product value = %q, want Core", schema.Fields[0].Value)
	}
}

func TestIntrospectBugzillaBothEmptyReturnsErrNoTemplate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}))
	defer ts.Close()

	client := httpx.NewTestClient(time.Second)
	intro := New(client)

	target := resolver.Target{
		CanonicalName: "empty-bugzilla",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolBugzilla,
			URL:      ts.URL + "/enter_bug.cgi",
		},
	}

	_, err := intro.Introspect(context.Background(), target)
	if err != ErrNoTemplateFound {
		t.Errorf("expected ErrNoTemplateFound, got: %v", err)
	}
}

func TestIntrospectGitHubAuthHeader(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test_secret_abc123")
	authHeaderReceived := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer ghp_test_secret_abc123" {
			authHeaderReceived = true
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	client := httpx.NewTestClient(time.Second)
	intro := New(client).WithEndpoints(Endpoints{
		GitHubAPIBaseURL: ts.URL,
	})

	target := resolver.Target{
		CanonicalName: "repo",
		RepositoryURL: "https://github.com/myorg/repo",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolGitHub,
			URL:      "https://github.com/myorg/repo/issues",
		},
	}

	_, err := intro.Introspect(context.Background(), target)
	if !errors.Is(err, ErrNoTemplateFound) {
		t.Fatalf("expected ErrNoTemplateFound, got: %v", err)
	}
	if !authHeaderReceived {
		t.Error("expected Authorization: Bearer ghp_test_secret_abc123 header to be sent")
	}
}

func TestShouldSendGitHubAuth(t *testing.T) {
	cases := []struct {
		name        string
		downloadURL string
		apiBaseURL  string
		want        bool
	}{
		{
			name:        "raw.githubusercontent.com public",
			downloadURL: "https://raw.githubusercontent.com/owner/repo/main/.github/ISSUE_TEMPLATE/bug.yml",
			apiBaseURL:  "https://api.github.com",
			want:        true,
		},
		{
			name:        "github.com domain",
			downloadURL: "https://github.com/owner/repo/raw/main/.github/ISSUE_TEMPLATE/bug.yml",
			apiBaseURL:  "https://api.github.com",
			want:        true,
		},
		{
			name:        "matching enterprise host",
			downloadURL: "https://github.enterprise.corp/raw/bug.yml",
			apiBaseURL:  "https://github.enterprise.corp/api/v3",
			want:        true,
		},
		{
			name:        "untrusted third party domain",
			downloadURL: "https://evil.example.com/template.yml",
			apiBaseURL:  "https://api.github.com",
			want:        false,
		},
		{
			name:        "untrusted third party domain on enterprise",
			downloadURL: "https://evil.example.com/template.yml",
			apiBaseURL:  "https://github.enterprise.corp/api/v3",
			want:        false,
		},
		{
			name:        "malformed url",
			downloadURL: "::not-a-url::",
			apiBaseURL:  "https://api.github.com",
			want:        false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldSendGitHubAuth(tc.downloadURL, tc.apiBaseURL)
			if got != tc.want {
				t.Errorf("shouldSendGitHubAuth(%q, %q) = %v, want %v", tc.downloadURL, tc.apiBaseURL, got, tc.want)
			}
		})
	}
}

func TestIntrospectTokenHostGuards(t *testing.T) {
	// 1. Direct unit checks for gitHubAuthHeader
	t.Setenv("BUGROUTER_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "ambient-gh-secret")
	t.Setenv("GH_TOKEN", "")

	if h := gitHubAuthHeader("github.com"); h["Authorization"] != "Bearer ambient-gh-secret" {
		t.Errorf("expected Bearer ambient-gh-secret for github.com, got: %v", h)
	}
	if h := gitHubAuthHeader("api.github.com"); h["Authorization"] != "Bearer ambient-gh-secret" {
		t.Errorf("expected Bearer ambient-gh-secret for api.github.com, got: %v", h)
	}
	if h := gitHubAuthHeader("enterprise.github.com"); h["Authorization"] != "Bearer ambient-gh-secret" {
		t.Errorf("expected Bearer ambient-gh-secret for enterprise.github.com, got: %v", h)
	}
	if h := gitHubAuthHeader("untrusted-domain.org"); h != nil {
		t.Errorf("expected no auth header for untrusted-domain.org, got: %v", h)
	}

	t.Setenv("BUGROUTER_GITHUB_TOKEN", "explicit-br-gh")
	if h := gitHubAuthHeader("untrusted-domain.org"); h["Authorization"] != "Bearer explicit-br-gh" {
		t.Errorf("expected Bearer explicit-br-gh for untrusted-domain.org with BUGROUTER_GITHUB_TOKEN, got: %v", h)
	}

	// 2. Direct unit checks for gitLabAuthHeader
	t.Setenv("BUGROUTER_GITLAB_TOKEN", "")
	t.Setenv("GITLAB_TOKEN", "ambient-gl-secret")
	t.Setenv("GL_TOKEN", "")

	if h := gitLabAuthHeader("gitlab.com"); h["PRIVATE-TOKEN"] != "ambient-gl-secret" {
		t.Errorf("expected PRIVATE-TOKEN ambient-gl-secret for gitlab.com, got: %v", h)
	}
	if h := gitLabAuthHeader("corp.gitlab.com"); h["PRIVATE-TOKEN"] != "ambient-gl-secret" {
		t.Errorf("expected PRIVATE-TOKEN ambient-gl-secret for corp.gitlab.com, got: %v", h)
	}
	if h := gitLabAuthHeader("untrusted-domain.org"); h != nil {
		t.Errorf("expected no auth header for untrusted-domain.org, got: %v", h)
	}

	t.Setenv("BUGROUTER_GITLAB_TOKEN", "explicit-br-gl")
	if h := gitLabAuthHeader("untrusted-domain.org"); h["PRIVATE-TOKEN"] != "explicit-br-gl" {
		t.Errorf("expected PRIVATE-TOKEN explicit-br-gl for untrusted-domain.org with BUGROUTER_GITLAB_TOKEN, got: %v", h)
	}

	// 3. Direct unit checks for giteaAuthHeader
	t.Setenv("BUGROUTER_GITEA_TOKEN", "")
	t.Setenv("CODEBERG_TOKEN", "ambient-cb-secret")
	t.Setenv("GITEA_TOKEN", "ambient-gt-secret")

	if h := giteaAuthHeader("codeberg.org"); h["Authorization"] != "token ambient-cb-secret" {
		t.Errorf("expected token ambient-cb-secret for codeberg.org, got: %v", h)
	}
	if h := giteaAuthHeader("gitea.com"); h["Authorization"] != "token ambient-gt-secret" {
		t.Errorf("expected token ambient-gt-secret for gitea.com, got: %v", h)
	}
	if h := giteaAuthHeader("projects.blender.org"); h["Authorization"] != "token ambient-gt-secret" {
		t.Errorf("expected token ambient-gt-secret for projects.blender.org, got: %v", h)
	}
	if h := giteaAuthHeader("untrusted-domain.org"); h != nil {
		t.Errorf("expected no auth header for untrusted-domain.org, got: %v", h)
	}

	t.Setenv("BUGROUTER_GITEA_TOKEN", "explicit-br-gt")
	if h := giteaAuthHeader("untrusted-domain.org"); h["Authorization"] != "token explicit-br-gt" {
		t.Errorf("expected token explicit-br-gt for untrusted-domain.org with BUGROUTER_GITEA_TOKEN, got: %v", h)
	}

	// 4. End-to-end introspection: ambient tokens are not leaked to untrusted custom forge hosts
	t.Setenv("BUGROUTER_GITHUB_TOKEN", "")
	t.Setenv("BUGROUTER_GITLAB_TOKEN", "")
	t.Setenv("BUGROUTER_GITEA_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "ambient-gh-secret")
	t.Setenv("GITLAB_TOKEN", "ambient-gl-secret")
	t.Setenv("GITEA_TOKEN", "ambient-gt-secret")

	var receivedAuth, receivedPrivateToken string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedPrivateToken = r.Header.Get("PRIVATE-TOKEN")
		http.NotFound(w, r)
	}))
	defer ts.Close()

	client := httpx.NewTestClient(time.Second)
	intro := New(client).WithEndpoints(Endpoints{
		GitHubAPIBaseURL: ts.URL,
		GitLabBaseURL:    ts.URL,
	})

	// GitHub target pointing to custom untrusted forge
	untrustedGHTarget := resolver.Target{
		CanonicalName: "untrusted-repo",
		RepositoryURL: ts.URL + "/untrusted/repo",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolGitHub,
			URL:      ts.URL + "/untrusted/repo/issues",
		},
	}
	if schema, err := intro.Introspect(context.Background(), untrustedGHTarget); !errors.Is(err, ErrNoTemplateFound) || schema != nil {
		t.Fatalf("expected ErrNoTemplateFound, got: %v", err)
	}
	if receivedAuth != "" {
		t.Errorf("ambient GITHUB_TOKEN leaked to untrusted custom host: %q", receivedAuth)
	}

	// GitLab target pointing to custom untrusted forge
	untrustedGLTarget := resolver.Target{
		CanonicalName: "untrusted-gl",
		RepositoryURL: ts.URL + "/untrusted/project",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolGitLab,
			URL:      ts.URL + "/untrusted/project/-/issues",
		},
	}
	if schema, err := intro.Introspect(context.Background(), untrustedGLTarget); !errors.Is(err, ErrNoTemplateFound) || schema != nil {
		t.Fatalf("expected ErrNoTemplateFound, got: %v", err)
	}
	if receivedPrivateToken != "" {
		t.Errorf("ambient GITLAB_TOKEN leaked to untrusted custom host: %q", receivedPrivateToken)
	}

	// Gitea target pointing to custom untrusted forge
	untrustedGiteaTarget := resolver.Target{
		CanonicalName: "untrusted-gitea",
		RepositoryURL: ts.URL + "/untrusted/gitearepo",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolGitea,
			URL:      ts.URL + "/untrusted/gitearepo/issues",
		},
	}
	receivedAuth = ""
	if schema, err := intro.Introspect(context.Background(), untrustedGiteaTarget); !errors.Is(err, ErrNoTemplateFound) || schema != nil {
		t.Fatalf("expected ErrNoTemplateFound, got: %v", err)
	}
	if receivedAuth != "" {
		t.Errorf("ambient GITEA_TOKEN leaked to untrusted custom host: %q", receivedAuth)
	}

	// Explicit override works even on untrusted hosts
	t.Setenv("BUGROUTER_GITHUB_TOKEN", "explicit-authorized-key")
	receivedAuth = ""
	if schema, err := intro.Introspect(context.Background(), untrustedGHTarget); !errors.Is(err, ErrNoTemplateFound) || schema != nil {
		t.Fatalf("expected ErrNoTemplateFound, got: %v", err)
	}
	if receivedAuth != "Bearer explicit-authorized-key" {
		t.Errorf("expected explicit BUGROUTER_GITHUB_TOKEN to be sent, got: %q", receivedAuth)
	}

	t.Setenv("BUGROUTER_GITLAB_TOKEN", "explicit-gl-authorized-key")
	receivedPrivateToken = ""
	if schema, err := intro.Introspect(context.Background(), untrustedGLTarget); !errors.Is(err, ErrNoTemplateFound) || schema != nil {
		t.Fatalf("expected ErrNoTemplateFound, got: %v", err)
	}
	if receivedPrivateToken != "explicit-gl-authorized-key" {
		t.Errorf("expected explicit BUGROUTER_GITLAB_TOKEN to be sent, got: %q", receivedPrivateToken)
	}

	t.Setenv("BUGROUTER_GITEA_TOKEN", "explicit-gt-authorized-key")
	receivedAuth = ""
	if schema, err := intro.Introspect(context.Background(), untrustedGiteaTarget); !errors.Is(err, ErrNoTemplateFound) || schema != nil {
		t.Fatalf("expected ErrNoTemplateFound, got: %v", err)
	}
	if receivedAuth != "token explicit-gt-authorized-key" {
		t.Errorf("expected explicit BUGROUTER_GITEA_TOKEN to be sent, got: %q", receivedAuth)
	}
}
