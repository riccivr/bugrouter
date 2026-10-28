package introspector

import (
	"context"
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
