package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/dedup"
	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/introspector"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/scrubber"
)

func TestParseMarkdownBodyFileHeadings(t *testing.T) {
	raw := `## Summary
Payment gateway timed out unexpectedly.

### Environment Details
Region: us-east-1
Cluster: prod-checkout

## Steps to Reproduce
1. Navigate to /checkout
2. Submit valid payment info
3. Observe 504 Gateway Timeout

## Logs & Output
### Stack Trace
[error] dial tcp 10.0.0.1:443: i/o timeout
`
	summary, steps, logs := parseMarkdownBodyFile(raw)
	if !strings.Contains(summary, "Payment gateway timed out unexpectedly.") {
		t.Errorf("summary = %q, want expected summary", summary)
	}
	if !strings.Contains(summary, "### Environment Details") || !strings.Contains(summary, "prod-checkout") {
		t.Errorf("summary = %q, missing ### Environment Details or body content", summary)
	}
	if !strings.Contains(steps, "504 Gateway Timeout") {
		t.Errorf("steps = %q, want steps text", steps)
	}
	if !strings.Contains(logs, "### Stack Trace") || !strings.Contains(logs, "i/o timeout") {
		t.Errorf("logs = %q, missing ### Stack Trace or log output", logs)
	}
}

func TestParseMarkdownBodyFileNoHeadings(t *testing.T) {
	raw := "This is a single unformatted paragraph describing the issue."
	summary, steps, logs := parseMarkdownBodyFile(raw)
	if summary != raw {
		t.Errorf("summary = %q, want %q", summary, raw)
	}
	if steps != "" {
		t.Errorf("steps = %q, want empty", steps)
	}
	if logs != "" {
		t.Errorf("logs = %q, want empty", logs)
	}
}

func TestGoldenPathDraftAndBodyFile(t *testing.T) {
	tempDir := t.TempDir()
	dataHome := filepath.Join(tempDir, "data")
	cacheHome := filepath.Join(tempDir, "cache")
	configHome := filepath.Join(tempDir, "config")
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_CACHE_HOME", cacheHome)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	// Mock GitHub Enterprise instance
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v3/repos/myorg/checkout-api/contents/.github/ISSUE_TEMPLATE"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `[
				{"name": "bug.yml", "download_url": "http://%s/.github/ISSUE_TEMPLATE/bug.yml", "type": "file"}
			]`, r.Host)

		case r.URL.Path == "/.github/ISSUE_TEMPLATE/bug.yml":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, `
name: Bug Report
description: Submit a bug for checkout-api
title: "[BUG]: "
labels: ["bug", "triage"]
body:
  - type: textarea
    id: summary
    attributes:
      label: Summary
  - type: textarea
    id: reproduction
    attributes:
      label: Reproduction Steps
  - type: textarea
    id: error-logs
    attributes:
      label: Error Logs
`)

		case strings.HasPrefix(r.URL.Path, "/api/v3/search/issues"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{
				"total_count": 1,
				"items": [
					{
						"number": 88,
						"title": "Payment gateway timeout in checkout worker",
						"html_url": "http://%s/myorg/checkout-api/issues/88",
						"state": "open"
					}
				]
			}`, r.Host)

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// Configure BUGROUTER_SERVICES_FILE
	servicesPath := filepath.Join(tempDir, "services.json")
	servicesJSON := fmt.Sprintf(`{
		"services": [
			{
				"name": "checkout-api",
				"repository_url": "%s/myorg/checkout-api",
				"tracker": {
					"protocol": "github",
					"url": "%s/myorg/checkout-api/issues"
				}
			}
		]
	}`, ts.URL, ts.URL)
	if err := os.WriteFile(servicesPath, []byte(servicesJSON), 0600); err != nil {
		t.Fatalf("write services.json: %v", err)
	}
	t.Setenv("BUGROUTER_SERVICES_FILE", servicesPath)

	// Create markdown body file
	bodyContent := `## Summary
Payment gateway timeout with key AKIAIOSFODNN7EXAMPLE

## Steps to Reproduce
1. Send request to /checkout
2. Wait for timeout

## Logs
Fatal error reading config from /home/alice/secret.txt
`
	bodyFilePath := filepath.Join(tempDir, "body.md")
	if err := os.WriteFile(bodyFilePath, []byte(bodyContent), 0600); err != nil {
		t.Fatalf("write body.md: %v", err)
	}

	// 1. Exercise parseMarkdownBodyFile
	bodyData, err := os.ReadFile(bodyFilePath)
	if err != nil {
		t.Fatalf("read body.md: %v", err)
	}
	parsedSummary, parsedSteps, parsedLogs := parseMarkdownBodyFile(string(bodyData))

	// 2. Exercise Target Resolution
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	httpClient := httpx.NewTestClient(0)
	target, err := resolveTarget(ctx, httpClient, "checkout-api", true)
	if err != nil {
		t.Fatalf("resolveTarget checkout-api: %v", err)
	}
	if target.CanonicalName != "checkout-api" {
		t.Errorf("CanonicalName = %q, want checkout-api", target.CanonicalName)
	}
	if target.Tracker.Protocol != resolver.ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", target.Tracker.Protocol)
	}

	// 3. Exercise Template Introspection
	intro := introspector.New(httpClient)
	schema, err := intro.Introspect(ctx, *target)
	if err != nil {
		t.Fatalf("Introspect failed: %v", err)
	}
	if schema.Format != introspector.FormatGitHubForm {
		t.Errorf("Template format = %q, want github-form", schema.Format)
	}

	// 4. Exercise Duplicate Detection
	title := "Payment gateway timeout in checkout worker"
	finder := dedup.NewFinder(httpClient)
	dups, err := finder.FindDuplicates(ctx, *target, scrubber.Scrub(title))
	if err != nil {
		t.Fatalf("FindDuplicates failed: %v", err)
	}
	if len(dups) == 0 {
		t.Fatal("expected at least 1 duplicate, got 0")
	}
	if dups[0].ID != "88" {
		t.Errorf("dups[0].ID = %q, want 88", dups[0].ID)
	}

	// 5. Build Staged Draft
	draft, err := adapter.BuildDraft(adapter.DraftInput{
		Target:           *target,
		Title:            title,
		Summary:          parsedSummary,
		StepsToReproduce: parsedSteps,
		Logs:             parsedLogs,
		Template:         schema,
		Duplicates:       dups,
	})
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}

	// Verify Redaction
	bodyStr := string(draft.MarkdownBody)
	if strings.Contains(bodyStr, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("body leaked raw AWS key")
	}
	if !strings.Contains(bodyStr, "[REDACTED_AWS_KEY]") {
		t.Error("body missing [REDACTED_AWS_KEY]")
	}
	if strings.Contains(bodyStr, "/home/alice") {
		t.Error("body leaked /home/alice path")
	}
	if !strings.Contains(bodyStr, "~/secret.txt") {
		t.Error("body missing ~/secret.txt replacement")
	}

	// Verify Template Headings
	if !strings.Contains(bodyStr, "### Reproduction Steps") {
		t.Errorf("body missing ### Reproduction Steps heading: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "### Error Logs") {
		t.Errorf("body missing ### Error Logs heading: %s", bodyStr)
	}

	// Verify Duplicates Attached
	if len(draft.PotentialDuplicates) == 0 {
		t.Error("expected duplicates attached to staged draft")
	}

	// 6. Save Draft to XDG Store
	store := adapter.NewDraftStore("")
	savedPath, err := store.Save(draft)
	if err != nil {
		t.Fatalf("Save draft failed: %v", err)
	}

	// Verify File Permissions (0600)
	info, err := os.Stat(savedPath)
	if err != nil {
		t.Fatalf("stat saved draft: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("draft file permissions = %04o, want 0600", perm)
	}

	// Verify Draft Deserialization from Disk
	retrieved, err := store.Get(draft.ID)
	if err != nil {
		t.Fatalf("Get draft %s: %v", draft.ID, err)
	}
	if retrieved.ID != draft.ID {
		t.Errorf("retrieved ID = %q, want %q", retrieved.ID, draft.ID)
	}
	if retrieved.Target.CanonicalName != "checkout-api" {
		t.Errorf("retrieved target = %q, want checkout-api", retrieved.Target.CanonicalName)
	}
}
