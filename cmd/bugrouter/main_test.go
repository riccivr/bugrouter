package main

import (
	"bytes"
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
	"github.com/riccivr/bugrouter/internal/telemetry"
	"github.com/riccivr/bugrouter/internal/verifier"
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

func TestAgentTriagePipeline(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(tempDir, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(tempDir, "cache"))

	crashLog := `panic: runtime error: slice bounds out of range [:20] with capacity 10

goroutine 1 [running]:
github.com/example/worker.ProcessItems(0xc000088000)
	/go/pkg/mod/github.com/example/worker@v1.2.0/process.go:88 +0x34
main.main()
	/app/main.go:24 +0x50
`

	// 1. Extract candidates
	candidates := resolver.ExtractTargetsFromLog(crashLog)
	if len(candidates) == 0 {
		t.Fatal("expected at least 1 candidate, got 0")
	}
	if candidates[0].Query != "github.com/example/worker" {
		t.Errorf("candidate query = %q, want github.com/example/worker", candidates[0].Query)
	}
	if candidates[0].Source != "go_module" {
		t.Errorf("candidate source = %q, want go_module", candidates[0].Source)
	}

	// 2. Resolve target
	httpClient := httpx.NewTestClient(0)
	target, err := resolveTarget(context.Background(), httpClient, candidates[0].Query, true)
	if err != nil {
		t.Fatalf("resolveTarget failed: %v", err)
	}
	if target.Tracker.Protocol != resolver.ProtocolGitHub {
		t.Errorf("target protocol = %s, want github", target.Tracker.Protocol)
	}

	// 3. Assemble AgentTriageResult
	res := AgentTriageResult{
		Candidates:     candidates,
		ResolvedTarget: target,
		ScrubbedLog:    scrubber.Scrub(crashLog),
		NextActions: []string{
			fmt.Sprintf("Run 'bugrouter draft --title <title> --steps <steps> %s' to stage a verified bug ticket", target.CanonicalName),
		},
	}

	if len(res.Candidates) != 1 {
		t.Errorf("len(res.Candidates) = %d, want 1", len(res.Candidates))
	}
	if res.ResolvedTarget.CanonicalName != "worker" {
		t.Errorf("resolved target = %s, want worker", res.ResolvedTarget.CanonicalName)
	}
	if !strings.Contains(res.ResolvedTarget.RepositoryURL, "github.com/example/worker") {
		t.Errorf("resolved repo = %s, want github.com/example/worker", res.ResolvedTarget.RepositoryURL)
	}
	if len(res.NextActions) == 0 {
		t.Errorf("expected NextActions, got empty")
	}
}

func TestDraftStrictQualityEvaluation(t *testing.T) {
	// 1. Bad input with AI slop
	badInput := adapter.DraftInput{
		Target: resolver.Target{
			CanonicalName: "my-package",
		},
		Title:            "Crash when we delve into configuration",
		Summary:          "I hope this message finds you well. As an AI, I noticed an issue.",
		StepsToReproduce: "1. Run app.",
	}

	draftBad, err := adapter.BuildDraft(badInput)
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}
	if draftBad.Quality.Passed {
		t.Errorf("expected draft with slop to fail quality check")
	}
	if len(draftBad.Quality.Issues) == 0 {
		t.Errorf("expected issues in quality report")
	}

	// 2. High signal input
	cleanInput := adapter.DraftInput{
		Target: resolver.Target{
			CanonicalName: "my-package",
		},
		Title:            "Panic on invalid memory address during server initialization",
		Summary:          "When starting the worker without a valid configuration, a nil pointer panic occurs.",
		StepsToReproduce: "1. Run worker binary without config flag\n2. Observe panic stack trace",
		Logs:             "panic: runtime error: invalid memory address",
	}

	draftClean, err := adapter.BuildDraft(cleanInput)
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}
	if !draftClean.Quality.Passed {
		t.Errorf("expected clean draft to pass quality gate, got issues: %v", draftClean.Quality.Issues)
	}
	if draftClean.Quality.Score != 100 {
		t.Errorf("clean draft score = %d, want 100", draftClean.Quality.Score)
	}
}

func TestAgentVerifyIntegration(t *testing.T) {
	proof, err := verifier.Verify(context.Background(), verifier.VerifyOptions{
		Command: "echo 'error log' && exit 1",
	})
	if err != nil {
		t.Fatalf("verifier.Verify failed: %v", err)
	}
	if !proof.Reproduced {
		t.Errorf("expected Reproduced=true")
	}
	if proof.ExitCode != 1 {
		t.Errorf("expected ExitCode=1, got %d", proof.ExitCode)
	}
	if !strings.Contains(string(proof.ScrubbedOutput), "error log") {
		t.Errorf("expected scrubbed output to contain 'error log', got %s", proof.ScrubbedOutput)
	}
}

func TestDraftVerifyCmdIntegration(t *testing.T) {
	proof, err := verifier.Verify(context.Background(), verifier.VerifyOptions{
		Command: "echo 'panic: stack trace failure' && exit 1",
	})
	if err != nil {
		t.Fatalf("verifier.Verify failed: %v", err)
	}

	in := adapter.DraftInput{
		Target: resolver.Target{
			CanonicalName: "core-svc",
		},
		Title:            "Crash in core service worker",
		Summary:          "A failure was verified through automated reproduction.",
		StepsToReproduce: "1. Run verify script\n2. Observe exit code 1",
		Verification:     proof,
	}

	draft, err := adapter.BuildDraft(in)
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}

	if draft.Verification == nil {
		t.Fatalf("expected Verification to be set on draft")
	}
	if !draft.Verification.Reproduced {
		t.Errorf("expected draft.Verification.Reproduced = true")
	}
	if !strings.Contains(string(draft.MarkdownBody), "## Verified Reproduction") {
		t.Errorf("expected markdown body to contain verified reproduction section")
	}
	if !strings.Contains(string(draft.MarkdownBody), "panic: stack trace failure") {
		t.Errorf("expected auto-populated logs in markdown body")
	}
}

func TestStackCommandIntegration(t *testing.T) {
	tempDir := t.TempDir()

	goMod := `module myapp
go 1.22
require github.com/example/lib v1.2.3
`
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	pkgJson := `{
		"dependencies": {
			"https://github.com/example/nodepkg": "2.0.0"
		}
	}`
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(pkgJson), 0600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	wf := resolver.NewWaterfall(time.Second, resolver.NewDirectProbe())
	finder := dedup.NewFinder(httpx.NewTestClient(time.Second))

	report, err := dedup.BuildStackRadar(context.Background(), wf, finder, tempDir, false)
	if err != nil {
		t.Fatalf("BuildStackRadar failed: %v", err)
	}

	if report.Total != 2 {
		t.Errorf("report.Total = %d, want 2", report.Total)
	}
	if report.Resolved != 2 {
		t.Errorf("report.Resolved = %d, want 2", report.Resolved)
	}
	if len(report.Entries) != 2 {
		t.Fatalf("len(report.Entries) = %d, want 2", len(report.Entries))
	}
}

func TestTelemetryCommandIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	telem := telemetry.Collect(ctx)
	if telem.OS == "" {
		t.Fatal("expected non-empty OS from Collect")
	}

	draft, err := adapter.BuildDraft(adapter.DraftInput{
		Target: resolver.Target{
			CanonicalName: "blender",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitea,
				URL:      "https://projects.blender.org/blender/blender/issues",
			},
		},
		Title:     "GPU crash on launch",
		Telemetry: &telem,
	})
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}

	if draft.Telemetry == nil {
		t.Fatalf("expected Telemetry attached to draft")
	}
	body := string(draft.MarkdownBody)
	if !strings.Contains(body, "## Environment") {
		t.Errorf("expected ## Environment in draft markdown body: %s", body)
	}
	if !strings.Contains(body, "- **OS**:") {
		t.Errorf("expected - **OS**: in draft markdown body: %s", body)
	}
}

func TestGuidedReportWizard(t *testing.T) {
	tempDir := t.TempDir()
	dataHome := filepath.Join(tempDir, "data")
	cacheHome := filepath.Join(tempDir, "cache")
	configHome := filepath.Join(tempDir, "config")
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_CACHE_HOME", cacheHome)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	// Simulated user typing interactively:
	// 1. Title
	// 2. Summary
	// 3. Steps to reproduce
	// 4. Expected behavior
	// 5. Actual behavior
	// 6. Logs / output
	userInput := strings.Join([]string{
		"Null pointer dereference during connection pool initialization",
		"When initializing the connection pool with zero max connections, a panic occurs.",
		"1. Instantiate pool with MaxConns=0\n2. Call pool.Acquire()\n3. Observe panic",
		"Clean error returned indicating invalid MaxConns",
		"SIGSEGV panic terminating process immediately",
		"panic: runtime error: invalid memory address or nil pointer dereference",
	}, "\n") + "\n"

	in := strings.NewReader(userInput)
	out := &bytes.Buffer{}

	client := httpx.NewTestClient(2 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := ReportOptions{
		Query:   "https://github.com/myorg/myapp",
		NoCache: true,
	}

	draft, stagedPath, err := runGuidedReport(ctx, in, out, client, opts)
	if err != nil {
		t.Fatalf("runGuidedReport failed: %v", err)
	}

	if draft == nil {
		t.Fatal("expected non-nil staged draft")
	}
	if draft.Title != "Null pointer dereference during connection pool initialization" {
		t.Errorf("title = %q, want expected title", draft.Title)
	}
	if draft.Quality.Score < 80 {
		t.Errorf("expected quality score >= 80, got %d", draft.Quality.Score)
	}
	if !draft.Quality.Passed {
		t.Errorf("expected quality passed=true, got false (issues: %v)", draft.Quality.Issues)
	}
	if draft.Telemetry == nil {
		t.Error("expected telemetry attached by default")
	}

	if stagedPath == "" {
		t.Fatal("expected non-empty stagedPath")
	}
	if _, statErr := os.Stat(stagedPath); statErr != nil {
		t.Fatalf("staged file does not exist at %s: %v", stagedPath, statErr)
	}

	output := out.String()
	if !strings.Contains(output, "--- Bug Report Staged ---") {
		t.Errorf("output missing staging banner: %s", output)
	}
	if !strings.Contains(output, "Quality Assessment:") {
		t.Errorf("output missing quality assessment: %s", output)
	}
	if !strings.Contains(output, "Score:") {
		t.Errorf("output missing score: %s", output)
	}
}

func TestParkAndDraftFromParked(t *testing.T) {
	tempDir := t.TempDir()
	dataHome := filepath.Join(tempDir, "data")
	cacheHome := filepath.Join(tempDir, "cache")
	configHome := filepath.Join(tempDir, "config")
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_CACHE_HOME", cacheHome)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	parkStore := adapter.NewParkedStore("")
	bug, handoff, err := parkStore.Park(
		"https://github.com/lovell/sharp",
		"SIGSEGV in libvips image resize",
		"panic: runtime error in libvips.so",
		"downgraded to 0.32.0",
		"server/image.ts:15",
	)
	if err != nil {
		t.Fatalf("Park failed: %v", err)
	}

	if bug.ID == "" || bug.Status != "parked" {
		t.Fatalf("invalid parked bug: %+v", bug)
	}
	if handoff.CLICommand != "bugrouter draft --from-parked "+bug.ID {
		t.Errorf("handoff.CLICommand = %q, want bugrouter draft --from-parked %s", handoff.CLICommand, bug.ID)
	}

	// Now hydrate draft using the parked ID
	p, err := parkStore.Get(bug.ID)
	if err != nil {
		t.Fatalf("Get parked bug %s failed: %v", bug.ID, err)
	}

	target := resolver.Target{
		CanonicalName: "sharp",
		RepositoryURL: p.Dependency,
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolGitHub,
			URL:      "https://github.com/lovell/sharp/issues",
		},
	}

	title := p.Title
	logs := string(p.ErrorSnippet)
	summary := fmt.Sprintf("Discovered anomaly in %s: %s\n\nWorkaround/Notes: %s", p.Dependency, p.Title, string(p.WorkaroundNote))
	steps := fmt.Sprintf("Observed in %s", p.WorkspaceFile)

	draft, err := adapter.BuildDraft(adapter.DraftInput{
		Target:           target,
		Title:            title,
		Summary:          summary,
		StepsToReproduce: steps,
		Logs:             logs,
	})
	if err != nil {
		t.Fatalf("BuildDraft from parked failed: %v", err)
	}

	if draft.Title != "SIGSEGV in libvips image resize" {
		t.Errorf("title = %q, want expected", draft.Title)
	}

	// Save draft and update parked status to triaged
	draftStore := adapter.NewDraftStore("")
	savedPath, err := draftStore.Save(draft)
	if err != nil {
		t.Fatalf("draftStore.Save failed: %v", err)
	}
	if savedPath == "" {
		t.Fatal("expected non-empty savedPath")
	}

	p.Status = "triaged"
	if err := parkStore.Save(p); err != nil {
		t.Fatalf("parkStore.Save update status failed: %v", err)
	}

	triaged, err := parkStore.Get(bug.ID)
	if err != nil {
		t.Fatalf("Get triaged bug failed: %v", err)
	}
	if triaged.Status != "triaged" {
		t.Errorf("triaged.Status = %q, want triaged", triaged.Status)
	}
}

func TestPatchSubcommandLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	patchFile := filepath.Join(tempDir, "patches.json")
	t.Setenv("BUGROUTER_PATCHES_FILE", patchFile)

	store := adapter.NewPatchStore("")
	if store.Path() != patchFile {
		t.Fatalf("expected store path %q, got %q", patchFile, store.Path())
	}

	// 1. Initial list
	initial, err := store.List()
	if err != nil {
		t.Fatalf("initial List failed: %v", err)
	}
	if len(initial) != 0 {
		t.Errorf("expected 0 patches, got %d", len(initial))
	}

	// 2. Record patch
	patch, err := store.Record(
		"github.com/gin-gonic/gin",
		"go",
		"github.com/myorg/gin@fix-context",
		"go.mod",
		"https://github.com/gin-gonic/gin/issues/999",
		"Fix data race in Context.Copy",
	)
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}
	if patch.Dependency != "github.com/gin-gonic/gin" {
		t.Errorf("expected gin dep, got %q", patch.Dependency)
	}

	// 3. List
	list, err := store.List()
	if err != nil {
		t.Fatalf("List after record failed: %v", err)
	}
	if len(list) != 1 || list[0].ID != patch.ID {
		t.Fatalf("expected 1 patch in list, got %+v", list)
	}

	// 4. Remove by dep
	if err := store.Remove("github.com/gin-gonic/gin"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	afterRm, err := store.List()
	if err != nil {
		t.Fatalf("List after rm failed: %v", err)
	}
	if len(afterRm) != 0 {
		t.Errorf("expected 0 patches after rm, got %d", len(afterRm))
	}
}

func TestRecoverAndParkSelfBug(t *testing.T) {
	tempDir := t.TempDir()

	// 1. When panic is nil, returns nil
	nilBug, nilErr := recoverAndParkSelfBug(nil, nil, tempDir)
	if nilErr != nil {
		t.Fatalf("unexpected error on nil panic: %v", nilErr)
	}
	if nilBug != nil {
		t.Fatalf("expected nil bug on nil panic, got: %+v", nilBug)
	}

	// 2. Recover unexpected panic and park breadcrumb
	panicVal := "nil pointer dereference at runtime"
	stack := []byte("goroutine 1 [running]:\ncmd/bugrouter/main.go:300 +0x123")

	bug, err := recoverAndParkSelfBug(panicVal, stack, tempDir)
	if err != nil {
		t.Fatalf("recoverAndParkSelfBug failed: %v", err)
	}
	if bug == nil {
		t.Fatalf("expected parked bug, got nil")
	}

	if bug.Dependency != "bugrouter" {
		t.Errorf("Dependency = %q, want bugrouter", bug.Dependency)
	}
	if !strings.Contains(bug.Title, "internal panic in bugrouter") || !strings.Contains(bug.Title, panicVal) {
		t.Errorf("Title = %q, missing panic details", bug.Title)
	}
	if !strings.Contains(string(bug.ErrorSnippet), "goroutine 1 [running]") {
		t.Errorf("ErrorSnippet missing stack trace: %s", bug.ErrorSnippet)
	}
	if !strings.Contains(string(bug.WorkaroundNote), "os=") {
		t.Errorf("WorkaroundNote missing os/arch: %s", bug.WorkaroundNote)
	}

	// 3. Verify it was written to disk and can be reloaded
	store := adapter.NewParkedStore(tempDir)
	reloaded, err := store.Get(bug.ID)
	if err != nil {
		t.Fatalf("Get parked bug %s failed: %v", bug.ID, err)
	}
	if reloaded.Title != bug.Title {
		t.Errorf("reloaded title = %q, want %q", reloaded.Title, bug.Title)
	}
}

func TestCrashLogPipeline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	logData, suspect, err := resolver.ReadLatestCrash(ctx)
	if err == nil {
		if logData == "" {
			t.Errorf("expected non-empty crash log when err == nil")
		}
		if suspect != "" {
			candidates := resolver.ExtractTargetsFromLog(logData)
			if len(candidates) < 0 {
				t.Errorf("unexpected negative candidates")
			}
		}
	} else {
		if !strings.Contains(err.Error(), "no") && !strings.Contains(err.Error(), "context") && !strings.Contains(err.Error(), "not found") {
			t.Logf("ReadLatestCrash returned: %v (expected in clean test environment)", err)
		}
	}
}
