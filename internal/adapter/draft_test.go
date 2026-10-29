package adapter

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/riccivr/bugrouter/internal/dedup"
	"github.com/riccivr/bugrouter/internal/introspector"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/telemetry"
	"github.com/riccivr/bugrouter/internal/verifier"
)

func TestBuildDraftSecretRedaction(t *testing.T) {
	in := DraftInput{
		Target: resolver.Target{
			CanonicalName: "my-app",
			LocalVersion:  "1.0.0",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitHub,
				URL:      "https://github.com/org/my-app/issues",
			},
		},
		Title:            "Crash when token=ghp_12345678901234567890 is passed",
		Summary:          "Failed with AWS_SECRET=AKIAIOSFODNN7EXAMPLE in /home/alice/app",
		StepsToReproduce: "1. Run with bearer secret_token_xyz",
		Logs:             "postgres://user:secretpass@localhost:5432/db",
	}

	draft, err := BuildDraft(in)
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}

	if len(draft.ID) != 16 {
		t.Errorf("ID length = %d, want 16", len(draft.ID))
	}
	if draft.Status != "pending_review" {
		t.Errorf("Status = %q, want pending_review", draft.Status)
	}

	// Verify title redaction
	if strings.Contains(string(draft.Title), "ghp_") {
		t.Errorf("Title contains unredacted github token: %s", draft.Title)
	}
	if !strings.Contains(string(draft.Title), "[REDACTED_GITHUB_TOKEN]") {
		t.Errorf("Title missing [REDACTED_GITHUB_TOKEN]: %s", draft.Title)
	}

	// Verify markdown body redaction
	body := string(draft.MarkdownBody)
	if strings.Contains(body, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Body contains unredacted AWS key")
	}
	if strings.Contains(body, "/home/alice") {
		t.Errorf("Body contains unredacted local path")
	}
	if strings.Contains(body, "secretpass") {
		t.Errorf("Body contains unredacted postgres password")
	}
	if strings.Contains(body, "secret_token_xyz") {
		t.Errorf("Body contains unredacted bearer token")
	}
	if !strings.Contains(body, "[REDACTED_AWS_KEY]") || !strings.Contains(body, "~/app") || !strings.Contains(body, "[REDACTED_PASSWORD]") {
		t.Errorf("Body missing expected redaction markers: %s", body)
	}
}

func TestBuildDraftDeepLinks(t *testing.T) {
	// 1. GitHub
	ghInput := DraftInput{
		Target: resolver.Target{
			CanonicalName: "cli-tool",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitHub,
				URL:      "https://github.com/org/cli-tool/issues",
			},
		},
		Title: "Fix race condition",
	}
	ghDraft, err := BuildDraft(ghInput)
	if err != nil {
		t.Fatalf("BuildDraft (GitHub) failed: %v", err)
	}
	if !strings.HasPrefix(ghDraft.SubmissionURL, "https://github.com/org/cli-tool/issues/new?title=") {
		t.Errorf("GitHub SubmissionURL unexpected: %s", ghDraft.SubmissionURL)
	}
	if !strings.Contains(ghDraft.SubmissionURL, url.QueryEscape("Fix race condition")) {
		t.Errorf("GitHub SubmissionURL missing escaped title: %s", ghDraft.SubmissionURL)
	}

	// 2. GitLab
	glInput := DraftInput{
		Target: resolver.Target{
			CanonicalName: "gl-tool",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitLab,
				URL:      "https://gitlab.com/org/gl-tool/issues",
			},
		},
		Title: "GitLab bug",
	}
	glDraft, err := BuildDraft(glInput)
	if err != nil {
		t.Fatalf("BuildDraft (GitLab) failed: %v", err)
	}
	if !strings.HasPrefix(glDraft.SubmissionURL, "https://gitlab.com/org/gl-tool/issues/new?issue%5Btitle%5D=") &&
		!strings.HasPrefix(glDraft.SubmissionURL, "https://gitlab.com/org/gl-tool/issues/new?issue[title]=") {
		t.Errorf("GitLab SubmissionURL unexpected: %s", glDraft.SubmissionURL)
	}

	// 3. Debbugs
	debInput := DraftInput{
		Target: resolver.Target{
			CanonicalName: "coreutils",
			LocalVersion:  "9.1",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolDebbugs,
				Email:    "bug-coreutils@gnu.org",
			},
		},
		Title:    "Segfault in ls",
		Severity: "grave",
	}
	debDraft, err := BuildDraft(debInput)
	if err != nil {
		t.Fatalf("BuildDraft (Debbugs) failed: %v", err)
	}
	if !strings.HasPrefix(debDraft.SubmissionURL, "mailto:bug-coreutils@gnu.org?subject=") {
		t.Errorf("Debbugs SubmissionURL unexpected: %s", debDraft.SubmissionURL)
	}
	if !strings.Contains(debDraft.DebbugsEmail, "To: bug-coreutils@gnu.org") {
		t.Errorf("Debbugs email missing To header: %s", debDraft.DebbugsEmail)
	}
	if !strings.Contains(debDraft.DebbugsEmail, "Package: coreutils\nVersion: 9.1\nSeverity: grave") {
		t.Errorf("Debbugs email missing pseudo-headers: %s", debDraft.DebbugsEmail)
	}
}

func TestBuildDraftEmptyTitleRejection(t *testing.T) {
	_, err := BuildDraft(DraftInput{Title: "   "})
	if err == nil {
		t.Fatal("expected error on empty title, got nil")
	}
}

func TestBuildDraftTitleNewlineSanitization(t *testing.T) {
	in := DraftInput{
		Target: resolver.Target{
			CanonicalName: "coreutils",
			LocalVersion:  "9.1",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolDebbugs,
				Email:    "bug-coreutils@gnu.org",
			},
		},
		Title: "Crash in ls\r\nBcc: attacker@evil.com\nPackage: hijacked",
	}

	draft, err := BuildDraft(in)
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}

	expectedTitle := "Crash in ls Bcc: attacker@evil.com Package: hijacked"
	if string(draft.Title) != expectedTitle {
		t.Errorf("draft.Title = %q, want %q", string(draft.Title), expectedTitle)
	}
	if strings.Contains(string(draft.Title), "\r") || strings.Contains(string(draft.Title), "\n") {
		t.Errorf("draft.Title contains newline characters: %q", string(draft.Title))
	}

	expectedSubject := "Subject: " + expectedTitle
	if !strings.Contains(draft.DebbugsEmail, expectedSubject) {
		t.Errorf("DebbugsEmail missing single-line subject: %s", draft.DebbugsEmail)
	}
	for _, line := range strings.Split(draft.DebbugsEmail, "\n") {
		if strings.HasPrefix(line, "Bcc:") {
			t.Errorf("DebbugsEmail contains injected Bcc header line: %q", line)
		}
	}
}

func TestDraftStoreSave(t *testing.T) {
	tempDir := t.TempDir()
	store := NewDraftStore(tempDir)

	draft, err := BuildDraft(DraftInput{
		Target: resolver.Target{CanonicalName: "ripgrep"},
		Title:  "Crash on large file",
	})
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}

	filePath, err := store.Save(draft)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	expectedPath := filepath.Join(tempDir, draft.ID+".json")
	if filePath != expectedPath {
		t.Errorf("filePath = %q, want %q", filePath, expectedPath)
	}

	// Verify file was written and can be decoded
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var loaded StagedDraft
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal saved draft failed: %v", err)
	}
	if loaded.ID != draft.ID || loaded.Title != draft.Title {
		t.Errorf("loaded %+v, want %+v", loaded, draft)
	}

	// Verify permissions on Unix/Linux systems
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file mode = %o, want 0600", perm)
	}
}

func TestBuildDraftWithGitHubFormTemplate(t *testing.T) {
	tmpl := &introspector.TemplateSchema{
		Name:        "Bug report",
		FileName:    "bug_report.yml",
		TitlePrefix: "[BUG]: ",
		Format:      introspector.FormatGitHubForm,
		Protocol:    resolver.ProtocolGitHub,
		Fields: []introspector.FieldSchema{
			{
				ID:       "what_happened",
				Label:    "What happened?",
				Type:     introspector.FieldTextarea,
				Required: true,
			},
			{
				ID:       "steps",
				Label:    "Steps to Reproduce",
				Type:     introspector.FieldTextarea,
				Required: true,
			},
			{
				ID:       "logs",
				Label:    "Relevant log output",
				Type:     introspector.FieldTextarea,
				Required: false,
			},
		},
	}

	in := DraftInput{
		Target: resolver.Target{
			CanonicalName: "my-cli",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitHub,
				URL:      "https://github.com/org/my-cli/issues",
			},
		},
		Title:            "segfault on start",
		Summary:          "Crashed with exit code 139",
		StepsToReproduce: "Run my-cli without args",
		Logs:             "panic: runtime error",
		Template:         tmpl,
	}

	draft, err := BuildDraft(in)
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}

	expectedTitle := "[BUG]: segfault on start"
	if string(draft.Title) != expectedTitle {
		t.Errorf("Title = %q, want %q", string(draft.Title), expectedTitle)
	}

	body := string(draft.MarkdownBody)
	if !strings.Contains(body, "### What happened?\n\nCrashed with exit code 139") {
		t.Errorf("MarkdownBody missing '### What happened?' section: %s", body)
	}
	if !strings.Contains(body, "### Steps to Reproduce\n\nRun my-cli without args") {
		t.Errorf("MarkdownBody missing '### Steps to Reproduce' section: %s", body)
	}
	if !strings.Contains(body, "### Relevant log output\n\npanic: runtime error") {
		t.Errorf("MarkdownBody missing '### Relevant log output' section: %s", body)
	}

	if !strings.Contains(draft.SubmissionURL, "template="+url.QueryEscape("bug_report.yml")) {
		t.Errorf("SubmissionURL missing template query param: %s", draft.SubmissionURL)
	}
	if !strings.Contains(draft.SubmissionURL, "what_happened="+url.QueryEscape("Crashed with exit code 139")) {
		t.Errorf("SubmissionURL missing what_happened query param: %s", draft.SubmissionURL)
	}
	if !strings.Contains(draft.SubmissionURL, "steps="+url.QueryEscape("Run my-cli without args")) {
		t.Errorf("SubmissionURL missing steps query param: %s", draft.SubmissionURL)
	}
	if !strings.Contains(draft.SubmissionURL, "logs="+url.QueryEscape("panic: runtime error")) {
		t.Errorf("SubmissionURL missing logs query param: %s", draft.SubmissionURL)
	}
	if draft.Template == nil || draft.Template.FileName != "bug_report.yml" {
		t.Errorf("draft.Template not preserved: %+v", draft.Template)
	}
}

func TestBuildDraftWithBugzillaSchema(t *testing.T) {
	tmpl := &introspector.TemplateSchema{
		Name:     "Bugzilla Schema",
		Format:   introspector.FormatBugzillaSchema,
		Protocol: resolver.ProtocolBugzilla,
		Fields: []introspector.FieldSchema{
			{
				ID:       "product",
				Label:    "Product",
				Type:     introspector.FieldDropdown,
				Required: true,
				Value:    "Core",
			},
			{
				ID:       "component",
				Label:    "Component",
				Type:     introspector.FieldDropdown,
				Required: true,
				Value:    "Networking",
			},
			{
				ID:    "severity",
				Label: "Severity",
				Type:  introspector.FieldDropdown,
				Value: "critical",
			},
		},
	}

	in := DraftInput{
		Target: resolver.Target{
			CanonicalName: "core-net",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolBugzilla,
				URL:      "https://bugzilla.example.com",
			},
		},
		Title:    "Connection dropped unexpectedly",
		Summary:  "Socket reset after handshake",
		Severity: "critical",
		Template: tmpl,
	}

	draft, err := BuildDraft(in)
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}

	if !strings.HasPrefix(draft.SubmissionURL, "https://bugzilla.example.com/enter_bug.cgi?") {
		t.Errorf("Bugzilla SubmissionURL unexpected base: %s", draft.SubmissionURL)
	}
	if !strings.Contains(draft.SubmissionURL, "short_desc="+url.QueryEscape("Connection dropped unexpectedly")) {
		t.Errorf("SubmissionURL missing short_desc: %s", draft.SubmissionURL)
	}
	if !strings.Contains(draft.SubmissionURL, "bug_severity="+url.QueryEscape("critical")) {
		t.Errorf("SubmissionURL missing bug_severity: %s", draft.SubmissionURL)
	}
	if !strings.Contains(draft.SubmissionURL, "product="+url.QueryEscape("Core")) {
		t.Errorf("SubmissionURL missing product: %s", draft.SubmissionURL)
	}
	if !strings.Contains(draft.SubmissionURL, "component="+url.QueryEscape("Networking")) {
		t.Errorf("SubmissionURL missing component: %s", draft.SubmissionURL)
	}
}

func TestDraftStoreListGetDelete(t *testing.T) {
	tempDir := t.TempDir()
	store := NewDraftStore(tempDir)

	d1, err := BuildDraft(DraftInput{
		Target: resolver.Target{CanonicalName: "pkg-a"},
		Title:  "Bug A",
	})
	if err != nil {
		t.Fatalf("BuildDraft A failed: %v", err)
	}
	d2, err := BuildDraft(DraftInput{
		Target: resolver.Target{CanonicalName: "pkg-b"},
		Title:  "Bug B",
	})
	if err != nil {
		t.Fatalf("BuildDraft B failed: %v", err)
	}

	if _, err := store.Save(d1); err != nil {
		t.Fatalf("Save d1 failed: %v", err)
	}
	if _, err := store.Save(d2); err != nil {
		t.Fatalf("Save d2 failed: %v", err)
	}

	// 1. List
	drafts, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(drafts) != 2 {
		t.Fatalf("List returned %d drafts, want 2", len(drafts))
	}

	// 2. Get
	loaded, err := store.Get(d1.ID)
	if err != nil {
		t.Fatalf("Get d1 failed: %v", err)
	}
	if loaded.ID != d1.ID || string(loaded.Title) != string(d1.Title) {
		t.Errorf("loaded draft = %+v, want %+v", loaded, d1)
	}

	// Get non-existent
	_, err = store.Get("nonexistent-id")
	if err == nil {
		t.Errorf("expected error getting nonexistent draft, got nil")
	}

	// 3. Delete
	if err := store.Delete(d1.ID); err != nil {
		t.Fatalf("Delete d1 failed: %v", err)
	}
	remaining, err := store.List()
	if err != nil {
		t.Fatalf("List after delete failed: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("List after delete returned %d drafts, want 1", len(remaining))
	}
	if remaining[0].ID != d2.ID {
		t.Errorf("remaining draft = %s, want %s", remaining[0].ID, d2.ID)
	}
}

func TestDraftStoreIDValidation(t *testing.T) {
	tempDir := t.TempDir()
	store := NewDraftStore(tempDir)

	invalidIDs := []string{
		"",
		"..",
		"../evil",
		"evil/../secret",
		"a/b",
		"a\\b",
		"draft with spaces",
		"draft*special",
		"id;rm -rf",
	}

	for _, id := range invalidIDs {
		if IsValidDraftID(id) {
			t.Errorf("IsValidDraftID(%q) = true, want false", id)
		}
		if _, err := store.Get(id); err == nil {
			t.Errorf("store.Get(%q) succeeded, expected error", id)
		}
		if err := store.Delete(id); err == nil {
			t.Errorf("store.Delete(%q) succeeded, expected error", id)
		}
	}

	validIDs := []string{
		"abc123DEF",
		"draft-1",
		"draft_2",
		"a-b_c-123",
	}

	for _, id := range validIDs {
		if !IsValidDraftID(id) {
			t.Errorf("IsValidDraftID(%q) = false, want true", id)
		}
	}
}

func TestBuildDraftDuplicates(t *testing.T) {
	in := DraftInput{
		Target: resolver.Target{
			CanonicalName: "my-app",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitHub,
				URL:      "https://github.com/org/my-app/issues",
			},
		},
		Title: "Null pointer exception on startup",
		Duplicates: []dedup.ExistingIssue{
			{
				ID:    "123",
				Title: "Panic: null pointer dereference during startup",
				URL:   "https://github.com/org/my-app/issues/123",
				State: "open",
				Score: 0.75,
			},
		},
	}

	draft, err := BuildDraft(in)
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}

	if len(draft.PotentialDuplicates) != 1 {
		t.Fatalf("len(PotentialDuplicates) = %d, want 1", len(draft.PotentialDuplicates))
	}
	dup := draft.PotentialDuplicates[0]
	if dup.ID != "123" || dup.Score != 0.75 || dup.State != "open" {
		t.Errorf("unexpected duplicate: %+v", dup)
	}
}

func TestBuildDraftQualityReport(t *testing.T) {
	in := DraftInput{
		Target: resolver.Target{
			CanonicalName: "my-app",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitHub,
				URL:      "https://github.com/org/my-app/issues",
			},
		},
		Title:            "Memory leak in streaming worker",
		Summary:          "Memory usage grows unbounded during long-lived websocket connections.",
		StepsToReproduce: "1. Open connection.\n2. Stream 100k messages.\n3. Observe memory growth.",
		Logs:             "FATAL: heap memory exceeded limit",
	}

	draft, err := BuildDraft(in)
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}
	if !draft.Quality.Passed {
		t.Errorf("expected clean draft to pass quality check, got issues: %v", draft.Quality.Issues)
	}
	if draft.Quality.Score != 100 {
		t.Errorf("expected Score=100, got %d", draft.Quality.Score)
	}
}

func TestBuildDraftWithVerificationProof(t *testing.T) {
	proof := &verifier.VerificationProof{
		Command:        "go test -run TestCrash ./...",
		Reproduced:     true,
		ExitCode:       1,
		DurationMs:     42,
		ScrubbedOutput: "--- FAIL: TestCrash (0.01s)\npanic: nil pointer [REDACTED_PASSWORD]",
		ProofDigest:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	in := DraftInput{
		Target: resolver.Target{
			CanonicalName: "core-worker",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitHub,
				URL:      "https://github.com/org/core-worker/issues",
			},
		},
		Title:            "Panic in crash handler during test execution",
		Summary:          "A nil pointer dereference is triggered when running the test suite.",
		StepsToReproduce: "1. Run go test -run TestCrash\n2. Observe panic output",
		Verification:     proof,
	}

	draft, err := BuildDraft(in)
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}

	if draft.Verification == nil {
		t.Fatalf("expected Verification to be attached to staged draft")
	}
	if !draft.Verification.Reproduced {
		t.Errorf("expected Reproduced=true")
	}

	body := string(draft.MarkdownBody)
	if !strings.Contains(body, "## Verified Reproduction") {
		t.Errorf("expected '## Verified Reproduction' header in markdown body: %s", body)
	}
	if !strings.Contains(body, "- **Reproduced:** true (exit code 1, 42ms)") {
		t.Errorf("expected reproduced status line in body: %s", body)
	}
	if !strings.Contains(body, "- **Command:** `go test -run TestCrash ./...`") {
		t.Errorf("expected command in body: %s", body)
	}
	if !strings.Contains(body, "- **Proof Digest:** `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`") {
		t.Errorf("expected proof digest in body: %s", body)
	}
	// Verify that verified logs populated the logs section when in.Logs was empty
	if !strings.Contains(body, "panic: nil pointer [REDACTED_PASSWORD]") {
		t.Errorf("expected verification scrubbed output to populate logs section: %s", body)
	}
}

func TestBuildDraftWithTelemetry(t *testing.T) {
	telem := &telemetry.SystemTelemetry{
		OS:            "linux",
		Arch:          "amd64",
		KernelVersion: "6.6.0-generic",
		CPUModel:      "AMD Ryzen 9 5900X",
		NumCPU:        12,
		GPUs:          []string{"NVIDIA GeForce RTX 3080"},
		DesktopEnv:    "GNOME",
		DisplayServer: "wayland",
	}

	in := DraftInput{
		Target: resolver.Target{
			CanonicalName: "blender",
			LocalVersion:  "4.2.0",
			Tracker: resolver.TrackerInfo{
				Protocol: resolver.ProtocolGitea,
				URL:      "https://projects.blender.org/blender/blender/issues",
			},
		},
		Title:            "GPU rendering crash on startup",
		Summary:          "Blender crashes immediately when switching viewport to rendered mode.",
		StepsToReproduce: "1. Launch blender\n2. Press Z and select Rendered",
		Telemetry:        telem,
	}

	draft, err := BuildDraft(in)
	if err != nil {
		t.Fatalf("BuildDraft failed: %v", err)
	}

	if draft.Telemetry == nil {
		t.Fatalf("expected Telemetry to be attached to staged draft")
	}
	if draft.Telemetry.CPUModel != "AMD Ryzen 9 5900X" {
		t.Errorf("expected CPUModel %q, got %q", "AMD Ryzen 9 5900X", draft.Telemetry.CPUModel)
	}

	body := string(draft.MarkdownBody)
	if !strings.Contains(body, "## Environment") {
		t.Errorf("expected '## Environment' in markdown body: %s", body)
	}
	if !strings.Contains(body, "- **GPU**: NVIDIA GeForce RTX 3080") {
		t.Errorf("expected GPU line in environment: %s", body)
	}
	if !strings.Contains(body, "- **Desktop**: GNOME") {
		t.Errorf("expected Desktop line in environment: %s", body)
	}
	if !strings.Contains(body, "- **Display Server**: wayland") {
		t.Errorf("expected Display Server line in environment: %s", body)
	}
}
