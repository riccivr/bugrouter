package adapter

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/riccivr/bugrouter/internal/resolver"
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
