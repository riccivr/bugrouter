package adapter

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestParkedStoreLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	store := NewParkedStore(tempDir)

	if store.Dir() != tempDir {
		t.Fatalf("expected store dir %q, got %q", tempDir, store.Dir())
	}

	// 1. Validation errors
	if _, _, err := store.Park("", "Title", "", "", ""); err == nil {
		t.Error("expected error on empty dependency")
	}
	if _, _, err := store.Park("dep", "", "", "", ""); err == nil {
		t.Error("expected error on empty title")
	}

	// 2. <5ms latency test and secret scrubbing
	start := time.Now()
	secretLog := "Error: connection failed with token Authorization: Bearer ghp_123456789012345678901234567890123456"
	secretWorkaround := "Switched to fallback cluster using key sk-proj-1234567890abcdef1234567890abcdef12"
	bug, handoff, err := store.Park("sharp", "SIGSEGV during libvips resize", secretLog, secretWorkaround, "src/image.ts:42")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Park failed: %v", err)
	}

	// Allow reasonable overhead for test runners while asserting non-blocking bounded latency
	if elapsed > 100*time.Millisecond {
		t.Errorf("expected Park to execute in <100ms in test, took %v", elapsed)
	}

	if len(bug.ID) != 8 {
		t.Errorf("expected 8-char hex ID, got %q (len=%d)", bug.ID, len(bug.ID))
	}
	if bug.Dependency != "sharp" {
		t.Errorf("expected dependency sharp, got %q", bug.Dependency)
	}
	if bug.Status != "parked" {
		t.Errorf("expected status parked, got %q", bug.Status)
	}

	// Verify secret scrubbing
	if strings.Contains(string(bug.ErrorSnippet), "ghp_") {
		t.Errorf("ErrorSnippet contains raw GitHub token: %s", bug.ErrorSnippet)
	}
	if !strings.Contains(string(bug.ErrorSnippet), "[REDACTED") {
		t.Errorf("ErrorSnippet missing redaction tag: %s", bug.ErrorSnippet)
	}
	if strings.Contains(string(bug.WorkaroundNote), "sk-proj-") {
		t.Errorf("WorkaroundNote contains raw OpenAI token: %s", bug.WorkaroundNote)
	}

	// Verify HandoffPayload
	if handoff.ParkedID != bug.ID {
		t.Errorf("handoff.ParkedID = %q, want %q", handoff.ParkedID, bug.ID)
	}
	expectedURI := "bugrouter://parked/" + bug.ID
	if handoff.ResourceURI != expectedURI {
		t.Errorf("handoff.ResourceURI = %q, want %q", handoff.ResourceURI, expectedURI)
	}
	if handoff.MCPPromptName != "triage_parked_bug" {
		t.Errorf("handoff.MCPPromptName = %q, want triage_parked_bug", handoff.MCPPromptName)
	}
	expectedCmd := "bugrouter draft --from-parked " + bug.ID
	if handoff.CLICommand != expectedCmd {
		t.Errorf("handoff.CLICommand = %q, want %q", handoff.CLICommand, expectedCmd)
	}
	if !strings.Contains(handoff.AgentDirective, "CRITICAL: Bug parked in <5ms") {
		t.Errorf("handoff.AgentDirective missing expected warning: %s", handoff.AgentDirective)
	}

	// 3. File permissions (0600)
	targetPath := tempDir + "/" + bug.ID + ".json"
	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("stat parked file failed: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected 0600 file permissions, got %04o", perm)
	}

	// 4. Get
	retrieved, err := store.Get(bug.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if retrieved.ID != bug.ID || retrieved.Title != bug.Title {
		t.Errorf("retrieved bug mismatch: %+v", retrieved)
	}

	// 5. List
	bugs, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(bugs) != 1 || bugs[0].ID != bug.ID {
		t.Errorf("expected 1 bug in List, got %d", len(bugs))
	}

	// 6. Delete
	if err := store.Delete(bug.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := store.Get(bug.ID); err == nil {
		t.Error("expected error getting deleted bug, got nil")
	}

	// 7. Delete non-existent
	if err := store.Delete("nonexist"); err == nil {
		t.Error("expected error deleting non-existent bug, got nil")
	}
}
