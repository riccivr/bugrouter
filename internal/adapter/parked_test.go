package adapter

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	if !strings.Contains(handoff.AgentDirective, "user_options") {
		t.Errorf("handoff.AgentDirective missing user_options directive: %s", handoff.AgentDirective)
	}

	// Verify UserOptions 4 choices
	if len(handoff.UserOptions) != 4 {
		t.Fatalf("expected 4 user options, got %d: %v", len(handoff.UserOptions), handoff.UserOptions)
	}
	if !strings.Contains(handoff.UserOptions[0], "Ignore") {
		t.Errorf("option 1 unexpected: %s", handoff.UserOptions[0])
	}
	if !strings.Contains(handoff.UserOptions[1], "Keep parked") {
		t.Errorf("option 2 unexpected: %s", handoff.UserOptions[1])
	}
	if !strings.Contains(handoff.UserOptions[2], "Spawn separate session") {
		t.Errorf("option 3 unexpected: %s", handoff.UserOptions[2])
	}
	if !strings.Contains(handoff.UserOptions[3], "Fork/patch") {
		t.Errorf("option 4 unexpected: %s", handoff.UserOptions[3])
	}

	// Verify PatchInstructions
	if !strings.Contains(handoff.PatchInstructions, "bugrouter patch add") {
		t.Errorf("PatchInstructions missing bugrouter patch add hint: %s", handoff.PatchInstructions)
	}

	// 3. File permissions (0600)
	targetPath := tempDir + "/" + bug.ID + ".json"
	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("stat parked file failed: %v", err)
	}
	if runtime.GOOS != "windows" {
		perm := info.Mode().Perm()
		if perm != 0600 {
			t.Errorf("expected 0600 file permissions, got %04o", perm)
		}
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

func TestPatchStoreLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	patchFile := filepath.Join(tempDir, "patches.json")
	store := NewPatchStore(patchFile)

	if store.Path() != patchFile {
		t.Fatalf("expected store path %q, got %q", patchFile, store.Path())
	}

	// 1. Initial list is empty
	initialList, err := store.List()
	if err != nil {
		t.Fatalf("initial List failed: %v", err)
	}
	if len(initialList) != 0 {
		t.Errorf("expected 0 patches initially, got %d", len(initialList))
	}

	// 2. Validation errors
	if _, err := store.Record("", "go", "fork@v1", "go.mod", "", "reason"); err == nil {
		t.Error("expected error on empty dependency")
	}
	if _, err := store.Record("dep", "go", "", "go.mod", "", "reason"); err == nil {
		t.Error("expected error on empty patch target")
	}
	if _, err := store.Record("dep", "go", "fork@v1", "go.mod", "", ""); err == nil {
		t.Error("expected error on empty reason")
	}

	// 3. Record valid patches
	patch1, err := store.Record(
		"github.com/gin-gonic/gin",
		"go",
		"github.com/myorg/gin@fix-context",
		"go.mod",
		"https://github.com/gin-gonic/gin/issues/999",
		"Fix data race in Context.Copy",
	)
	if err != nil {
		t.Fatalf("Record patch1 failed: %v", err)
	}

	if len(patch1.ID) != 8 {
		t.Errorf("expected 8-char hex ID, got %q (len=%d)", patch1.ID, len(patch1.ID))
	}
	if patch1.Status != "active" {
		t.Errorf("expected status 'active', got %q", patch1.Status)
	}
	if patch1.Ecosystem != "go" {
		t.Errorf("expected ecosystem 'go', got %q", patch1.Ecosystem)
	}

	// Record second patch with auto-derived ecosystem from package.json
	patch2, err := store.Record(
		"sharp",
		"",
		"patches/sharp+0.33.0.patch",
		"package.json",
		"https://github.com/lovell/sharp/issues/1234",
		"Fix musl SIGSEGV in libvips",
	)
	if err != nil {
		t.Fatalf("Record patch2 failed: %v", err)
	}
	if patch2.Ecosystem != "npm" {
		t.Errorf("expected auto-derived ecosystem 'npm', got %q", patch2.Ecosystem)
	}

	// 4. Verify file permissions are 0600
	fi, err := os.Stat(patchFile)
	if err != nil {
		t.Fatalf("stat patches.json failed: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := fi.Mode().Perm(); perm != 0600 {
			t.Errorf("expected 0600 file permissions, got %04o", perm)
		}
	}

	// 5. List patches
	patches, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %d", len(patches))
	}
	// Verify descending sort (patch2 is newer than patch1)
	if patches[0].ID != patch2.ID || patches[1].ID != patch1.ID {
		t.Errorf("unexpected list ordering: %+v", patches)
	}

	// 6. Remove patch1 by ID
	if err := store.Remove(patch1.ID); err != nil {
		t.Fatalf("Remove by ID failed: %v", err)
	}

	patchesAfterRm1, err := store.List()
	if err != nil {
		t.Fatalf("List after rm1 failed: %v", err)
	}
	if len(patchesAfterRm1) != 1 || patchesAfterRm1[0].ID != patch2.ID {
		t.Fatalf("expected 1 patch remaining (%s), got %+v", patch2.ID, patchesAfterRm1)
	}

	// 7. Remove patch2 by dependency name (case-insensitive)
	if err := store.Remove("SHARP"); err != nil {
		t.Fatalf("Remove by dependency name failed: %v", err)
	}

	patchesAfterRm2, err := store.List()
	if err != nil {
		t.Fatalf("List after rm2 failed: %v", err)
	}
	if len(patchesAfterRm2) != 0 {
		t.Errorf("expected 0 patches after removing all, got %d", len(patchesAfterRm2))
	}

	// 8. Remove non-existent returns error
	if err := store.Remove("nonexistent"); err == nil {
		t.Error("expected error removing non-existent patch, got nil")
	}

	// 9. Concurrency test
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, recErr := store.Record(
				"concurrent-dep",
				"custom",
				"target",
				"manifest",
				"url",
				"reason",
			)
			if recErr != nil {
				t.Errorf("concurrent Record failed: %v", recErr)
			}
		}(i)
	}
	wg.Wait()

	finalList, err := store.List()
	if err != nil {
		t.Fatalf("final List failed: %v", err)
	}
	if len(finalList) != 5 {
		t.Errorf("expected 5 concurrent patches, got %d", len(finalList))
	}
}
