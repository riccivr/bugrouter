package adapter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScanGoModPatches(t *testing.T) {
	tempDir := t.TempDir()
	goModContent := `module github.com/test/project

go 1.24

require (
	golang.org/x/crypto v0.10.0
	github.com/gin-gonic/gin v1.9.0
	example.com/foo v1.0.0
)

replace golang.org/x/crypto => ./crypto-fork // single line replacement

replace (
	github.com/gin-gonic/gin v1.9.0 => github.com/myorg/gin v1.9.1-patch
	example.com/foo => ../foo
)
`
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte(goModContent), 0600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	patches, err := ScanWorkspacePatches(tempDir)
	if err != nil {
		t.Fatalf("ScanWorkspacePatches failed: %v", err)
	}

	expected := []struct {
		dep    string
		target string
	}{
		{dep: "example.com/foo", target: "../foo"},
		{dep: "github.com/gin-gonic/gin", target: "github.com/myorg/gin v1.9.1-patch"},
		{dep: "golang.org/x/crypto", target: "./crypto-fork"},
	}

	if len(patches) != len(expected) {
		t.Fatalf("expected %d patches, got %d: %+v", len(expected), len(patches), patches)
	}

	for i, exp := range expected {
		if patches[i].Dependency != exp.dep {
			t.Errorf("[%d] expected dep %q, got %q", i, exp.dep, patches[i].Dependency)
		}
		if patches[i].PatchTarget != exp.target {
			t.Errorf("[%d] expected target %q, got %q", i, exp.target, patches[i].PatchTarget)
		}
		if patches[i].Ecosystem != "go" {
			t.Errorf("[%d] expected ecosystem 'go', got %q", i, patches[i].Ecosystem)
		}
		if patches[i].ManifestFile != "go.mod" {
			t.Errorf("[%d] expected manifest 'go.mod', got %q", i, patches[i].ManifestFile)
		}
	}
}

func TestScanPackageJSONAndPatchesDir(t *testing.T) {
	tempDir := t.TempDir()
	pkgJSONContent := `{
  "name": "test-node-project",
  "dependencies": {
    "sharp": "patch:sharp@0.33.0#./patches/sharp.patch",
    "local-pkg": "file:../local-pkg",
    "git-fork": "git+https://github.com/test/fork.git#v1.0.0",
    "normal-dep": "^1.0.0"
  },
  "devDependencies": {
    "linked-lib": "link:../../libs/linked",
    "normal-dev": "^2.0.0"
  },
  "overrides": {
    "glob": "10.0.0-override"
  },
  "resolutions": {
    "lodash": "4.17.21-res"
  }
}`
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(pkgJSONContent), 0600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	patchesDir := filepath.Join(tempDir, "patches")
	if err := os.MkdirAll(patchesDir, 0700); err != nil {
		t.Fatalf("mkdir patches: %v", err)
	}

	patchFiles := []string{
		"sharp+0.33.0.patch",
		"@types+node+20.1.0.patch",
	}
	for _, pf := range patchFiles {
		if err := os.WriteFile(filepath.Join(patchesDir, pf), []byte("diff --git a/index.js b/index.js\n"), 0600); err != nil {
			t.Fatalf("write patch file %s: %v", pf, err)
		}
	}

	patches, err := ScanWorkspacePatches(tempDir)
	if err != nil {
		t.Fatalf("ScanWorkspacePatches failed: %v", err)
	}

	depMap := make(map[string]DependencyPatch)
	for _, p := range patches {
		depMap[p.Dependency] = p
	}

	expectedDeps := []struct {
		dep    string
		target string
	}{
		{dep: "@types/node", target: "patches/@types+node+20.1.0.patch"},
		{dep: "git-fork", target: "git+https://github.com/test/fork.git#v1.0.0"},
		{dep: "glob", target: "10.0.0-override"},
		{dep: "linked-lib", target: "link:../../libs/linked"},
		{dep: "local-pkg", target: "file:../local-pkg"},
		{dep: "lodash", target: "4.17.21-res"},
		{dep: "sharp", target: "patch:sharp@0.33.0#./patches/sharp.patch"},
	}

	for _, exp := range expectedDeps {
		p, found := depMap[exp.dep]
		if !found {
			t.Errorf("missing expected dependency %q in scanned patches", exp.dep)
			continue
		}
		if p.Ecosystem != "npm" {
			t.Errorf("dep %q: expected ecosystem 'npm', got %q", exp.dep, p.Ecosystem)
		}
		if p.ManifestFile != "package.json" {
			t.Errorf("dep %q: expected manifest 'package.json', got %q", exp.dep, p.ManifestFile)
		}
	}
}

func TestScanCargoTomlPatches(t *testing.T) {
	tempDir := t.TempDir()
	cargoContent := `[package]
name = "test-cargo-project"
version = "0.1.0"

[dependencies]
tokio = "1.0"
serde = "1.0"

[patch.crates-io]
tokio = { path = "../tokio-fork" }
serde = { git = "https://github.com/myfork/serde.git", branch = "patch" }

[patch.crates-io.hyper]
path = "../hyper-fork"
`
	if err := os.WriteFile(filepath.Join(tempDir, "Cargo.toml"), []byte(cargoContent), 0600); err != nil {
		t.Fatalf("write Cargo.toml: %v", err)
	}

	patches, err := ScanWorkspacePatches(tempDir)
	if err != nil {
		t.Fatalf("ScanWorkspacePatches failed: %v", err)
	}

	expected := []struct {
		dep    string
		target string
	}{
		{dep: "hyper", target: "../hyper-fork"},
		{dep: "serde", target: "https://github.com/myfork/serde.git"},
		{dep: "tokio", target: "../tokio-fork"},
	}

	if len(patches) != len(expected) {
		t.Fatalf("expected %d patches, got %d: %+v", len(expected), len(patches), patches)
	}

	for i, exp := range expected {
		if patches[i].Dependency != exp.dep {
			t.Errorf("[%d] expected dep %q, got %q", i, exp.dep, patches[i].Dependency)
		}
		if patches[i].PatchTarget != exp.target {
			t.Errorf("[%d] expected target %q, got %q", i, exp.target, patches[i].PatchTarget)
		}
		if patches[i].Ecosystem != "cargo" {
			t.Errorf("[%d] expected ecosystem 'cargo', got %q", i, patches[i].Ecosystem)
		}
		if patches[i].ManifestFile != "Cargo.toml" {
			t.Errorf("[%d] expected manifest 'Cargo.toml', got %q", i, patches[i].ManifestFile)
		}
	}
}

func TestScanPyprojectToml(t *testing.T) {
	tempDir := t.TempDir()
	pyContent := `[tool.poetry]
name = "my-python-app"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
requests = { path = "../requests-fork" }
urllib3 = { git = "https://github.com/myfork/urllib3.git" }
normal-dep = "^2.0.0"
`
	if err := os.WriteFile(filepath.Join(tempDir, "pyproject.toml"), []byte(pyContent), 0600); err != nil {
		t.Fatalf("write pyproject.toml: %v", err)
	}

	patches, err := ScanWorkspacePatches(tempDir)
	if err != nil {
		t.Fatalf("ScanWorkspacePatches failed: %v", err)
	}

	if len(patches) != 2 {
		t.Fatalf("expected 2 python patches, got %d: %+v", len(patches), patches)
	}

	if patches[0].Dependency != "requests" || patches[0].PatchTarget != "../requests-fork" {
		t.Errorf("unexpected patch[0]: %+v", patches[0])
	}
	if patches[1].Dependency != "urllib3" || patches[1].PatchTarget != "https://github.com/myfork/urllib3.git" {
		t.Errorf("unexpected patch[1]: %+v", patches[1])
	}
}

func TestScanWorkspaceEmptyAndInvalid(t *testing.T) {
	tempDir := t.TempDir()

	// Empty directory should return empty slice and nil error
	patches, err := ScanWorkspacePatches(tempDir)
	if err != nil {
		t.Fatalf("ScanWorkspacePatches on empty dir failed: %v", err)
	}
	if len(patches) != 0 {
		t.Errorf("expected 0 patches, got %d", len(patches))
	}

	// Non-existent directory should return error
	_, err = ScanWorkspacePatches(filepath.Join(tempDir, "non_existent"))
	if err == nil {
		t.Errorf("expected error for non-existent root dir, got nil")
	}
}

func TestScanWorkspaceDeduplication(t *testing.T) {
	tempDir := t.TempDir()
	// package.json with identical dep in dependencies and devDependencies
	pkgJSONContent := `{
  "dependencies": {
    "my-lib": "file:../my-lib"
  },
  "devDependencies": {
    "my-lib": "file:../my-lib"
  }
}`
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(pkgJSONContent), 0600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	patches, err := ScanWorkspacePatches(tempDir)
	if err != nil {
		t.Fatalf("ScanWorkspacePatches failed: %v", err)
	}

	if len(patches) != 1 {
		t.Fatalf("expected exactly 1 deduplicated patch, got %d: %+v", len(patches), patches)
	}
}

func TestPatchStoreSyncWorkspaceIdempotency(t *testing.T) {
	tempDir := t.TempDir()
	workspaceDir := filepath.Join(tempDir, "workspace")
	if err := os.MkdirAll(workspaceDir, 0700); err != nil {
		t.Fatalf("mkdir workspace: %v", err)
	}

	goModContent := `module github.com/test/mod

go 1.24

replace example.com/pkg => ../pkg
`
	if err := os.WriteFile(filepath.Join(workspaceDir, "go.mod"), []byte(goModContent), 0600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	pkgJSONContent := `{
  "dependencies": {
    "mypkg": "file:../mypkg"
  }
}`
	if err := os.WriteFile(filepath.Join(workspaceDir, "package.json"), []byte(pkgJSONContent), 0600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	cargoContent := `[patch.crates-io]
mycrate = { path = "../mycrate" }
`
	if err := os.WriteFile(filepath.Join(workspaceDir, "Cargo.toml"), []byte(cargoContent), 0600); err != nil {
		t.Fatalf("write Cargo.toml: %v", err)
	}

	storePath := filepath.Join(tempDir, "patches.json")
	store := NewPatchStore(storePath)

	// First sync: should discover and add all 3 patches
	newlyAdded1, err := store.SyncWorkspace(workspaceDir)
	if err != nil {
		t.Fatalf("first SyncWorkspace failed: %v", err)
	}

	if len(newlyAdded1) != 3 {
		t.Fatalf("expected 3 newly added patches on first sync, got %d: %+v", len(newlyAdded1), newlyAdded1)
	}

	// Verify persistence in store
	list1, err := store.List()
	if err != nil {
		t.Fatalf("store.List() failed: %v", err)
	}
	if len(list1) != 3 {
		t.Fatalf("expected 3 patches in store, got %d", len(list1))
	}

	// Read file modification content
	data1, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read patches.json: %v", err)
	}

	// Second sync: should be strictly idempotent (0 newly added, no duplicates)
	newlyAdded2, err := store.SyncWorkspace(workspaceDir)
	if err != nil {
		t.Fatalf("second SyncWorkspace failed: %v", err)
	}

	if len(newlyAdded2) != 0 {
		t.Fatalf("expected 0 newly added patches on second sync, got %d: %+v", len(newlyAdded2), newlyAdded2)
	}

	list2, err := store.List()
	if err != nil {
		t.Fatalf("store.List() after second sync failed: %v", err)
	}
	if len(list2) != 3 {
		t.Fatalf("expected still 3 patches in store after second sync, got %d", len(list2))
	}

	data2, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read patches.json after second sync: %v", err)
	}

	var parsed1, parsed2 []DependencyPatch
	if err := json.Unmarshal(data1, &parsed1); err != nil {
		t.Fatalf("unmarshal data1: %v", err)
	}
	if err := json.Unmarshal(data2, &parsed2); err != nil {
		t.Fatalf("unmarshal data2: %v", err)
	}
	if !reflect.DeepEqual(parsed1, parsed2) {
		t.Errorf("store file content changed during idempotent sync")
	}
}
