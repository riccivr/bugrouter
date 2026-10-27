package resolver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceProbeNodeModules(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Unscoped package with string bugs and repository
	pkg1Dir := filepath.Join(tempDir, "node_modules", "remix")
	if err := os.MkdirAll(pkg1Dir, 0755); err != nil {
		t.Fatalf("mkdir remix: %v", err)
	}
	pkg1JSON := `{
		"name": "remix",
		"version": "2.8.1",
		"bugs": "https://github.com/remix-run/remix/issues",
		"repository": "https://github.com/remix-run/remix.git"
	}`
	if err := os.WriteFile(filepath.Join(pkg1Dir, "package.json"), []byte(pkg1JSON), 0644); err != nil {
		t.Fatalf("write remix package.json: %v", err)
	}

	// 2. Unscoped package with object bugs and repository
	pkg2Dir := filepath.Join(tempDir, "node_modules", "sharp")
	if err := os.MkdirAll(pkg2Dir, 0755); err != nil {
		t.Fatalf("mkdir sharp: %v", err)
	}
	pkg2JSON := `{
		"name": "sharp",
		"version": "0.33.2",
		"bugs": {
			"url": "https://github.com/lovell/sharp/issues",
			"email": "bugs@sharp.pixel"
		},
		"repository": {
			"type": "git",
			"url": "git+https://github.com/lovell/sharp.git"
		}
	}`
	if err := os.WriteFile(filepath.Join(pkg2Dir, "package.json"), []byte(pkg2JSON), 0644); err != nil {
		t.Fatalf("write sharp package.json: %v", err)
	}

	// 3. Scoped package
	pkg3Dir := filepath.Join(tempDir, "node_modules", "@remix-run", "node")
	if err := os.MkdirAll(pkg3Dir, 0755); err != nil {
		t.Fatalf("mkdir scoped package: %v", err)
	}
	pkg3JSON := `{
		"name": "@remix-run/node",
		"version": "2.8.1",
		"bugs": "https://github.com/remix-run/remix/issues",
		"repository": "https://github.com/remix-run/remix"
	}`
	if err := os.WriteFile(filepath.Join(pkg3Dir, "package.json"), []byte(pkg3JSON), 0644); err != nil {
		t.Fatalf("write scoped package.json: %v", err)
	}

	probe := NewWorkspaceProbe(tempDir)

	// Test remix
	t1, err := probe.Resolve(context.Background(), "remix")
	if err != nil {
		t.Fatalf("resolve remix: %v", err)
	}
	if t1.CanonicalName != "remix" {
		t.Errorf("CanonicalName = %q, want remix", t1.CanonicalName)
	}
	if t1.LocalVersion != "2.8.1" {
		t.Errorf("LocalVersion = %q, want 2.8.1", t1.LocalVersion)
	}
	if t1.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", t1.Tracker.Protocol)
	}

	// Test sharp
	t2, err := probe.Resolve(context.Background(), "sharp")
	if err != nil {
		t.Fatalf("resolve sharp: %v", err)
	}
	if t2.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", t2.Tracker.Protocol)
	}
	if t2.Tracker.Email != "bugs@sharp.pixel" {
		t.Errorf("Email = %q, want bugs@sharp.pixel", t2.Tracker.Email)
	}

	// Test scoped package
	t3, err := probe.Resolve(context.Background(), "@remix-run/node")
	if err != nil {
		t.Fatalf("resolve @remix-run/node: %v", err)
	}
	if t3.CanonicalName != "@remix-run/node" {
		t.Errorf("CanonicalName = %q, want @remix-run/node", t3.CanonicalName)
	}
}

func TestWorkspaceProbeGoMod(t *testing.T) {
	tempDir := t.TempDir()

	goModContent := `module testworkspace

go 1.22

require (
	github.com/BurntSushi/ripgrep v1.4.1
	gitlab.com/gnachman/iterm2 v0.1.0 // indirect
)

replace (
	github.com/replaced/module v1.0.0 => github.com/fork/module v1.0.1
)

exclude (
	github.com/excluded/module v1.0.0
)
`
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	probe := NewWorkspaceProbe(tempDir)

	// Resolve ripgrep
	t1, err := probe.Resolve(context.Background(), "ripgrep")
	if err != nil {
		t.Fatalf("resolve ripgrep: %v", err)
	}
	if t1.LocalVersion != "v1.4.1" {
		t.Errorf("LocalVersion = %q, want v1.4.1", t1.LocalVersion)
	}
	if t1.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", t1.Tracker.Protocol)
	}
	if t1.Tracker.URL != "https://github.com/BurntSushi/ripgrep/issues" {
		t.Errorf("Tracker URL = %q, want https://github.com/BurntSushi/ripgrep/issues", t1.Tracker.URL)
	}

	// Resolve iterm2
	t2, err := probe.Resolve(context.Background(), "iterm2")
	if err != nil {
		t.Fatalf("resolve iterm2: %v", err)
	}
	if t2.Tracker.Protocol != ProtocolGitLab {
		t.Errorf("Protocol = %q, want gitlab", t2.Tracker.Protocol)
	}

	// Replaced and excluded modules must not be resolved
	for _, query := range []string{"module", "replaced", "excluded"} {
		_, err := probe.Resolve(context.Background(), query)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("expected ErrNotFound for %q, got: %v", query, err)
		}
	}
}

func TestWorkspaceProbeSecurityAndNotFound(t *testing.T) {
	tempDir := t.TempDir()
	probe := NewWorkspaceProbe(tempDir)

	// Path traversal attempts and invalid package names
	for _, bad := range []string{"../etc", "/bin/sh", "\\windows\\system32", "a/../../b", ".", "@scope/a/b"} {
		_, err := probe.Resolve(context.Background(), bad)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("expected ErrNotFound for %q, got: %v", bad, err)
		}
	}

	// Missing dependency
	_, err := probe.Resolve(context.Background(), "nonexistent-pkg")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for nonexistent-pkg, got: %v", err)
	}
}
