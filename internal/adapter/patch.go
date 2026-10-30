package adapter

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DependencyPatch represents a tracked temporary fork or local patch of an upstream dependency.
type DependencyPatch struct {
	ID               string    `json:"id"`
	CreatedAt        time.Time `json:"created_at"`
	Dependency       string    `json:"dependency"`
	Ecosystem        string    `json:"ecosystem"`
	PatchTarget      string    `json:"patch_target"`
	ManifestFile     string    `json:"manifest_file,omitempty"`
	UpstreamIssueURL string    `json:"upstream_issue_url,omitempty"`
	Reason           string    `json:"reason"`
	Status           string    `json:"status"` // "active" or "reverted"
}

// PatchStore manages atomic storage for dependency patches.
type PatchStore struct {
	path string
	mu   sync.Mutex
}

// DefaultPatchStorePath returns the canonical path for patches.json.
func DefaultPatchStorePath() string {
	if env := os.Getenv("BUGROUTER_PATCHES_FILE"); env != "" {
		return env
	}
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "bugrouter", "patches.json")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "share", "bugrouter", "patches.json")
	}
	return filepath.Join(os.TempDir(), "bugrouter", "patches.json")
}

// NewPatchStore creates a PatchStore pointing to path, or the default path if path is empty.
func NewPatchStore(path string) *PatchStore {
	if path == "" {
		path = DefaultPatchStorePath()
	}
	return &PatchStore{path: path}
}

// Path returns the backing file path.
func (s *PatchStore) Path() string {
	return s.path
}

// Record persists a new dependency patch atomically with 0600 permissions.
func (s *PatchStore) Record(dep, ecosystem, patchTarget, manifestFile, upstreamURL, reason string) (*DependencyPatch, error) {
	dep = strings.TrimSpace(dep)
	patchTarget = strings.TrimSpace(patchTarget)
	reason = strings.TrimSpace(reason)

	if dep == "" {
		return nil, errors.New("dependency is required")
	}
	if patchTarget == "" {
		return nil, errors.New("patch_target is required")
	}
	if reason == "" {
		return nil, errors.New("reason is required")
	}

	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	if ecosystem == "" {
		if strings.Contains(manifestFile, "go.mod") || strings.Contains(dep, "github.com/") {
			ecosystem = "go"
		} else if strings.Contains(manifestFile, "package.json") {
			ecosystem = "npm"
		} else if strings.Contains(manifestFile, "Cargo.toml") {
			ecosystem = "cargo"
		} else if strings.Contains(manifestFile, "pyproject.toml") {
			ecosystem = "python"
		} else {
			ecosystem = "custom"
		}
	}

	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate patch id: %w", err)
	}
	id := hex.EncodeToString(b)

	patch := DependencyPatch{
		ID:               id,
		CreatedAt:        time.Now().UTC(),
		Dependency:       dep,
		Ecosystem:        ecosystem,
		PatchTarget:      patchTarget,
		ManifestFile:     strings.TrimSpace(manifestFile),
		UpstreamIssueURL: strings.TrimSpace(upstreamURL),
		Reason:           reason,
		Status:           "active",
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	patches, err := s.readPatchesLocked()
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read patches: %w", err)
	}

	// Prepend new patch to preserve descending order
	patches = append([]DependencyPatch{patch}, patches...)

	if err := s.writePatchesLocked(patches); err != nil {
		return nil, err
	}

	return &patch, nil
}

// List returns all tracked dependency patches, sorted descending by creation time.
func (s *PatchStore) List() ([]DependencyPatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	patches, err := s.readPatchesLocked()
	if err != nil {
		if os.IsNotExist(err) {
			return []DependencyPatch{}, nil
		}
		return nil, fmt.Errorf("read patches: %w", err)
	}

	sort.Slice(patches, func(i, j int) bool {
		return patches[i].CreatedAt.After(patches[j].CreatedAt)
	})

	return patches, nil
}

// Remove deletes a patch from the ledger matching either its 8-char ID or dependency name.
func (s *PatchStore) Remove(idOrDep string) error {
	needle := strings.TrimSpace(idOrDep)
	if needle == "" {
		return errors.New("id or dependency name is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	patches, err := s.readPatchesLocked()
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("patch %q: not found", needle)
		}
		return fmt.Errorf("read patches: %w", err)
	}

	var updated []DependencyPatch
	found := false
	for _, p := range patches {
		if !found && (strings.EqualFold(p.ID, needle) || strings.EqualFold(p.Dependency, needle)) {
			found = true
			continue
		}
		updated = append(updated, p)
	}

	if !found {
		return fmt.Errorf("patch %q: not found", needle)
	}

	return s.writePatchesLocked(updated)
}

func (s *PatchStore) readPatchesLocked() ([]DependencyPatch, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}

	// Support direct slice representation
	var direct []DependencyPatch
	if err := json.Unmarshal(data, &direct); err == nil {
		return direct, nil
	}

	// Support wrapped {"patches": [...]} format
	var wrapped struct {
		Patches []DependencyPatch `json:"patches"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return nil, fmt.Errorf("unmarshal patches file %s: %w", s.path, err)
	}
	return wrapped.Patches, nil
}

func (s *PatchStore) writePatchesLocked(patches []DependencyPatch) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create patch directory %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(patches, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal patches: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, "patches-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp patch file: %w", err)
	}
	tmpName := tmpFile.Name()

	if err := tmpFile.Chmod(0600); err != nil {
		closeErr := tmpFile.Close()
		cleanupErr := os.Remove(tmpName)
		if cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return fmt.Errorf("chmod %s: %w (close: %v, cleanup: %v)", tmpName, err, closeErr, cleanupErr)
		}
		if closeErr != nil {
			return fmt.Errorf("chmod %s: %w (close: %v)", tmpName, err, closeErr)
		}
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		closeErr := tmpFile.Close()
		cleanupErr := os.Remove(tmpName)
		if cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return fmt.Errorf("write %s: %w (close: %v, cleanup: %v)", tmpName, err, closeErr, cleanupErr)
		}
		if closeErr != nil {
			return fmt.Errorf("write %s: %w (close: %v)", tmpName, err, closeErr)
		}
		return fmt.Errorf("write %s: %w", tmpName, err)
	}

	if err := tmpFile.Close(); err != nil {
		cleanupErr := os.Remove(tmpName)
		if cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return fmt.Errorf("close %s: %w (cleanup: %v)", tmpName, err, cleanupErr)
		}
		return fmt.Errorf("close %s: %w", tmpName, err)
	}

	if err := os.Rename(tmpName, s.path); err != nil {
		cleanupErr := os.Remove(tmpName)
		if cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return fmt.Errorf("rename to %s: %w (cleanup: %v)", s.path, err, cleanupErr)
		}
		return fmt.Errorf("rename to %s: %w", s.path, err)
	}

	return nil
}
