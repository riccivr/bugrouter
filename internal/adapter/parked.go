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
	"time"

	"github.com/riccivr/bugrouter/internal/scrubber"
)

// ParkedBug represents a 3rd-party anomaly parked during coding without context hijacking.
type ParkedBug struct {
	ID                string                `json:"id"`
	CreatedAt         time.Time             `json:"created_at"`
	Dependency        string                `json:"dependency"`
	Title             string                `json:"title"`
	ErrorSnippet      scrubber.ScrubbedText `json:"error_snippet,omitempty"`
	WorkaroundNote    scrubber.ScrubbedText `json:"workaround_note,omitempty"`
	WorkspaceFile     string                `json:"workspace_file,omitempty"`
	RelatedDependency string                `json:"related_dependency,omitempty"`
	Status            string                `json:"status"` // "parked" or "triaged"
}

// HandoffPayload provides host agents with native MCP handoff directives, user options, and spawn instructions.
type HandoffPayload struct {
	ParkedID           string   `json:"parked_id"`
	ResourceURI        string   `json:"resource_uri"`
	MCPPromptName      string   `json:"mcp_prompt_name"`
	CLICommand         string   `json:"cli_command"`
	PatchInstructions  string   `json:"patch_instructions"`
	UserOptions        []string `json:"user_options"`
	SpawnSessionPrompt string   `json:"spawn_session_prompt,omitempty"`
	AgentDirective     string   `json:"agent_directive"`
}

// ParkedStore manages zero-latency breadcrumbs in restricted user storage.
type ParkedStore struct {
	dir string
}

// NewParkedStore creates a store defaulting to XDG data or user local share directory.
func NewParkedStore(dir string) *ParkedStore {
	if dir == "" {
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			dir = filepath.Join(xdg, "bugrouter", "parked")
		} else if home, err := os.UserHomeDir(); err == nil && home != "" {
			dir = filepath.Join(home, ".local", "share", "bugrouter", "parked")
		} else {
			dir = filepath.Join(os.TempDir(), "bugrouter", "parked")
		}
	}
	return &ParkedStore{dir: dir}
}

// Dir returns the root storage directory for parked bugs.
func (s *ParkedStore) Dir() string {
	return s.dir
}

// Park records a 3rd-party bug anomaly in <5ms with zero network I/O.
func (s *ParkedStore) Park(dep, title, snippet, workaround, file string, relatedDep ...string) (*ParkedBug, HandoffPayload, error) {
	dep = strings.TrimSpace(dep)
	title = sanitizeTitle(title)

	if dep == "" {
		return nil, HandoffPayload{}, errors.New("dependency is required")
	}
	if title == "" {
		return nil, HandoffPayload{}, errors.New("title is required")
	}

	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return nil, HandoffPayload{}, fmt.Errorf("generate parked id: %w", err)
	}
	id := hex.EncodeToString(b)

	var rel string
	if len(relatedDep) > 0 {
		rel = strings.TrimSpace(relatedDep[0])
	}

	bug := &ParkedBug{
		ID:                id,
		CreatedAt:         time.Now().UTC(),
		Dependency:        dep,
		Title:             title,
		ErrorSnippet:      scrubber.Scrub(snippet),
		WorkaroundNote:    scrubber.Scrub(workaround),
		WorkspaceFile:     file,
		RelatedDependency: rel,
		Status:            "parked",
	}

	if err := s.Save(bug); err != nil {
		return nil, HandoffPayload{}, err
	}

	patchInstructions := derivePatchInstructions(dep, file)
	userOptions := []string{
		"1. Ignore and continue current task",
		"2. Keep parked for later triage",
		"3. Spawn separate session to file upstream bug",
		"4. Fork/patch dependency locally and track in patch ledger",
	}

	handoff := HandoffPayload{
		ParkedID:           id,
		ResourceURI:        "bugrouter://parked/" + id,
		MCPPromptName:      "triage_parked_bug",
		CLICommand:         "bugrouter draft --from-parked " + id,
		PatchInstructions:  patchInstructions,
		UserOptions:        userOptions,
		SpawnSessionPrompt: fmt.Sprintf("Triage parked bug %s affecting %s: %s", id, dep, title),
		AgentDirective:     "CRITICAL: Bug parked in <5ms. Do NOT resolve, introspect, or draft this ticket in the current session. Present the 4 user_options concisely and continue the user's primary task.",
	}

	return bug, handoff, nil
}

func derivePatchInstructions(dep, file string) string {
	depLower := strings.ToLower(dep)
	fileLower := strings.ToLower(file)

	if strings.Contains(fileLower, "go.mod") || strings.HasSuffix(fileLower, ".go") || strings.Contains(depLower, "github.com/") || strings.Contains(depLower, "golang.org/") {
		return fmt.Sprintf("go mod edit -replace %s=<fork-target> && bugrouter patch add --dep %s --target <fork-target> --ecosystem go", dep, dep)
	}
	if strings.Contains(fileLower, "package.json") || strings.HasSuffix(fileLower, ".ts") || strings.HasSuffix(fileLower, ".js") {
		return fmt.Sprintf("pnpm patch %s (or npm/yarn 'overrides') && bugrouter patch add --dep %s --target patches/%s.patch --ecosystem npm", dep, dep, dep)
	}
	if strings.Contains(fileLower, "cargo.toml") || strings.HasSuffix(fileLower, ".rs") {
		return fmt.Sprintf("[patch.crates-io] in Cargo.toml && bugrouter patch add --dep %s --target <fork-target> --ecosystem cargo", dep)
	}
	if strings.Contains(fileLower, "pyproject.toml") || strings.Contains(fileLower, "requirements.txt") || strings.HasSuffix(fileLower, ".py") {
		return fmt.Sprintf("Point dependency to git fork in pyproject.toml / requirements.txt && bugrouter patch add --dep %s --target <fork-target> --ecosystem python", dep)
	}
	return fmt.Sprintf("Fork repository locally/remotely and track in ledger via: bugrouter patch add --dep %s --target <fork-target>", dep)
}

// Save writes the parked bug atomically with 0600 file permissions.
func (s *ParkedStore) Save(b *ParkedBug) error {
	if b == nil {
		return errors.New("parked bug cannot be nil")
	}
	if !IsValidDraftID(b.ID) {
		return fmt.Errorf("invalid parked bug id %q", b.ID)
	}

	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("create parked directory %s: %w", s.dir, err)
	}

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal parked bug %s: %w", b.ID, err)
	}

	targetPath := filepath.Join(s.dir, b.ID+".json")
	tmpFile, err := os.CreateTemp(s.dir, "parked-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp parked file: %w", err)
	}
	tmpName := tmpFile.Name()

	// Enforce 0600 file permissions so parked logs remain restricted to the local user.
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

	if err := os.Rename(tmpName, targetPath); err != nil {
		cleanupErr := os.Remove(tmpName)
		if cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return fmt.Errorf("rename to %s: %w (cleanup: %v)", targetPath, err, cleanupErr)
		}
		return fmt.Errorf("rename to %s: %w", targetPath, err)
	}

	return nil
}

// List retrieves all parked bugs sorted descending by creation time.
func (s *ParkedStore) List() ([]*ParkedBug, error) {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return nil, fmt.Errorf("create parked directory %s: %w", s.dir, err)
	}

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("read parked directory %s: %w", s.dir, err)
	}

	var bugs []*ParkedBug
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), "parked-") {
			continue
		}

		path := filepath.Join(s.dir, entry.Name())
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}

		var b ParkedBug
		if unmarshalErr := json.Unmarshal(data, &b); unmarshalErr != nil {
			continue
		}
		bugs = append(bugs, &b)
	}

	sort.Slice(bugs, func(i, j int) bool {
		return bugs[i].CreatedAt.After(bugs[j].CreatedAt)
	})

	return bugs, nil
}

// Get retrieves a single parked bug by its 8-char hex identifier.
func (s *ParkedStore) Get(id string) (*ParkedBug, error) {
	if !IsValidDraftID(id) {
		return nil, fmt.Errorf("invalid parked id %q", id)
	}
	cleanID := filepath.Base(id)
	path := filepath.Join(s.dir, cleanID+".json")

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("parked bug %s: not found", cleanID)
		}
		return nil, fmt.Errorf("read parked bug %s: %w", cleanID, err)
	}

	var b ParkedBug
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("unmarshal parked bug %s: %w", cleanID, err)
	}

	return &b, nil
}

// Delete removes a parked bug file from local storage.
func (s *ParkedStore) Delete(id string) error {
	if !IsValidDraftID(id) {
		return fmt.Errorf("invalid parked id %q", id)
	}
	cleanID := filepath.Base(id)
	path := filepath.Join(s.dir, cleanID+".json")

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("parked bug %s: not found", cleanID)
		}
		return fmt.Errorf("delete parked bug %s: %w", cleanID, err)
	}
	return nil
}
