package resolver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WorkspaceProbe resolves dependencies present in local manifests and node_modules.
type WorkspaceProbe struct {
	rootDir string
}

// NewWorkspaceProbe creates a probe rooted at the specified workspace directory.
func NewWorkspaceProbe(rootDir string) *WorkspaceProbe {
	if strings.TrimSpace(rootDir) == "" {
		rootDir = "."
	}
	return &WorkspaceProbe{rootDir: rootDir}
}

// Name returns the probe identifier.
func (w *WorkspaceProbe) Name() string {
	return "workspace"
}

// Layer returns the resolution layer classification.
func (w *WorkspaceProbe) Layer() SourceLayer {
	return LayerWorkspace
}

type nodePackage struct {
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	Bugs       json.RawMessage `json:"bugs"`
	Repository json.RawMessage `json:"repository"`
}

func parseBugs(raw json.RawMessage) (string, string) {
	if len(raw) == 0 {
		return "", ""
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return str, ""
	}
	var obj struct {
		URL   string `json:"url"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.URL, obj.Email
	}
	return "", ""
}

func parseRepository(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return str
	}
	var obj struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.URL
	}
	return ""
}

// Resolve inspects local node_modules and go.mod files for dependency resolution.
func (w *WorkspaceProbe) Resolve(ctx context.Context, query string) (*Target, error) {
	if strings.Contains(query, "..") || strings.HasPrefix(query, "/") || strings.HasPrefix(query, "\\") {
		return nil, ErrNotFound
	}

	// 1. Node.js check: node_modules/<query>/package.json
	pkgPath := filepath.Join(w.rootDir, "node_modules", query, "package.json")
	if data, err := os.ReadFile(pkgPath); err == nil {
		var pkg nodePackage
		if err := json.Unmarshal(data, &pkg); err == nil {
			bugsURL, bugsEmail := parseBugs(pkg.Bugs)
			repoURL := parseRepository(pkg.Repository)
			tracker, normRepo := ClassifyTracker(bugsURL, bugsEmail, repoURL)

			canonicalName := pkg.Name
			if canonicalName == "" {
				canonicalName = query
			}

			return &Target{
				Query:         query,
				CanonicalName: canonicalName,
				LocalVersion:  pkg.Version,
				Layer:         LayerWorkspace,
				RepositoryURL: normRepo,
				Tracker:       tracker,
			}, nil
		}
	}

	// 2. Go check: go.mod
	goModPath := filepath.Join(w.rootDir, "go.mod")
	if file, err := os.Open(goModPath); err == nil {
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if idx := strings.Index(line, "//"); idx != -1 {
				line = line[:idx]
			}
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "module ") || strings.HasPrefix(line, "go ") {
				continue
			}

			fields := strings.Fields(line)
			var modPath, version string
			if fields[0] == "require" && len(fields) >= 3 {
				modPath = fields[1]
				version = fields[2]
			} else if len(fields) >= 2 && fields[0] != "(" && fields[0] != ")" && fields[0] != "replace" {
				modPath = fields[0]
				version = fields[1]
			}

			if modPath != "" && (modPath == query || strings.HasSuffix(modPath, "/"+query)) {
				if strings.HasPrefix(modPath, "github.com/") ||
					strings.HasPrefix(modPath, "gitlab.com/") ||
					strings.HasPrefix(modPath, "codeberg.org/") {
					tracker, normRepo := ClassifyTracker("", "", "https://"+modPath)
					return &Target{
						Query:         query,
						CanonicalName: query,
						LocalVersion:  version,
						Layer:         LayerWorkspace,
						RepositoryURL: normRepo,
						Tracker:       tracker,
					}, nil
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read go.mod: %w", err)
		}
	}

	return nil, ErrNotFound
}
