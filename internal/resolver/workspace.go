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

func isValidNPMPackageName(q string) bool {
	if q == "" || q == "." || q == ".." || strings.Contains(q, "\\") {
		return false
	}

	if strings.HasPrefix(q, "@") {
		parts := strings.Split(q, "/")
		if len(parts) != 2 {
			return false
		}
		scope := strings.TrimPrefix(parts[0], "@")
		pkg := parts[1]
		if scope == "" || pkg == "" || strings.HasPrefix(scope, ".") || strings.HasPrefix(pkg, ".") {
			return false
		}
		return true
	}

	return !strings.Contains(q, "/") && !strings.HasPrefix(q, ".")
}

// Resolve inspects local node_modules and go.mod files for dependency resolution.
func (w *WorkspaceProbe) Resolve(ctx context.Context, query string) (*Target, error) {
	if strings.Contains(query, "..") || strings.HasPrefix(query, "/") || strings.HasPrefix(query, "\\") {
		return nil, ErrNotFound
	}

	// 1. Node.js check: node_modules/<query>/package.json (only for valid package names to prevent directory traversal)
	if isValidNPMPackageName(query) {
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
	}

	// 2. Go check: go.mod
	goModPath := filepath.Join(w.rootDir, "go.mod")
	if file, err := os.Open(goModPath); err == nil {
		defer file.Close()

		var inRequireBlock bool
		var inIgnoredBlock bool

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if idx := strings.Index(line, "//"); idx != -1 {
				line = line[:idx]
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if inIgnoredBlock {
				if line == ")" {
					inIgnoredBlock = false
				}
				continue
			}

			if inRequireBlock {
				if line == ")" {
					inRequireBlock = false
					continue
				}

				// Strip potential replacement targets
				if idx := strings.Index(line, "=>"); idx != -1 {
					line = line[:idx]
				}

				fields := strings.Fields(line)
				if len(fields) >= 2 {
					modPath := fields[0]
					version := fields[1]
					if modPath == query || strings.HasSuffix(modPath, "/"+query) {
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
				continue
			}

			if line == "require (" {
				inRequireBlock = true
				continue
			}

			if strings.HasPrefix(line, "replace (") ||
				strings.HasPrefix(line, "exclude (") ||
				strings.HasPrefix(line, "retract (") ||
				strings.HasPrefix(line, "tool (") {
				inIgnoredBlock = true
				continue
			}

			if strings.HasPrefix(line, "require ") {
				if idx := strings.Index(line, "=>"); idx != -1 {
					line = line[:idx]
				}
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					modPath := fields[1]
					version := fields[2]
					if modPath == query || strings.HasSuffix(modPath, "/"+query) {
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
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read go.mod: %w", err)
		}
	}

	// 3. Rust check: Cargo.toml & Cargo.lock
	if target, err := w.resolveCargo(ctx, query); err == nil {
		return target, nil
	}

	// 4. Python check: pyproject.toml
	if target, err := w.resolvePyproject(ctx, query); err == nil {
		return target, nil
	}

	return nil, ErrNotFound
}

func stripTOMLComment(line string) string {
	inQuote := false
	var quoteChar rune
	for i, r := range line {
		if (r == '"' || r == '\'') && !inQuote {
			inQuote = true
			quoteChar = r
		} else if inQuote && r == quoteChar {
			inQuote = false
		} else if !inQuote && r == '#' {
			return strings.TrimSpace(line[:i])
		}
	}
	return strings.TrimSpace(line)
}

func extractTOMLValue(val string) string {
	val = strings.TrimSpace(val)
	if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
		return val[1 : len(val)-1]
	}
	return val
}

func extractInlineTableField(table, field string) string {
	idx := strings.Index(table, field)
	if idx == -1 {
		return ""
	}
	rest := strings.TrimSpace(table[idx+len(field):])
	if !strings.HasPrefix(rest, "=") {
		return ""
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
	if len(rest) > 0 && (rest[0] == '"' || rest[0] == '\'') {
		q := rest[0]
		end := strings.IndexByte(rest[1:], q)
		if end != -1 {
			return rest[1 : end+1]
		}
	}
	return ""
}

func (w *WorkspaceProbe) resolveCargo(ctx context.Context, query string) (*Target, error) {
	cargoPath := filepath.Join(w.rootDir, "Cargo.toml")
	data, err := os.ReadFile(cargoPath)
	if err != nil {
		return nil, ErrNotFound
	}

	lines := strings.Split(string(data), "\n")
	var currentSection string
	var pkgName, pkgVer, pkgRepo, pkgHome string
	var depVer, depGit string
	var inMatchingDepSection bool

	for _, rawLine := range lines {
		line := stripTOMLComment(rawLine)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[] \t")
			inMatchingDepSection = false
			lowerSec := strings.ToLower(currentSection)
			for _, prefix := range []string{"dependencies.", "dev-dependencies.", "build-dependencies.", "workspace.dependencies."} {
				if strings.HasPrefix(lowerSec, prefix) {
					subName := strings.TrimPrefix(lowerSec, prefix)
					if strings.EqualFold(subName, query) {
						inMatchingDepSection = true
					}
				}
			}
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		if currentSection == "package" {
			switch strings.ToLower(key) {
			case "name":
				pkgName = extractTOMLValue(val)
			case "version":
				pkgVer = extractTOMLValue(val)
			case "repository":
				pkgRepo = extractTOMLValue(val)
			case "homepage":
				pkgHome = extractTOMLValue(val)
			}
			continue
		}

		lowerSec := strings.ToLower(currentSection)
		isDepSection := lowerSec == "dependencies" ||
			lowerSec == "dev-dependencies" ||
			lowerSec == "build-dependencies" ||
			lowerSec == "workspace.dependencies"

		if isDepSection {
			if strings.EqualFold(key, query) {
				if strings.HasPrefix(val, "{") && strings.HasSuffix(val, "}") {
					depVer = extractInlineTableField(val, "version")
					depGit = extractInlineTableField(val, "git")
				} else {
					depVer = extractTOMLValue(val)
				}
			}
		} else if inMatchingDepSection {
			switch strings.ToLower(key) {
			case "version":
				depVer = extractTOMLValue(val)
			case "git":
				depGit = extractTOMLValue(val)
			}
		}
	}

	// 1. Check if query matched local package
	if strings.EqualFold(pkgName, query) {
		repoURL := pkgRepo
		if repoURL == "" {
			repoURL = pkgHome
		}
		if repoURL != "" {
			tracker, normRepo := ClassifyTracker("", "", repoURL)
			if tracker.URL != "" || tracker.Email != "" {
				return &Target{
					Query:         query,
					CanonicalName: query,
					LocalVersion:  pkgVer,
					Layer:         LayerWorkspace,
					RepositoryURL: normRepo,
					Tracker:       tracker,
				}, nil
			}
		}
	}

	// 2. Check if git URL found on dependency
	if depGit != "" {
		tracker, normRepo := ClassifyTracker("", "", depGit)
		if tracker.URL != "" || tracker.Email != "" {
			return &Target{
				Query:         query,
				CanonicalName: query,
				LocalVersion:  depVer,
				Layer:         LayerWorkspace,
				RepositoryURL: normRepo,
				Tracker:       tracker,
			}, nil
		}
	}

	// 3. Scan Cargo.lock if present
	lockPath := filepath.Join(w.rootDir, "Cargo.lock")
	if lockData, lockErr := os.ReadFile(lockPath); lockErr == nil {
		lockLines := strings.Split(string(lockData), "\n")
		var curPkg, curVer, curSource string
		flushPkg := func() *Target {
			if strings.EqualFold(curPkg, query) && curSource != "" {
				source := curSource
				if strings.Contains(source, "git+") || strings.HasPrefix(source, "git://") {
					source = strings.TrimPrefix(source, "git+")
					if idx := strings.Index(source, "#"); idx != -1 {
						source = source[:idx]
					}
					if idx := strings.Index(source, "?"); idx != -1 {
						source = source[:idx]
					}
					tracker, normRepo := ClassifyTracker("", "", source)
					if tracker.URL != "" || tracker.Email != "" {
						return &Target{
							Query:         query,
							CanonicalName: query,
							LocalVersion:  curVer,
							Layer:         LayerWorkspace,
							RepositoryURL: normRepo,
							Tracker:       tracker,
						}
					}
				}
			}
			return nil
		}

		for _, rawLine := range lockLines {
			line := stripTOMLComment(rawLine)
			if line == "[[package]]" {
				if t := flushPkg(); t != nil {
					return t, nil
				}
				curPkg, curVer, curSource = "", "", ""
				continue
			}
			key, val, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			val = extractTOMLValue(val)
			switch key {
			case "name":
				curPkg = val
			case "version":
				curVer = val
			case "source":
				curSource = val
			}
		}
		if t := flushPkg(); t != nil {
			return t, nil
		}
	}

	return nil, ErrNotFound
}

func (w *WorkspaceProbe) resolvePyproject(ctx context.Context, query string) (*Target, error) {
	pyprojectPath := filepath.Join(w.rootDir, "pyproject.toml")
	data, err := os.ReadFile(pyprojectPath)
	if err != nil {
		return nil, ErrNotFound
	}

	lines := strings.Split(string(data), "\n")
	var currentSection string
	var projName, projVer string
	var issuesURL, repoURL, homeURL string
	var inDependenciesArray bool

	var depGitURL string
	var inMatchingPoetryDep bool

	for _, rawLine := range lines {
		line := stripTOMLComment(rawLine)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[] \t")
			inDependenciesArray = false
			inMatchingPoetryDep = false
			lowerSec := strings.ToLower(currentSection)
			if strings.HasPrefix(lowerSec, "tool.poetry.dependencies.") {
				subName := strings.TrimPrefix(lowerSec, "tool.poetry.dependencies.")
				if strings.EqualFold(subName, query) {
					inMatchingPoetryDep = true
				}
			}
			continue
		}

		lowerSec := strings.ToLower(currentSection)

		if inDependenciesArray {
			if strings.HasSuffix(line, "]") {
				inDependenciesArray = false
			}
			tok := strings.Trim(line, "[], \t\"'")
			if idx := strings.Index(tok, "@"); idx != -1 {
				depName := strings.TrimSpace(tok[:idx])
				if strings.EqualFold(depName, query) {
					depGitURL = strings.TrimSpace(tok[idx+1:])
					depGitURL = strings.Trim(depGitURL, "\",' ")
				}
			}
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		if lowerSec == "project" || lowerSec == "tool.poetry" {
			switch strings.ToLower(key) {
			case "name":
				projName = extractTOMLValue(val)
			case "version":
				projVer = extractTOMLValue(val)
			case "dependencies":
				if strings.HasPrefix(val, "[") && !strings.HasSuffix(val, "]") {
					inDependenciesArray = true
				} else if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
					inner := strings.Trim(val, "[] \t")
					items := strings.Split(inner, ",")
					for _, it := range items {
						tok := strings.Trim(it, " \t\"'")
						if idx := strings.Index(tok, "@"); idx != -1 {
							depName := strings.TrimSpace(tok[:idx])
							if strings.EqualFold(depName, query) {
								depGitURL = strings.TrimSpace(tok[idx+1:])
								depGitURL = strings.Trim(depGitURL, "\",' ")
							}
						}
					}
				}
			}
			continue
		}

		if lowerSec == "project.urls" || lowerSec == "tool.poetry.urls" {
			strVal := extractTOMLValue(val)
			switch strings.ToLower(key) {
			case "repository", "source", "code":
				if repoURL == "" {
					repoURL = strVal
				}
			case "homepage", "home":
				if homeURL == "" {
					homeURL = strVal
				}
			case "issues", "issue tracker", "bug tracker", "bugs", "tracker":
				if issuesURL == "" {
					issuesURL = strVal
				}
			}
			continue
		}

		if lowerSec == "tool.poetry.dependencies" {
			if strings.EqualFold(key, query) {
				if strings.HasPrefix(val, "{") && strings.HasSuffix(val, "}") {
					depGitURL = extractInlineTableField(val, "git")
					if depGitURL == "" {
						depGitURL = extractInlineTableField(val, "url")
					}
				}
			}
			continue
		}

		if inMatchingPoetryDep {
			switch strings.ToLower(key) {
			case "git", "url":
				depGitURL = extractTOMLValue(val)
			}
		}
	}

	// 1. Check if query matched project
	if strings.EqualFold(projName, query) {
		targetURL := issuesURL
		if targetURL == "" {
			targetURL = repoURL
		}
		if targetURL == "" {
			targetURL = homeURL
		}
		if targetURL != "" {
			tracker, normRepo := ClassifyTracker(issuesURL, "", repoURL)
			if tracker.URL == "" && tracker.Email == "" {
				tracker, normRepo = ClassifyTracker("", "", targetURL)
			}
			if tracker.URL != "" || tracker.Email != "" {
				return &Target{
					Query:         query,
					CanonicalName: query,
					LocalVersion:  projVer,
					Layer:         LayerWorkspace,
					RepositoryURL: normRepo,
					Tracker:       tracker,
				}, nil
			}
		}
	}

	// 2. Check if git URL found on dependency
	if depGitURL != "" {
		cleanURL := strings.TrimPrefix(depGitURL, "git+")
		if idx := strings.Index(cleanURL, "#"); idx != -1 {
			cleanURL = cleanURL[:idx]
		}
		if idx := strings.Index(cleanURL, "?"); idx != -1 {
			cleanURL = cleanURL[:idx]
		}
		tracker, normRepo := ClassifyTracker("", "", cleanURL)
		if tracker.URL != "" || tracker.Email != "" {
			return &Target{
				Query:         query,
				CanonicalName: query,
				Layer:         LayerWorkspace,
				RepositoryURL: normRepo,
				Tracker:       tracker,
			}, nil
		}
	}

	return nil, ErrNotFound
}
