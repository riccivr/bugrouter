package resolver

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
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

	// 5. Java check: pom.xml
	if target, err := w.resolveMaven(ctx, query); err == nil {
		return target, nil
	}

	// 6. .NET / C# check: .csproj & packages.config
	if target, err := w.resolveDotNet(ctx, query); err == nil {
		return target, nil
	}

	// 7. Ruby check: Gemfile.lock & Gemfile
	if target, err := w.resolveRuby(ctx, query); err == nil {
		return target, nil
	}

	// 8. PHP check: composer.lock & composer.json
	if target, err := w.resolvePHP(ctx, query); err == nil {
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
	content := strings.TrimSpace(table)
	if strings.HasPrefix(content, "{") && strings.HasSuffix(content, "}") {
		content = strings.TrimSpace(content[1 : len(content)-1])
	}

	var entries []string
	var cur strings.Builder
	var inQuote rune

	for _, r := range content {
		switch {
		case inQuote != 0:
			if r == inQuote {
				inQuote = 0
			}
			cur.WriteRune(r)
		case r == '"' || r == '\'':
			inQuote = r
			cur.WriteRune(r)
		case r == ',':
			entries = append(entries, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		entries = append(entries, cur.String())
	}

	for _, entry := range entries {
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), field) {
			return extractTOMLValue(v)
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

func normalizePyPkgName(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "["); idx != -1 {
		s = s[:idx]
	}
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}

func parsePyDepGitURL(rawItem string, query string) (string, bool) {
	tok := strings.Trim(rawItem, "[], \t\"'")
	if idx := strings.Index(tok, "@"); idx != -1 {
		depName := strings.TrimSpace(tok[:idx])
		if normalizePyPkgName(depName) == normalizePyPkgName(query) {
			depURL := strings.TrimSpace(tok[idx+1:])
			depURL = strings.Trim(depURL, "\",' ")
			return depURL, true
		}
	}
	return "", false
}

func parsePyDepSlice(itemsStr string, query string) string {
	var cur strings.Builder
	var inQuote rune
	var elements []string
	for _, r := range itemsStr {
		switch {
		case inQuote != 0:
			if r == inQuote {
				inQuote = 0
			}
			cur.WriteRune(r)
		case r == '"' || r == '\'':
			inQuote = r
			cur.WriteRune(r)
		case r == ',':
			elements = append(elements, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		elements = append(elements, cur.String())
	}
	for _, el := range elements {
		if gitURL, ok := parsePyDepGitURL(el, query); ok {
			return gitURL
		}
	}
	return ""
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
				if normalizePyPkgName(subName) == normalizePyPkgName(query) {
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
			if u := parsePyDepSlice(line, query); u != "" && depGitURL == "" {
				depGitURL = u
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
					rest := strings.TrimPrefix(val, "[")
					if u := parsePyDepSlice(rest, query); u != "" && depGitURL == "" {
						depGitURL = u
					}
				} else if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
					inner := strings.Trim(val, "[] \t")
					if u := parsePyDepSlice(inner, query); u != "" && depGitURL == "" {
						depGitURL = u
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
			if normalizePyPkgName(key) == normalizePyPkgName(query) {
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
	if normalizePyPkgName(projName) == normalizePyPkgName(query) {
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

// maxWorkspaceManifestBytes caps manifest ingestion to 2 MiB.
const maxWorkspaceManifestBytes = 2 * 1024 * 1024

func readBoundedFile(path string) (data []byte, err error) {
	file, openErr := os.Open(path)
	if openErr != nil {
		return nil, openErr
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close %s: %w", path, closeErr)
		}
	}()

	limited := io.LimitReader(file, maxWorkspaceManifestBytes+1)
	buf, readErr := io.ReadAll(limited)
	if readErr != nil {
		return nil, fmt.Errorf("read %s: %w", path, readErr)
	}
	if len(buf) > maxWorkspaceManifestBytes {
		return nil, fmt.Errorf("manifest %s exceeds %d byte limit", path, maxWorkspaceManifestBytes)
	}
	return buf, nil
}

func shortPkgName(name string) string {
	if idx := strings.LastIndex(name, "/"); idx != -1 {
		return name[idx+1:]
	}
	if idx := strings.LastIndex(name, ":"); idx != -1 {
		return name[idx+1:]
	}
	return name
}

// ----------------------------------------------------------------------------
// Maven (pom.xml) Parser
// ----------------------------------------------------------------------------

type pomProject struct {
	XMLName         xml.Name        `xml:"project"`
	GroupID         string          `xml:"groupId"`
	ArtifactID      string          `xml:"artifactId"`
	Version         string          `xml:"version"`
	URL             string          `xml:"url"`
	Parent          pomParent       `xml:"parent"`
	SCM             pomSCM          `xml:"scm"`
	IssueManagement pomIssueMgmt    `xml:"issueManagement"`
	Dependencies    pomDependencies `xml:"dependencies"`
}

type pomParent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type pomSCM struct {
	URL                 string `xml:"url"`
	Connection          string `xml:"connection"`
	DeveloperConnection string `xml:"developerConnection"`
}

type pomIssueMgmt struct {
	System string `xml:"system"`
	URL    string `xml:"url"`
}

type pomDependencies struct {
	Dependency []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	URL        string `xml:"url"`
	SCM        pomSCM `xml:"scm"`
}

func (w *WorkspaceProbe) resolveMaven(ctx context.Context, query string) (*Target, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	pomPath := filepath.Join(w.rootDir, "pom.xml")
	data, err := readBoundedFile(pomPath)
	if err != nil {
		return nil, ErrNotFound
	}

	var pom pomProject
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, ErrNotFound
	}

	groupID := strings.TrimSpace(pom.GroupID)
	if groupID == "" {
		groupID = strings.TrimSpace(pom.Parent.GroupID)
	}
	version := strings.TrimSpace(pom.Version)
	if version == "" {
		version = strings.TrimSpace(pom.Parent.Version)
	}
	artifactID := strings.TrimSpace(pom.ArtifactID)

	// 1. Check if query matches the root project
	isProjectMatch := (artifactID != "" && strings.EqualFold(artifactID, query)) ||
		(groupID != "" && artifactID != "" && strings.EqualFold(groupID+":"+artifactID, query)) ||
		(groupID != "" && artifactID != "" && strings.EqualFold(groupID+"/"+artifactID, query))

	if isProjectMatch {
		issuesURL := strings.TrimSpace(pom.IssueManagement.URL)
		repoURL := strings.TrimSpace(pom.SCM.URL)
		if repoURL == "" {
			repoURL = strings.TrimSpace(pom.SCM.Connection)
		}
		if repoURL == "" {
			repoURL = strings.TrimSpace(pom.SCM.DeveloperConnection)
		}
		if repoURL == "" {
			repoURL = strings.TrimSpace(pom.URL)
		}

		tracker, normRepo := ClassifyTracker(issuesURL, "", repoURL)
		switch strings.ToLower(strings.TrimSpace(pom.IssueManagement.System)) {
		case "jira":
			tracker.Protocol = ProtocolJira
			tracker.URL = issuesURL
		case "bugzilla":
			tracker.Protocol = ProtocolBugzilla
			tracker.URL = issuesURL
		case "github":
			tracker.Protocol = ProtocolGitHub
		case "gitlab":
			tracker.Protocol = ProtocolGitLab
		default:
			if strings.Contains(strings.ToLower(issuesURL), "/jira/") {
				tracker.Protocol = ProtocolJira
				tracker.URL = issuesURL
			}
		}

		if tracker.URL != "" || tracker.Email != "" {
			return &Target{
				Query:         query,
				CanonicalName: artifactID,
				LocalVersion:  version,
				Layer:         LayerWorkspace,
				RepositoryURL: normRepo,
				Tracker:       tracker,
			}, nil
		}
	}

	// 2. Check dependencies
	for _, dep := range pom.Dependencies.Dependency {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		depArtifact := strings.TrimSpace(dep.ArtifactID)
		depGroup := strings.TrimSpace(dep.GroupID)
		depVersion := strings.TrimSpace(dep.Version)

		isDepMatch := strings.EqualFold(depArtifact, query) ||
			(depGroup != "" && strings.EqualFold(depGroup+":"+depArtifact, query)) ||
			(depGroup != "" && strings.EqualFold(depGroup+"/"+depArtifact, query))

		if !isDepMatch {
			continue
		}

		repoURL := strings.TrimSpace(dep.SCM.URL)
		if repoURL == "" {
			repoURL = strings.TrimSpace(dep.SCM.Connection)
		}
		if repoURL == "" {
			repoURL = strings.TrimSpace(dep.SCM.DeveloperConnection)
		}
		if repoURL == "" {
			repoURL = strings.TrimSpace(dep.URL)
		}

		// Infer git forge URL from groupId if available
		if repoURL == "" {
			lowerGroup := strings.ToLower(depGroup)
			if strings.HasPrefix(lowerGroup, "com.github.") {
				user := strings.TrimPrefix(lowerGroup, "com.github.")
				repoURL = fmt.Sprintf("https://github.com/%s/%s", user, depArtifact)
			} else if strings.HasPrefix(lowerGroup, "io.github.") {
				user := strings.TrimPrefix(lowerGroup, "io.github.")
				repoURL = fmt.Sprintf("https://github.com/%s/%s", user, depArtifact)
			} else if strings.HasPrefix(lowerGroup, "com.gitlab.") {
				user := strings.TrimPrefix(lowerGroup, "com.gitlab.")
				repoURL = fmt.Sprintf("https://gitlab.com/%s/%s", user, depArtifact)
			} else if strings.HasPrefix(lowerGroup, "org.codeberg.") {
				user := strings.TrimPrefix(lowerGroup, "org.codeberg.")
				repoURL = fmt.Sprintf("https://codeberg.org/%s/%s", user, depArtifact)
			}
		}

		if repoURL != "" {
			tracker, normRepo := ClassifyTracker("", "", repoURL)
			if tracker.URL != "" || tracker.Email != "" {
				return &Target{
					Query:         query,
					CanonicalName: depArtifact,
					LocalVersion:  depVersion,
					Layer:         LayerWorkspace,
					RepositoryURL: normRepo,
					Tracker:       tracker,
				}, nil
			}
		}
	}

	return nil, ErrNotFound
}

// ----------------------------------------------------------------------------
// .NET / C# (.csproj / packages.config) Parser
// ----------------------------------------------------------------------------

type csProject struct {
	XMLName        xml.Name          `xml:"Project"`
	PropertyGroups []csPropertyGroup `xml:"PropertyGroup"`
	ItemGroups     []csItemGroup     `xml:"ItemGroup"`
}

type csPropertyGroup struct {
	PackageID         string `xml:"PackageId"`
	AssemblyName      string `xml:"AssemblyName"`
	Version           string `xml:"Version"`
	RepositoryURL     string `xml:"RepositoryUrl"`
	PackageProjectURL string `xml:"PackageProjectUrl"`
}

type csItemGroup struct {
	PackageReferences []csPackageReference `xml:"PackageReference"`
}

type csPackageReference struct {
	Include           string `xml:"Include,attr"`
	Update            string `xml:"Update,attr"`
	VersionAttr       string `xml:"Version,attr"`
	VersionElem       string `xml:"Version"`
	RepositoryURLAttr string `xml:"RepositoryUrl,attr"`
	RepositoryURLElem string `xml:"RepositoryUrl"`
	ProjectURLAttr    string `xml:"PackageProjectUrl,attr"`
	ProjectURLElem    string `xml:"PackageProjectUrl"`
	ProjectURLAttr2   string `xml:"ProjectUrl,attr"`
	ProjectURLElem2   string `xml:"ProjectUrl"`
}

type packagesConfig struct {
	XMLName  xml.Name           `xml:"packages"`
	Packages []packageConfigPkg `xml:"package"`
}

type packageConfigPkg struct {
	ID            string `xml:"id,attr"`
	Version       string `xml:"version,attr"`
	RepositoryURL string `xml:"repositoryUrl,attr"`
	ProjectURL    string `xml:"projectUrl,attr"`
}

func (w *WorkspaceProbe) resolveDotNet(ctx context.Context, query string) (*Target, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	entries, err := os.ReadDir(w.rootDir)
	if err != nil {
		return nil, ErrNotFound
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(strings.ToLower(name), ".csproj") {
			csprojPath := filepath.Join(w.rootDir, name)
			if target, parseErr := w.parseCSProj(ctx, csprojPath, query); parseErr == nil && target != nil {
				return target, nil
			}
		}
	}

	pkgConfigPath := filepath.Join(w.rootDir, "packages.config")
	if target, parseErr := w.parsePackagesConfig(ctx, pkgConfigPath, query); parseErr == nil && target != nil {
		return target, nil
	}

	return nil, ErrNotFound
}

func (w *WorkspaceProbe) parseCSProj(ctx context.Context, csprojPath string, query string) (*Target, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	data, err := readBoundedFile(csprojPath)
	if err != nil {
		return nil, ErrNotFound
	}

	var proj csProject
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, ErrNotFound
	}

	// 1. Check PropertyGroups for project match
	for _, pg := range proj.PropertyGroups {
		pkgID := strings.TrimSpace(pg.PackageID)
		if pkgID == "" {
			pkgID = strings.TrimSpace(pg.AssemblyName)
		}
		ver := strings.TrimSpace(pg.Version)
		repo := strings.TrimSpace(pg.RepositoryURL)
		if repo == "" {
			repo = strings.TrimSpace(pg.PackageProjectURL)
		}

		if (strings.EqualFold(pkgID, query) || strings.EqualFold(shortPkgName(pkgID), query)) && repo != "" {
			tracker, normRepo := ClassifyTracker("", "", repo)
			if tracker.URL != "" || tracker.Email != "" {
				canonicalName := pkgID
				if canonicalName == "" {
					canonicalName = query
				}
				return &Target{
					Query:         query,
					CanonicalName: canonicalName,
					LocalVersion:  ver,
					Layer:         LayerWorkspace,
					RepositoryURL: normRepo,
					Tracker:       tracker,
				}, nil
			}
		}
	}

	// 2. Check ItemGroups for PackageReference match
	for _, ig := range proj.ItemGroups {
		for _, pkg := range ig.PackageReferences {
			pkgName := strings.TrimSpace(pkg.Include)
			if pkgName == "" {
				pkgName = strings.TrimSpace(pkg.Update)
			}
			if !strings.EqualFold(pkgName, query) && !strings.EqualFold(shortPkgName(pkgName), query) {
				continue
			}

			ver := strings.TrimSpace(pkg.VersionAttr)
			if ver == "" {
				ver = strings.TrimSpace(pkg.VersionElem)
			}

			repo := strings.TrimSpace(pkg.RepositoryURLAttr)
			if repo == "" {
				repo = strings.TrimSpace(pkg.RepositoryURLElem)
			}
			if repo == "" {
				repo = strings.TrimSpace(pkg.ProjectURLAttr)
			}
			if repo == "" {
				repo = strings.TrimSpace(pkg.ProjectURLElem)
			}
			if repo == "" {
				repo = strings.TrimSpace(pkg.ProjectURLAttr2)
			}
			if repo == "" {
				repo = strings.TrimSpace(pkg.ProjectURLElem2)
			}

			if repo == "" {
				repo = fmt.Sprintf("https://www.nuget.org/packages/%s", pkgName)
			}

			tracker, normRepo := ClassifyTracker("", "", repo)
			if tracker.URL != "" || tracker.Email != "" {
				return &Target{
					Query:         query,
					CanonicalName: pkgName,
					LocalVersion:  ver,
					Layer:         LayerWorkspace,
					RepositoryURL: normRepo,
					Tracker:       tracker,
				}, nil
			}
		}
	}

	return nil, ErrNotFound
}

func (w *WorkspaceProbe) parsePackagesConfig(ctx context.Context, configPath string, query string) (*Target, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	data, err := readBoundedFile(configPath)
	if err != nil {
		return nil, ErrNotFound
	}

	var cfg packagesConfig
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return nil, ErrNotFound
	}

	for _, pkg := range cfg.Packages {
		id := strings.TrimSpace(pkg.ID)
		if !strings.EqualFold(id, query) && !strings.EqualFold(shortPkgName(id), query) {
			continue
		}

		repo := strings.TrimSpace(pkg.RepositoryURL)
		if repo == "" {
			repo = strings.TrimSpace(pkg.ProjectURL)
		}
		if repo == "" {
			repo = fmt.Sprintf("https://www.nuget.org/packages/%s", id)
		}

		tracker, normRepo := ClassifyTracker("", "", repo)
		if tracker.URL != "" || tracker.Email != "" {
			return &Target{
				Query:         query,
				CanonicalName: id,
				LocalVersion:  strings.TrimSpace(pkg.Version),
				Layer:         LayerWorkspace,
				RepositoryURL: normRepo,
				Tracker:       tracker,
			}, nil
		}
	}

	return nil, ErrNotFound
}

// ----------------------------------------------------------------------------
// Ruby (Gemfile.lock / Gemfile) Parser
// ----------------------------------------------------------------------------

func (w *WorkspaceProbe) resolveRuby(ctx context.Context, query string) (*Target, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	lockPath := filepath.Join(w.rootDir, "Gemfile.lock")
	if data, err := readBoundedFile(lockPath); err == nil {
		if t, parseErr := w.parseGemfileLock(ctx, data, query); parseErr == nil && t != nil {
			return t, nil
		}
	}

	gemfilePath := filepath.Join(w.rootDir, "Gemfile")
	if data, err := readBoundedFile(gemfilePath); err == nil {
		if t, parseErr := w.parseGemfile(ctx, data, query); parseErr == nil && t != nil {
			return t, nil
		}
	}

	return nil, ErrNotFound
}

func (w *WorkspaceProbe) parseGemfileLock(ctx context.Context, data []byte, query string) (*Target, error) {
	lines := strings.Split(string(data), "\n")
	var currentSection string
	var currentRemote string

	for _, rawLine := range lines {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		trimmed := strings.TrimRight(rawLine, "\r\n")
		if strings.TrimSpace(trimmed) == "" {
			continue
		}

		if len(trimmed) > 0 && trimmed[0] != ' ' && trimmed[0] != '\t' {
			currentSection = strings.TrimSpace(trimmed)
			currentRemote = ""
			continue
		}

		lineTrimmed := strings.TrimSpace(trimmed)
		if strings.HasPrefix(lineTrimmed, "remote:") {
			currentRemote = strings.TrimSpace(strings.TrimPrefix(lineTrimmed, "remote:"))
			continue
		}

		if idx := strings.Index(lineTrimmed, " ("); idx != -1 && strings.HasSuffix(lineTrimmed, ")") {
			gemName := strings.TrimSpace(lineTrimmed[:idx])
			version := strings.TrimSpace(lineTrimmed[idx+2 : len(lineTrimmed)-1])

			if strings.EqualFold(gemName, query) {
				repoURL := currentRemote
				if currentSection == "GEM" && (repoURL == "" || repoURL == "https://rubygems.org/" || repoURL == "http://rubygems.org/") {
					if gfRepo := w.findGemfileGitSource(gemName); gfRepo != "" {
						repoURL = gfRepo
					} else {
						repoURL = fmt.Sprintf("https://rubygems.org/gems/%s", gemName)
					}
				}

				if repoURL != "" {
					tracker, normRepo := ClassifyTracker("", "", repoURL)
					if tracker.URL != "" || tracker.Email != "" {
						return &Target{
							Query:         query,
							CanonicalName: gemName,
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

	return nil, ErrNotFound
}

func (w *WorkspaceProbe) parseGemfile(ctx context.Context, data []byte, query string) (*Target, error) {
	lines := strings.Split(string(data), "\n")
	for _, rawLine := range lines {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "gem ") {
			continue
		}

		rest := strings.TrimSpace(strings.TrimPrefix(line, "gem "))
		parts := strings.Split(rest, ",")
		if len(parts) == 0 {
			continue
		}

		gemName := strings.Trim(strings.TrimSpace(parts[0]), `"'`)
		if !strings.EqualFold(gemName, query) {
			continue
		}

		var version, repoURL string
		for i := 1; i < len(parts); i++ {
			p := strings.TrimSpace(parts[i])
			if strings.HasPrefix(p, "github:") {
				val := strings.Trim(strings.TrimSpace(strings.TrimPrefix(p, "github:")), `"'`)
				repoURL = "https://github.com/" + val
			} else if strings.HasPrefix(p, ":github =>") {
				val := strings.Trim(strings.TrimSpace(strings.TrimPrefix(p, ":github =>")), `"'`)
				repoURL = "https://github.com/" + val
			} else if strings.HasPrefix(p, "git:") {
				repoURL = strings.Trim(strings.TrimSpace(strings.TrimPrefix(p, "git:")), `"'`)
			} else if strings.HasPrefix(p, ":git =>") {
				repoURL = strings.Trim(strings.TrimSpace(strings.TrimPrefix(p, ":git =>")), `"'`)
			} else if version == "" && (strings.HasPrefix(p, `"`) || strings.HasPrefix(p, `'`)) {
				version = strings.Trim(p, `"' `)
			}
		}

		if repoURL == "" {
			repoURL = fmt.Sprintf("https://rubygems.org/gems/%s", gemName)
		}

		tracker, normRepo := ClassifyTracker("", "", repoURL)
		if tracker.URL != "" || tracker.Email != "" {
			return &Target{
				Query:         query,
				CanonicalName: gemName,
				LocalVersion:  version,
				Layer:         LayerWorkspace,
				RepositoryURL: normRepo,
				Tracker:       tracker,
			}, nil
		}
	}

	return nil, ErrNotFound
}

func (w *WorkspaceProbe) findGemfileGitSource(gemName string) string {
	gemfilePath := filepath.Join(w.rootDir, "Gemfile")
	data, err := readBoundedFile(gemfilePath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "gem ") {
			continue
		}

		rest := strings.TrimSpace(strings.TrimPrefix(line, "gem "))
		parts := strings.Split(rest, ",")
		if len(parts) == 0 {
			continue
		}

		name := strings.Trim(strings.TrimSpace(parts[0]), `"'`)
		if !strings.EqualFold(name, gemName) {
			continue
		}

		for i := 1; i < len(parts); i++ {
			p := strings.TrimSpace(parts[i])
			if strings.HasPrefix(p, "github:") {
				val := strings.Trim(strings.TrimSpace(strings.TrimPrefix(p, "github:")), `"'`)
				return "https://github.com/" + val
			} else if strings.HasPrefix(p, ":github =>") {
				val := strings.Trim(strings.TrimSpace(strings.TrimPrefix(p, ":github =>")), `"'`)
				return "https://github.com/" + val
			} else if strings.HasPrefix(p, "git:") {
				return strings.Trim(strings.TrimSpace(strings.TrimPrefix(p, "git:")), `"'`)
			} else if strings.HasPrefix(p, ":git =>") {
				return strings.Trim(strings.TrimSpace(strings.TrimPrefix(p, ":git =>")), `"'`)
			}
		}
	}
	return ""
}

// ----------------------------------------------------------------------------
// PHP (composer.lock / composer.json) Parser
// ----------------------------------------------------------------------------

type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name     string          `json:"name"`
	Version  string          `json:"version"`
	Source   composerSource  `json:"source"`
	Homepage string          `json:"homepage"`
	Support  composerSupport `json:"support"`
}

type composerSource struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type composerSupport struct {
	Issues string `json:"issues"`
	Source string `json:"source"`
}

type composerManifest struct {
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	Homepage   string            `json:"homepage"`
	Support    composerSupport   `json:"support"`
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

func (w *WorkspaceProbe) resolvePHP(ctx context.Context, query string) (*Target, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	lockPath := filepath.Join(w.rootDir, "composer.lock")
	if data, err := readBoundedFile(lockPath); err == nil {
		if t, parseErr := w.parseComposerLock(ctx, data, query); parseErr == nil && t != nil {
			return t, nil
		}
	}

	jsonPath := filepath.Join(w.rootDir, "composer.json")
	if data, err := readBoundedFile(jsonPath); err == nil {
		if t, parseErr := w.parseComposerJSON(ctx, data, query); parseErr == nil && t != nil {
			return t, nil
		}
	}

	return nil, ErrNotFound
}

func (w *WorkspaceProbe) parseComposerLock(ctx context.Context, data []byte, query string) (*Target, error) {
	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, ErrNotFound
	}

	allPackages := append(lock.Packages, lock.PackagesDev...)
	for _, pkg := range allPackages {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		name := strings.TrimSpace(pkg.Name)
		isMatch := strings.EqualFold(name, query) ||
			strings.EqualFold(shortPkgName(name), query) ||
			strings.EqualFold(strings.ReplaceAll(name, "/", ":"), query)

		if !isMatch {
			continue
		}

		issuesURL := strings.TrimSpace(pkg.Support.Issues)
		repoURL := strings.TrimSpace(pkg.Support.Source)
		if repoURL == "" {
			repoURL = strings.TrimSpace(pkg.Source.URL)
		}
		if repoURL == "" {
			repoURL = strings.TrimSpace(pkg.Homepage)
		}
		if repoURL == "" && issuesURL == "" {
			repoURL = fmt.Sprintf("https://packagist.org/packages/%s", name)
		}

		tracker, normRepo := ClassifyTracker(issuesURL, "", repoURL)
		if tracker.URL != "" || tracker.Email != "" {
			return &Target{
				Query:         query,
				CanonicalName: name,
				LocalVersion:  strings.TrimSpace(pkg.Version),
				Layer:         LayerWorkspace,
				RepositoryURL: normRepo,
				Tracker:       tracker,
			}, nil
		}
	}

	return nil, ErrNotFound
}

func (w *WorkspaceProbe) parseComposerJSON(ctx context.Context, data []byte, query string) (*Target, error) {
	var manifest composerManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, ErrNotFound
	}

	// 1. Check root project match
	rootName := strings.TrimSpace(manifest.Name)
	if rootName != "" {
		isRootMatch := strings.EqualFold(rootName, query) ||
			strings.EqualFold(shortPkgName(rootName), query) ||
			strings.EqualFold(strings.ReplaceAll(rootName, "/", ":"), query)

		if isRootMatch {
			issuesURL := strings.TrimSpace(manifest.Support.Issues)
			repoURL := strings.TrimSpace(manifest.Support.Source)
			if repoURL == "" {
				repoURL = strings.TrimSpace(manifest.Homepage)
			}

			tracker, normRepo := ClassifyTracker(issuesURL, "", repoURL)
			if tracker.URL != "" || tracker.Email != "" {
				return &Target{
					Query:         query,
					CanonicalName: rootName,
					LocalVersion:  strings.TrimSpace(manifest.Version),
					Layer:         LayerWorkspace,
					RepositoryURL: normRepo,
					Tracker:       tracker,
				}, nil
			}
		}
	}

	// 2. Check require & require-dev
	checkMap := func(deps map[string]string) *Target {
		for depName, depVer := range deps {
			depName = strings.TrimSpace(depName)
			if strings.EqualFold(depName, query) ||
				strings.EqualFold(shortPkgName(depName), query) ||
				strings.EqualFold(strings.ReplaceAll(depName, "/", ":"), query) {
				repoURL := fmt.Sprintf("https://packagist.org/packages/%s", depName)
				tracker, normRepo := ClassifyTracker("", "", repoURL)
				if tracker.URL != "" || tracker.Email != "" {
					return &Target{
						Query:         query,
						CanonicalName: depName,
						LocalVersion:  strings.TrimSpace(depVer),
						Layer:         LayerWorkspace,
						RepositoryURL: normRepo,
						Tracker:       tracker,
					}
				}
			}
		}
		return nil
	}

	if t := checkMap(manifest.Require); t != nil {
		return t, nil
	}
	if t := checkMap(manifest.RequireDev); t != nil {
		return t, nil
	}

	return nil, ErrNotFound
}
