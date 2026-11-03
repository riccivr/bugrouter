package adapter

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MaxManifestReadBytes limits manifest ingestion to 1 MiB to prevent memory exhaustion.
const MaxManifestReadBytes = 1024 * 1024

// ScanWorkspacePatches scans rootDir for local dependency forks and vendor patches
// across go.mod, package.json, Cargo.toml, pyproject.toml, and patches/*.patch.
// File reads are bounded to MaxManifestReadBytes (1 MiB). Results are deterministically sorted.
func ScanWorkspacePatches(rootDir string) ([]DependencyPatch, error) {
	info, err := os.Stat(rootDir)
	if err != nil {
		return nil, fmt.Errorf("stat workspace root %s: %w", rootDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("workspace root %s is not a directory", rootDir)
	}

	var all []DependencyPatch

	// 1. go.mod
	goModPath := filepath.Join(rootDir, "go.mod")
	if data, readErr := readBoundedManifest(goModPath); readErr == nil {
		all = append(all, parseGoModPatches(data)...)
	} else if !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("scan go.mod: %w", readErr)
	}

	// 2. package.json
	pkgJSONPath := filepath.Join(rootDir, "package.json")
	if data, readErr := readBoundedManifest(pkgJSONPath); readErr == nil {
		all = append(all, parsePackageJSONPatches(data)...)
	} else if !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("scan package.json: %w", readErr)
	}

	// 3. patches/ directory
	dirPatches, dirErr := scanPatchesDir(rootDir)
	if dirErr != nil {
		return nil, fmt.Errorf("scan patches dir: %w", dirErr)
	}
	all = append(all, dirPatches...)

	// 4. Cargo.toml
	cargoPath := filepath.Join(rootDir, "Cargo.toml")
	if data, readErr := readBoundedManifest(cargoPath); readErr == nil {
		all = append(all, parseCargoTomlPatches(data)...)
	} else if !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("scan Cargo.toml: %w", readErr)
	}

	// 5. pyproject.toml
	pyPath := filepath.Join(rootDir, "pyproject.toml")
	if data, readErr := readBoundedManifest(pyPath); readErr == nil {
		all = append(all, parsePyprojectTomlPatches(data)...)
	} else if !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("scan pyproject.toml: %w", readErr)
	}

	// Deduplicate by (strings.ToLower(Dependency), PatchTarget)
	seen := make(map[string]bool)
	var deduped []DependencyPatch
	for _, p := range all {
		key := strings.ToLower(strings.TrimSpace(p.Dependency)) + "|" + strings.TrimSpace(p.PatchTarget)
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, p)
	}

	// Deterministic sort: Dependency, then PatchTarget, then ManifestFile
	sort.Slice(deduped, func(i, j int) bool {
		depI := strings.ToLower(deduped[i].Dependency)
		depJ := strings.ToLower(deduped[j].Dependency)
		if depI != depJ {
			return depI < depJ
		}
		targetI := strings.ToLower(deduped[i].PatchTarget)
		targetJ := strings.ToLower(deduped[j].PatchTarget)
		if targetI != targetJ {
			return targetI < targetJ
		}
		return deduped[i].ManifestFile < deduped[j].ManifestFile
	})

	if deduped == nil {
		deduped = []DependencyPatch{}
	}

	return deduped, nil
}

// SyncWorkspace scans rootDir for manifest patches, compares against existing patches
// in PatchStore, and records any newly discovered patches atomically.
// It returns the newly recorded patches, and is strictly idempotent.
func (s *PatchStore) SyncWorkspace(rootDir string) ([]DependencyPatch, error) {
	if s == nil {
		return nil, errors.New("patch store is nil")
	}

	scanned, err := ScanWorkspacePatches(rootDir)
	if err != nil {
		return nil, fmt.Errorf("scan workspace patches: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	patches, err := s.readPatchesLocked()
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read patches: %w", err)
	}

	existingSet := make(map[string]bool, len(patches))
	existingIDs := make(map[string]bool, len(patches))
	for _, p := range patches {
		key := strings.ToLower(strings.TrimSpace(p.Dependency)) + "|" + strings.TrimSpace(p.PatchTarget)
		existingSet[key] = true
		existingIDs[p.ID] = true
	}

	var newlyAdded []DependencyPatch
	for _, p := range scanned {
		key := strings.ToLower(strings.TrimSpace(p.Dependency)) + "|" + strings.TrimSpace(p.PatchTarget)
		if existingSet[key] {
			continue
		}
		existingSet[key] = true

		var id string
		for {
			b := make([]byte, 8)
			if _, err := rand.Read(b); err != nil {
				return nil, fmt.Errorf("generate patch id: %w", err)
			}
			id = hex.EncodeToString(b)
			if !existingIDs[id] {
				existingIDs[id] = true
				break
			}
		}

		ecosystem := strings.ToLower(strings.TrimSpace(p.Ecosystem))
		if ecosystem == "" {
			if strings.Contains(p.ManifestFile, "go.mod") || strings.Contains(p.Dependency, "github.com/") {
				ecosystem = "go"
			} else if strings.Contains(p.ManifestFile, "package.json") {
				ecosystem = "npm"
			} else if strings.Contains(p.ManifestFile, "Cargo.toml") {
				ecosystem = "cargo"
			} else if strings.Contains(p.ManifestFile, "pyproject.toml") {
				ecosystem = "python"
			} else {
				ecosystem = "custom"
			}
		}

		reason := strings.TrimSpace(p.Reason)
		if reason == "" {
			reason = "Discovered in workspace scan"
		}

		newPatch := DependencyPatch{
			ID:               id,
			CreatedAt:        time.Now().UTC(),
			Dependency:       strings.TrimSpace(p.Dependency),
			Ecosystem:        ecosystem,
			PatchTarget:      strings.TrimSpace(p.PatchTarget),
			ManifestFile:     strings.TrimSpace(p.ManifestFile),
			UpstreamIssueURL: strings.TrimSpace(p.UpstreamIssueURL),
			Reason:           reason,
			Status:           "active",
		}
		newlyAdded = append(newlyAdded, newPatch)
	}

	if len(newlyAdded) > 0 {
		merged := make([]DependencyPatch, 0, len(newlyAdded)+len(patches))
		merged = append(merged, newlyAdded...)
		merged = append(merged, patches...)
		if err := s.writePatchesLocked(merged); err != nil {
			return nil, err
		}
	} else if newlyAdded == nil {
		newlyAdded = []DependencyPatch{}
	}

	return newlyAdded, nil
}

func readBoundedManifest(path string) (data []byte, err error) {
	f, openErr := os.Open(path)
	if openErr != nil {
		return nil, openErr
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close %s: %w", path, closeErr)
		}
	}()

	buf, readErr := io.ReadAll(io.LimitReader(f, MaxManifestReadBytes))
	if readErr != nil {
		return nil, fmt.Errorf("read %s: %w", path, readErr)
	}
	return buf, nil
}

func parseGoModPatches(data []byte) []DependencyPatch {
	var patches []DependencyPatch
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), MaxManifestReadBytes)

	inReplaceBlock := false
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "//"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if inReplaceBlock {
			if strings.HasPrefix(line, ")") {
				inReplaceBlock = false
				continue
			}
			line = strings.TrimPrefix(line, "replace ")
			line = strings.TrimSpace(line)
			if p, ok := parseGoReplaceDirective(line); ok {
				patches = append(patches, p)
			}
			continue
		}

		if strings.HasPrefix(line, "replace (") || (strings.HasPrefix(line, "replace") && strings.HasSuffix(line, "(")) {
			inReplaceBlock = true
			continue
		}

		if strings.HasPrefix(line, "replace ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "replace"))
			if p, ok := parseGoReplaceDirective(line); ok {
				patches = append(patches, p)
			}
		}
	}
	return patches
}

func parseGoReplaceDirective(line string) (DependencyPatch, bool) {
	if !strings.Contains(line, "=>") {
		return DependencyPatch{}, false
	}
	parts := strings.SplitN(line, "=>", 2)
	left := strings.TrimSpace(parts[0])
	right := strings.TrimSpace(parts[1])
	if left == "" || right == "" {
		return DependencyPatch{}, false
	}

	leftFields := strings.Fields(left)
	if len(leftFields) == 0 {
		return DependencyPatch{}, false
	}
	dep := leftFields[0]

	return DependencyPatch{
		Dependency:   dep,
		Ecosystem:    "go",
		PatchTarget:  right,
		ManifestFile: "go.mod",
		Reason:       "Auto-detected go.mod replace directive",
		Status:       "active",
	}, true
}

func isNPMPatchOrForkValue(val string) bool {
	s := strings.TrimSpace(val)
	if s == "" {
		return false
	}
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "patch:") ||
		strings.HasPrefix(lower, "file:") ||
		strings.HasPrefix(lower, "link:") ||
		strings.HasPrefix(lower, "git+") ||
		strings.HasPrefix(lower, "git:") ||
		strings.HasPrefix(lower, "git@") ||
		strings.HasPrefix(lower, "github:") ||
		strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "./") ||
		strings.HasPrefix(lower, "../") ||
		strings.HasPrefix(lower, ".\\") ||
		strings.HasPrefix(lower, "..\\") ||
		strings.Contains(lower, ".patch")
}

func parsePackageJSONPatches(data []byte) []DependencyPatch {
	var manifest struct {
		Dependencies    map[string]any `json:"dependencies"`
		DevDependencies map[string]any `json:"devDependencies"`
		Overrides       map[string]any `json:"overrides"`
		Resolutions     map[string]any `json:"resolutions"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil
	}

	var patches []DependencyPatch

	checkDepMap := func(m map[string]any) {
		for dep, val := range m {
			str, ok := val.(string)
			if !ok {
				continue
			}
			str = strings.TrimSpace(str)
			if isNPMPatchOrForkValue(str) {
				patches = append(patches, DependencyPatch{
					Dependency:   dep,
					Ecosystem:    "npm",
					PatchTarget:  str,
					ManifestFile: "package.json",
					Reason:       "Auto-detected package.json dependency patch",
					Status:       "active",
				})
			}
		}
	}
	checkDepMap(manifest.Dependencies)
	checkDepMap(manifest.DevDependencies)

	var checkOverrides func(m map[string]any, parent string)
	checkOverrides = func(m map[string]any, parent string) {
		for k, v := range m {
			if str, ok := v.(string); ok {
				dep := k
				if dep == "." {
					dep = parent
				}
				if dep == "." || dep == "" {
					continue
				}
				str = strings.TrimSpace(str)
				if isNPMPatchOrForkValue(str) {
					patches = append(patches, DependencyPatch{
						Dependency:   dep,
						Ecosystem:    "npm",
						PatchTarget:  str,
						ManifestFile: "package.json",
						Reason:       "Auto-detected package.json overrides directive",
						Status:       "active",
					})
				}
			} else if subMap, ok := v.(map[string]any); ok {
				parentKey := k
				if parentKey == "." {
					parentKey = parent
				}
				checkOverrides(subMap, parentKey)
			}
		}
	}
	checkOverrides(manifest.Overrides, "")

	var checkResolutions func(m map[string]any, parent string)
	checkResolutions = func(m map[string]any, parent string) {
		for k, v := range m {
			if str, ok := v.(string); ok {
				dep := k
				if dep == "." {
					dep = parent
				}
				if dep == "." || dep == "" {
					continue
				}
				str = strings.TrimSpace(str)
				if isNPMPatchOrForkValue(str) {
					patches = append(patches, DependencyPatch{
						Dependency:   dep,
						Ecosystem:    "npm",
						PatchTarget:  str,
						ManifestFile: "package.json",
						Reason:       "Auto-detected package.json resolutions directive",
						Status:       "active",
					})
				}
			} else if subMap, ok := v.(map[string]any); ok {
				parentKey := k
				if parentKey == "." {
					parentKey = parent
				}
				checkResolutions(subMap, parentKey)
			}
		}
	}
	checkResolutions(manifest.Resolutions, "")

	return patches
}

func scanPatchesDir(rootDir string) ([]DependencyPatch, error) {
	patchesDir := filepath.Join(rootDir, "patches")
	entries, err := os.ReadDir(patchesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read patches directory %s: %w", patchesDir, err)
	}

	var patches []DependencyPatch
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".patch") {
			continue
		}

		base := strings.TrimSuffix(name, ".patch")
		var dep string
		if strings.HasPrefix(base, "@") {
			parts := strings.Split(base, "+")
			if len(parts) >= 2 {
				dep = parts[0] + "/" + parts[1]
			} else {
				dep = base
			}
		} else {
			parts := strings.Split(base, "+")
			dep = parts[0]
		}

		dep = strings.TrimSpace(dep)
		if dep == "" {
			continue
		}

		target := filepath.ToSlash(filepath.Join("patches", name))
		patches = append(patches, DependencyPatch{
			Dependency:   dep,
			Ecosystem:    "npm",
			PatchTarget:  target,
			ManifestFile: "package.json",
			Reason:       "Auto-detected vendor patch in patches/",
			Status:       "active",
		})
	}

	return patches, nil
}

func parseCargoTomlPatches(data []byte) []DependencyPatch {
	var patches []DependencyPatch
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), MaxManifestReadBytes)

	inPatchSection := false
	currentSubtableCrate := ""
	currentSubtableTarget := ""

	flushSubtable := func() {
		if currentSubtableCrate != "" && currentSubtableTarget != "" {
			patches = append(patches, DependencyPatch{
				Dependency:   currentSubtableCrate,
				Ecosystem:    "cargo",
				PatchTarget:  currentSubtableTarget,
				ManifestFile: "Cargo.toml",
				Reason:       "Auto-detected Cargo.toml patch directive",
				Status:       "active",
			})
		}
		currentSubtableCrate = ""
		currentSubtableTarget = ""
	}

	for scanner.Scan() {
		rawLine := scanner.Text()
		line := stripTomlComment(rawLine)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flushSubtable()
			section := strings.TrimSpace(line[1 : len(line)-1])
			lowerSection := strings.ToLower(section)

			if strings.HasPrefix(lowerSection, "patch.") {
				inPatchSection = true
				parts := strings.Split(section, ".")
				if len(parts) >= 3 {
					currentSubtableCrate = strings.Trim(strings.TrimSpace(parts[2]), `"'`)
				} else {
					currentSubtableCrate = ""
				}
			} else if lowerSection == "patch" {
				inPatchSection = true
				currentSubtableCrate = ""
			} else {
				inPatchSection = false
				currentSubtableCrate = ""
			}
			continue
		}

		if !inPatchSection {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.Trim(strings.TrimSpace(parts[0]), `"'`)
		val := strings.TrimSpace(parts[1])

		if currentSubtableCrate != "" {
			cleanVal := strings.Trim(val, `"'`)
			if key == "path" || (key == "git" && currentSubtableTarget == "") {
				currentSubtableTarget = cleanVal
			}
		} else {
			target := extractCargoTarget(val)
			if key != "" && target != "" {
				patches = append(patches, DependencyPatch{
					Dependency:   key,
					Ecosystem:    "cargo",
					PatchTarget:  target,
					ManifestFile: "Cargo.toml",
					Reason:       "Auto-detected Cargo.toml patch directive",
					Status:       "active",
				})
			}
		}
	}
	flushSubtable()
	return patches
}

func extractCargoTarget(val string) string {
	val = strings.TrimSpace(val)
	if strings.HasPrefix(val, "{") && strings.HasSuffix(val, "}") {
		inner := strings.TrimSpace(val[1 : len(val)-1])
		pairs := splitInlineTablePairs(inner)
		var pathTarget, gitTarget string
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) != 2 {
				continue
			}
			k := strings.ToLower(strings.Trim(strings.TrimSpace(kv[0]), `"'`))
			v := strings.Trim(strings.TrimSpace(kv[1]), `"'`)
			if k == "path" {
				pathTarget = v
			} else if k == "git" && gitTarget == "" {
				gitTarget = v
			}
		}
		if pathTarget != "" {
			return pathTarget
		}
		if gitTarget != "" {
			return gitTarget
		}
		return ""
	}
	return strings.Trim(val, `"'`)
}

func splitInlineTablePairs(s string) []string {
	var pairs []string
	var cur strings.Builder
	inQuote := false
	var quoteChar rune
	escaped := false
	bracketDepth := 0
	braceDepth := 0

	for _, r := range s {
		if inQuote {
			cur.WriteRune(r)
			if escaped {
				escaped = false
			} else if r == '\\' && quoteChar == '"' {
				escaped = true
			} else if r == quoteChar {
				inQuote = false
			}
			continue
		}

		switch r {
		case '"', '\'':
			inQuote = true
			quoteChar = r
			cur.WriteRune(r)
		case '[':
			bracketDepth++
			cur.WriteRune(r)
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
			cur.WriteRune(r)
		case '{':
			braceDepth++
			cur.WriteRune(r)
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
			cur.WriteRune(r)
		case ',':
			if bracketDepth == 0 && braceDepth == 0 {
				pairs = append(pairs, cur.String())
				cur.Reset()
			} else {
				cur.WriteRune(r)
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		pairs = append(pairs, cur.String())
	}
	return pairs
}

func parsePyprojectTomlPatches(data []byte) []DependencyPatch {
	var patches []DependencyPatch
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), MaxManifestReadBytes)

	inDepsSection := false
	for scanner.Scan() {
		rawLine := scanner.Text()
		line := stripTomlComment(rawLine)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.TrimSpace(line[1 : len(line)-1])
			lower := strings.ToLower(section)
			if strings.Contains(lower, "dependencies") || strings.Contains(lower, "overrides") {
				inDepsSection = true
			} else {
				inDepsSection = false
			}
			continue
		}

		if !inDepsSection {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		dep := strings.Trim(strings.TrimSpace(parts[0]), `"'`)
		val := strings.TrimSpace(parts[1])

		target := extractCargoTarget(val)
		if strings.HasPrefix(val, "{") && target != "" && target != val {
			patches = append(patches, DependencyPatch{
				Dependency:   dep,
				Ecosystem:    "python",
				PatchTarget:  target,
				ManifestFile: "pyproject.toml",
				Reason:       "Auto-detected pyproject.toml local/fork dependency",
				Status:       "active",
			})
		}
	}
	return patches
}

func stripTomlComment(line string) string {
	inQuote := false
	var quoteChar rune
	for i, r := range line {
		if inQuote {
			if r == quoteChar {
				inQuote = false
			}
		} else {
			if r == '"' || r == '\'' {
				inQuote = true
				quoteChar = r
			} else if r == '#' {
				return line[:i]
			}
		}
	}
	return line
}
