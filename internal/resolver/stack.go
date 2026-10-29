package resolver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// StackDependency represents a single discovered workspace dependency or internal service.
type StackDependency struct {
	Name          string  `json:"name"`
	Version       string  `json:"version,omitempty"`
	Ecosystem     string  `json:"ecosystem"` // "service", "gomod", "npm", "cargo", "pypi"
	Manifest      string  `json:"manifest"`  // e.g. "services.json", "go.mod", "package.json", "Cargo.toml", "pyproject.toml"
	Target        *Target `json:"target,omitempty"`
	ResolutionErr string  `json:"resolution_error,omitempty"`
}

// StackInventory holds the full dependency radar for a workspace directory.
type StackInventory struct {
	RootDir      string            `json:"root_dir"`
	ScannedAt    time.Time         `json:"scanned_at"`
	Total        int               `json:"total"`
	Resolved     int               `json:"resolved"`
	Dependencies []StackDependency `json:"dependencies"`
}

// parsePEP508 extracts package name and version constraint from a PEP 508 dependency string.
func parsePEP508(raw string) (string, string) {
	s := strings.Trim(raw, "[] \t\"'")
	if idx := strings.Index(s, ";"); idx != -1 {
		s = strings.TrimSpace(s[:idx])
	}
	if idx := strings.Index(s, "#"); idx != -1 {
		s = strings.TrimSpace(s[:idx])
	}
	// Strip parentheses e.g. "urllib3 (>= 1.26.0)"
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")
	s = strings.TrimSpace(s)

	operators := []string{"===", "==", ">=", "<=", "~=", "!=", ">", "<"}
	for _, op := range operators {
		if idx := strings.Index(s, op); idx != -1 {
			name := strings.TrimSpace(s[:idx])
			if bracket := strings.Index(name, "["); bracket != -1 {
				name = strings.TrimSpace(name[:bracket])
			}
			ver := strings.TrimSpace(s[idx:])
			return name, ver
		}
	}

	name := s
	if bracket := strings.Index(name, "["); bracket != -1 {
		name = strings.TrimSpace(name[:bracket])
	}
	return name, ""
}

// ScanWorkspaceManifests scans all supported manifest files in rootDir and returns
// a deduplicated, deterministically sorted slice of dependencies.
func ScanWorkspaceManifests(rootDir string) ([]StackDependency, error) {
	if strings.TrimSpace(rootDir) == "" {
		rootDir = "."
	}

	var allDeps []StackDependency

	// 1. Enterprise services.json
	svcPath := filepath.Join(rootDir, "services.json")
	if _, err := os.Stat(svcPath); err != nil {
		svcPath = resolveOrgCloudConfigPath()
	}
	if data, err := os.ReadFile(svcPath); err == nil {
		var reg OrgCloudRegistry
		if unmarshalErr := json.Unmarshal(data, &reg); unmarshalErr == nil {
			for _, svc := range reg.Services {
				name := strings.TrimSpace(svc.Name)
				if name != "" {
					allDeps = append(allDeps, StackDependency{
						Name:      name,
						Ecosystem: "service",
						Manifest:  "services.json",
					})
				}
			}
		}
	}

	// 2. Go go.mod
	goModPath := filepath.Join(rootDir, "go.mod")
	if file, err := os.Open(goModPath); err == nil {
		scanner := bufio.NewScanner(file)
		inRequireBlock := false
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			if line == "require (" {
				inRequireBlock = true
				continue
			}
			if inRequireBlock {
				if line == ")" {
					inRequireBlock = false
					continue
				}
				if idx := strings.Index(line, "//"); idx != -1 {
					line = strings.TrimSpace(line[:idx])
				}
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					allDeps = append(allDeps, StackDependency{
						Name:      fields[0],
						Version:   fields[1],
						Ecosystem: "gomod",
						Manifest:  "go.mod",
					})
				}
			} else if strings.HasPrefix(line, "require ") {
				line = strings.TrimPrefix(line, "require ")
				if idx := strings.Index(line, "//"); idx != -1 {
					line = strings.TrimSpace(line[:idx])
				}
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					allDeps = append(allDeps, StackDependency{
						Name:      fields[0],
						Version:   fields[1],
						Ecosystem: "gomod",
						Manifest:  "go.mod",
					})
				}
			}
		}
		if scanErr := scanner.Err(); scanErr != nil {
			file.Close()
			return nil, fmt.Errorf("read go.mod: %w", scanErr)
		}
		file.Close()
	}

	// 3. Node.js package.json
	pkgJsonPath := filepath.Join(rootDir, "package.json")
	if data, err := os.ReadFile(pkgJsonPath); err == nil {
		var pkg struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if unmarshalErr := json.Unmarshal(data, &pkg); unmarshalErr == nil {
			for k, v := range pkg.Dependencies {
				name := strings.TrimSpace(k)
				if name != "" {
					allDeps = append(allDeps, StackDependency{
						Name:      name,
						Version:   v,
						Ecosystem: "npm",
						Manifest:  "package.json",
					})
				}
			}
			for k, v := range pkg.DevDependencies {
				name := strings.TrimSpace(k)
				if name != "" {
					allDeps = append(allDeps, StackDependency{
						Name:      name,
						Version:   v,
						Ecosystem: "npm",
						Manifest:  "package.json",
					})
				}
			}
		}
	}

	// 4. Rust Cargo.toml
	cargoPath := filepath.Join(rootDir, "Cargo.toml")
	if data, err := os.ReadFile(cargoPath); err == nil {
		lines := strings.Split(string(data), "\n")
		var currentSection string
		var subCrateName, subCrateVer string
		var inSubCrateSection bool

		flushSubCrate := func() {
			if inSubCrateSection && subCrateName != "" {
				allDeps = append(allDeps, StackDependency{
					Name:      subCrateName,
					Version:   subCrateVer,
					Ecosystem: "cargo",
					Manifest:  "Cargo.toml",
				})
				inSubCrateSection = false
				subCrateName = ""
				subCrateVer = ""
			}
		}

		for _, rawLine := range lines {
			line := stripTOMLComment(rawLine)
			if line == "" {
				continue
			}

			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				flushSubCrate()
				currentSection = strings.Trim(line, "[] \t")
				lowerSec := strings.ToLower(currentSection)
				for _, prefix := range []string{"dependencies.", "dev-dependencies.", "build-dependencies.", "workspace.dependencies."} {
					if strings.HasPrefix(lowerSec, prefix) {
						inSubCrateSection = true
						subCrateName = strings.TrimPrefix(lowerSec, prefix)
						break
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

			lowerSec := strings.ToLower(currentSection)
			isDepSection := lowerSec == "dependencies" ||
				lowerSec == "dev-dependencies" ||
				lowerSec == "build-dependencies" ||
				lowerSec == "workspace.dependencies"

			if isDepSection {
				var ver string
				if strings.HasPrefix(val, "{") && strings.HasSuffix(val, "}") {
					ver = extractInlineTableField(val, "version")
				} else {
					ver = extractTOMLValue(val)
				}
				if key != "" {
					allDeps = append(allDeps, StackDependency{
						Name:      key,
						Version:   ver,
						Ecosystem: "cargo",
						Manifest:  "Cargo.toml",
					})
				}
			} else if inSubCrateSection {
				if strings.EqualFold(key, "version") {
					subCrateVer = extractTOMLValue(val)
				}
			}
		}
		flushSubCrate()
	}

	// 5. Python pyproject.toml
	pyPath := filepath.Join(rootDir, "pyproject.toml")
	if data, err := os.ReadFile(pyPath); err == nil {
		lines := strings.Split(string(data), "\n")
		var currentSection string
		var inDependenciesArray bool

		for _, rawLine := range lines {
			line := stripTOMLComment(rawLine)
			if line == "" {
				continue
			}

			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				currentSection = strings.Trim(line, "[] \t")
				inDependenciesArray = false
				continue
			}

			lowerSec := strings.ToLower(currentSection)

			if inDependenciesArray {
				if strings.HasSuffix(line, "]") {
					inDependenciesArray = false
					line = strings.TrimSuffix(line, "]")
				}
				parts := strings.Split(line, ",")
				for _, part := range parts {
					name, ver := parsePEP508(part)
					if name != "" {
						allDeps = append(allDeps, StackDependency{
							Name:      name,
							Version:   ver,
							Ecosystem: "pypi",
							Manifest:  "pyproject.toml",
						})
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

			if lowerSec == "project" {
				if strings.EqualFold(key, "dependencies") {
					if strings.HasPrefix(val, "[") && !strings.HasSuffix(val, "]") {
						inDependenciesArray = true
						val = strings.TrimPrefix(val, "[")
					} else if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
						val = strings.Trim(val, "[] \t")
					}
					parts := strings.Split(val, ",")
					for _, part := range parts {
						name, ver := parsePEP508(part)
						if name != "" {
							allDeps = append(allDeps, StackDependency{
								Name:      name,
								Version:   ver,
								Ecosystem: "pypi",
								Manifest:  "pyproject.toml",
							})
						}
					}
				}
			} else if lowerSec == "tool.poetry.dependencies" {
				if !strings.EqualFold(key, "python") && key != "" {
					var ver string
					if strings.HasPrefix(val, "{") && strings.HasSuffix(val, "}") {
						ver = extractInlineTableField(val, "version")
					} else {
						ver = extractTOMLValue(val)
					}
					allDeps = append(allDeps, StackDependency{
						Name:      key,
						Version:   ver,
						Ecosystem: "pypi",
						Manifest:  "pyproject.toml",
					})
				}
			}
		}
	}

	// Deduplicate entries by Ecosystem + ":" + Name
	seen := make(map[string]bool)
	var unique []StackDependency
	for _, d := range allDeps {
		if d.Name == "" {
			continue
		}
		dedupKey := d.Ecosystem + ":" + d.Name
		if !seen[dedupKey] {
			seen[dedupKey] = true
			unique = append(unique, d)
		}
	}

	// Sort deterministically by Ecosystem then Name
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Ecosystem != unique[j].Ecosystem {
			return unique[i].Ecosystem < unique[j].Ecosystem
		}
		return unique[i].Name < unique[j].Name
	})

	return unique, nil
}

// ScanStack scans the workspace manifests in rootDir and resolves each dependency
// to its canonical tracker using the Waterfall resolution engine.
func (w *Waterfall) ScanStack(ctx context.Context, rootDir string) (*StackInventory, error) {
	deps, err := ScanWorkspaceManifests(rootDir)
	if err != nil {
		return nil, fmt.Errorf("scan workspace manifests: %w", err)
	}

	results := make([]StackDependency, len(deps))
	copy(results, deps)

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var resolvedCount int64

	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			target, resolveErr := w.Resolve(ctx, results[idx].Name)
			if resolveErr != nil {
				results[idx].ResolutionErr = resolveErr.Error()
			} else if target != nil {
				if results[idx].Version != "" && target.LocalVersion == "" {
					target.LocalVersion = results[idx].Version
				}
				results[idx].Target = target
				atomic.AddInt64(&resolvedCount, 1)
			}
		}(i)
	}
	wg.Wait()

	scanRoot := rootDir
	if strings.TrimSpace(scanRoot) == "" {
		scanRoot = "."
	}

	return &StackInventory{
		RootDir:      scanRoot,
		ScannedAt:    time.Now().UTC(),
		Total:        len(results),
		Resolved:     int(resolvedCount),
		Dependencies: results,
	}, nil
}
