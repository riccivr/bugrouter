package resolver

import (
	"regexp"
	"strings"

	"github.com/riccivr/bugrouter/internal/scrubber"
)

// TraceCandidate represents an extracted dependency, module, or binary candidate from a crash log.
type TraceCandidate struct {
	Query    string `json:"query"`
	Source   string `json:"source"`
	Evidence string `json:"evidence"`
}

var (
	// Node.js node_modules path pattern (supports scoped @org/pkg and standard packages)
	nodeModulesRegex = regexp.MustCompile(`node_modules/(@[a-zA-Z0-9-._~]+/[a-zA-Z0-9-._~]+|[a-zA-Z0-9-._~]+)/`)

	// Go module import path pattern in stack traces
	goModuleRegex = regexp.MustCompile(`((?:github\.com|gitlab\.com|codeberg\.org)/[a-zA-Z0-9\-_~]+/[a-zA-Z0-9\-_~]+)`)

	// Python site-packages and dist-packages paths
	pythonPkgRegex = regexp.MustCompile(`(?:site-packages|dist-packages)/([a-zA-Z0-9_.-]+)`)

	// Rust Cargo registry dependency paths
	rustCrateRegex = regexp.MustCompile(`\.cargo/registry/src/[^/]+/([a-zA-Z0-9_-]+)-\d+\.\d+\.\d+/`)

	// CLI binary prefix errors at the start of a line
	cliBinaryRegex = regexp.MustCompile(`^([a-zA-Z0-9._+-]+):\s*(?:command not found|error|fatal|segmentation fault|panic|unrecognized option)`)
)

// Generic binary prefixes to exclude to avoid false-positive attribution
var genericBinaryPrefixes = map[string]bool{
	"error":   true,
	"fatal":   true,
	"warning": true,
	"sh":      true,
	"bash":    true,
	"zsh":     true,
	"sudo":    true,
}

// ExtractTargetsFromLog scans rawLog deterministically and extracts unique candidates (up to 5, preserving first-seen order).
func ExtractTargetsFromLog(rawLog string) []TraceCandidate {
	var candidates []TraceCandidate
	seen := make(map[string]bool)

	addCandidate := func(query, source, evidence string) bool {
		norm := strings.TrimSpace(query)
		if norm == "" || seen[norm] {
			return false
		}
		seen[norm] = true

		cleanEvidence := string(scrubber.Scrub(strings.TrimSpace(evidence)))
		if len(cleanEvidence) > 200 {
			cleanEvidence = cleanEvidence[:197] + "..."
		}

		candidates = append(candidates, TraceCandidate{
			Query:    norm,
			Source:   source,
			Evidence: cleanEvidence,
		})
		return len(candidates) >= 5
	}

	lines := strings.Split(rawLog, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// 1. Node.js node_modules
		if m := nodeModulesRegex.FindStringSubmatch(trimmed); len(m) > 1 {
			pkg := strings.TrimSuffix(m[1], "/")
			if addCandidate(pkg, "node_modules", trimmed) {
				return candidates
			}
		}

		// 2. Go module paths
		if m := goModuleRegex.FindStringSubmatch(trimmed); len(m) > 1 {
			if addCandidate(m[1], "go_module", trimmed) {
				return candidates
			}
		}

		// 3. Python site-packages / dist-packages
		if m := pythonPkgRegex.FindStringSubmatch(trimmed); len(m) > 1 {
			pkg := m[1]
			pkg = strings.TrimSuffix(pkg, ".py")
			if idx := strings.Index(pkg, ".dist-info"); idx > 0 {
				pkg = pkg[:idx]
			}
			if addCandidate(pkg, "python_pkg", trimmed) {
				return candidates
			}
		}

		// 4. Rust Cargo registry paths
		if m := rustCrateRegex.FindStringSubmatch(trimmed); len(m) > 1 {
			if addCandidate(m[1], "rust_crate", trimmed) {
				return candidates
			}
		}

		// 5. CLI binary prefix errors
		if m := cliBinaryRegex.FindStringSubmatch(trimmed); len(m) > 1 {
			bin := strings.ToLower(m[1])
			if !genericBinaryPrefixes[bin] {
				if addCandidate(m[1], "cli_binary", trimmed) {
					return candidates
				}
			}
		}
	}

	return candidates
}
