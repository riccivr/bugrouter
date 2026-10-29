package resolver

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/riccivr/bugrouter/internal/scrubber"
)

// CrashReport holds structured metadata and suspect targets parsed from a crash trace.
type CrashReport struct {
	Language        string   `json:"language"`
	ErrorType       string   `json:"error_type"`
	Message         string   `json:"message"`
	CulpritFile     string   `json:"culprit_file,omitempty"`
	CulpritLine     int      `json:"culprit_line,omitempty"`
	CulpritFunction string   `json:"culprit_function,omitempty"`
	SuspectTargets  []string `json:"suspect_targets"`
	PrimaryTarget   string   `json:"primary_target,omitempty"`
	RawLog          string   `json:"raw_log"`
}

// SuggestedTitle constructs a concise, structured title for the crash.
func (r *CrashReport) SuggestedTitle() string {
	errType := strings.TrimSpace(r.ErrorType)
	msg := strings.TrimSpace(r.Message)
	if errType == "" && msg == "" {
		errType = "Application Crash"
	}

	var title string
	switch {
	case r.PrimaryTarget != "" && errType != "" && msg != "":
		title = fmt.Sprintf("[%s] %s: %s", r.PrimaryTarget, errType, msg)
	case r.PrimaryTarget != "" && errType != "":
		title = fmt.Sprintf("[%s] %s", r.PrimaryTarget, errType)
	case errType != "" && msg != "":
		title = fmt.Sprintf("%s: %s", errType, msg)
	default:
		title = errType
	}

	// Collapse whitespace and cap title length to prevent bloated issue titles
	title = strings.Join(strings.Fields(title), " ")
	const maxLen = 100
	if len(title) > maxLen {
		title = title[:maxLen-3] + "..."
	}
	return title
}

// SuggestedSummary builds an explanatory summary of the crash location.
func (r *CrashReport) SuggestedSummary() string {
	var sb strings.Builder
	sb.WriteString("A crash occurred")
	if r.PrimaryTarget != "" {
		sb.WriteString(fmt.Sprintf(" attributed to target %s", r.PrimaryTarget))
	}
	if r.Language != "" && r.Language != "unknown" {
		sb.WriteString(fmt.Sprintf(" in %s runtime", r.Language))
	}
	sb.WriteString(".\n\n")

	if r.ErrorType != "" || r.Message != "" {
		sb.WriteString(fmt.Sprintf("- **Error:** %s\n", r.ErrorType))
		if r.Message != "" {
			sb.WriteString(fmt.Sprintf("- **Details:** %s\n", r.Message))
		}
	}
	if r.CulpritFile != "" {
		sb.WriteString(fmt.Sprintf("- **File:** %s\n", r.CulpritFile))
	}
	if r.CulpritLine > 0 {
		sb.WriteString(fmt.Sprintf("- **Line:** %d\n", r.CulpritLine))
	}
	if r.CulpritFunction != "" {
		sb.WriteString(fmt.Sprintf("- **Function:** `%s`\n", r.CulpritFunction))
	}
	return strings.TrimSpace(sb.String())
}

// SuggestedSteps formats deterministic reproduction steps based on the failing symbol.
func (r *CrashReport) SuggestedSteps() string {
	target := r.PrimaryTarget
	if target == "" {
		target = "target component"
	}
	fn := r.CulpritFunction
	if fn == "" {
		fn = "failing execution path"
	}

	return fmt.Sprintf("1. Invoke %s via %s.\n2. Supply workload triggering the failure.\n3. Observe crash with %s.", target, fn, r.ErrorType)
}

// CleanTrace returns the scrubbed crash log capped at 16 KiB to prevent payload exhaustion.
func (r *CrashReport) CleanTrace() string {
	scrubbed := string(scrubber.Scrub(r.RawLog))
	const maxTraceBytes = 16 * 1024
	if len(scrubbed) > maxTraceBytes {
		return scrubbed[:maxTraceBytes] + "\n... [trace truncated]"
	}
	return scrubbed
}

// TraceAttributor maps crash stack traces to upstream targets using the waterfall engine.
type TraceAttributor struct {
	waterfall *Waterfall
}

// NewTraceAttributor creates an attributor backed by a waterfall resolver.
func NewTraceAttributor(wf *Waterfall) *TraceAttributor {
	return &TraceAttributor{waterfall: wf}
}

// AttributeAndResolve parses a crash trace and resolves the best matching candidate target.
func (a *TraceAttributor) AttributeAndResolve(ctx context.Context, raw string) (*Target, *CrashReport, error) {
	report := ParseCrashTrace(raw)
	if report == nil {
		return nil, nil, errors.New("failed to parse crash trace")
	}

	if a.waterfall == nil {
		return nil, report, nil
	}

	for _, suspect := range report.SuspectTargets {
		target, err := a.waterfall.Resolve(ctx, suspect)
		if err == nil && target != nil {
			report.PrimaryTarget = target.CanonicalName
			return target, report, nil
		}
	}

	if report.PrimaryTarget != "" {
		target, err := a.waterfall.Resolve(ctx, report.PrimaryTarget)
		if err == nil && target != nil {
			return target, report, nil
		}
	}

	return nil, report, ErrNotFound
}

// ParseCrashTrace deterministically analyzes crash log text to extract stack trace metadata.
func ParseCrashTrace(raw string) *CrashReport {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return &CrashReport{
			Language:  "unknown",
			ErrorType: "UnknownError",
			Message:   "Empty crash log",
			RawLog:    raw,
		}
	}

	cleanRaw := string(scrubber.Scrub(trimmed))

	// Probe parsers in order of trace specificity
	if rep := parseGoPanic(cleanRaw); rep != nil {
		finalizeReport(rep)
		return rep
	}
	if rep := parsePythonTraceback(cleanRaw); rep != nil {
		finalizeReport(rep)
		return rep
	}
	if rep := parseNodeStackTrace(cleanRaw); rep != nil {
		finalizeReport(rep)
		return rep
	}
	if rep := parseRustPanic(cleanRaw); rep != nil {
		finalizeReport(rep)
		return rep
	}
	if rep := parseNativeCrash(cleanRaw); rep != nil {
		finalizeReport(rep)
		return rep
	}

	rep := parseGenericCrash(cleanRaw)
	finalizeReport(rep)
	return rep
}

func finalizeReport(r *CrashReport) {
	r.SuspectTargets = deduplicateSuspects(r.SuspectTargets)
	if r.PrimaryTarget == "" && len(r.SuspectTargets) > 0 {
		r.PrimaryTarget = r.SuspectTargets[0]
	}
}

func deduplicateSuspects(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		norm := strings.TrimSpace(s)
		if norm == "" || seen[norm] {
			continue
		}
		seen[norm] = true
		out = append(out, norm)
	}
	return out
}

// Go panic patterns
var (
	goPanicRegex      = regexp.MustCompile(`(?m)^panic:\s*(.+)$`)
	goGoroutineRegex  = regexp.MustCompile(`(?m)^goroutine\s+\d+\s+\[([^\]]+)\]:`)
	goFrameFuncRegex  = regexp.MustCompile(`^([a-zA-Z0-9_\-\./]+(?:\.[a-zA-Z0-9_\-\./]+)*(?:\.\(\*[^\)]+\))?(?:\.[a-zA-Z0-9_]+)+)\(.*\)$`)
	goFrameLocRegex   = regexp.MustCompile(`^\s*(.+):(\d+)(?:\s+\+0x[0-9a-fA-F]+)?$`)
	goModPathRegex    = regexp.MustCompile(`(?:^|/)(?:go/)?pkg/mod/([a-zA-Z0-9_\-\.]+(?:/[a-zA-Z0-9_\-\.]+)+)@[^/]+/(.+)$`)
	goModuleRepoRegex = regexp.MustCompile(`^(github\.com/[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+|gitlab\.com/[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+|golang\.org/x/[a-zA-Z0-9_\-\.]+)`)
)

func parseGoPanic(raw string) *CrashReport {
	if !strings.Contains(raw, "panic:") && !goGoroutineRegex.MatchString(raw) {
		return nil
	}

	r := &CrashReport{
		Language:  "go",
		ErrorType: "panic",
		RawLog:    raw,
	}

	if m := goPanicRegex.FindStringSubmatch(raw); len(m) > 1 {
		r.Message = strings.TrimSpace(m[1])
	}

	lines := strings.Split(raw, "\n")
	var suspects []string
	inGoroutine := false
	var lastFunc string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if goGoroutineRegex.MatchString(trimmed) {
			inGoroutine = true
			continue
		}
		if !inGoroutine {
			continue
		}

		if goFrameFuncRegex.MatchString(trimmed) {
			m := goFrameFuncRegex.FindStringSubmatch(trimmed)
			lastFunc = m[1]
			continue
		}

		if goFrameLocRegex.MatchString(trimmed) && lastFunc != "" {
			m := goFrameLocRegex.FindStringSubmatch(trimmed)
			filePath := m[1]
			lineNo, _ := strconv.Atoi(m[2])

			// Ignore Go runtime frames for culprit attribution
			if strings.HasPrefix(filePath, "runtime/") || strings.Contains(filePath, "/src/runtime/") {
				lastFunc = ""
				continue
			}

			if r.CulpritFile == "" {
				r.CulpritFile = filePath
				r.CulpritLine = lineNo
				r.CulpritFunction = lastFunc
			}

			if modMatch := goModPathRegex.FindStringSubmatch(filePath); len(modMatch) > 1 {
				mod := modMatch[1]
				suspects = append(suspects, mod)
			} else if repoMatch := goModuleRepoRegex.FindStringSubmatch(lastFunc); len(repoMatch) > 1 {
				suspects = append(suspects, repoMatch[1])
			} else if parts := strings.Split(lastFunc, "/"); len(parts) > 1 {
				// Fallback to top-level package name
				pkgPart := parts[len(parts)-1]
				dotParts := strings.Split(pkgPart, ".")
				if len(dotParts) > 0 && dotParts[0] != "main" && dotParts[0] != "runtime" {
					suspects = append(suspects, dotParts[0])
				}
			}

			lastFunc = ""
		}
	}

	r.SuspectTargets = suspects
	return r
}

// Python traceback patterns
var (
	pyTracebackStartRegex = regexp.MustCompile(`(?m)^Traceback \(most recent call last\):`)
	pyFrameRegex          = regexp.MustCompile(`^\s*File\s+"([^"]+)",\s+line\s+(\d+)(?:,\s+in\s+(.+))?`)
	pyExceptionRegex      = regexp.MustCompile(`^([a-zA-Z0-9_\.]+(?:Error|Exception|Interrupt|Exit|Fault|Warning))(?::\s*(.*))?$`)
	pySitePkgRegex        = regexp.MustCompile(`(?:site-packages|dist-packages)/([a-zA-Z0-9_\-]+)`)
)

func parsePythonTraceback(raw string) *CrashReport {
	if !pyTracebackStartRegex.MatchString(raw) && !strings.Contains(raw, "Traceback (most recent call last):") {
		return nil
	}

	r := &CrashReport{
		Language:  "python",
		ErrorType: "Exception",
		RawLog:    raw,
	}

	lines := strings.Split(raw, "\n")
	var suspects []string

	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		if m := pyExceptionRegex.FindStringSubmatch(line); len(m) > 1 && r.ErrorType == "Exception" {
			r.ErrorType = m[1]
			if len(m) > 2 {
				r.Message = strings.TrimSpace(m[2])
			}
			parts := strings.Split(r.ErrorType, ".")
			if len(parts) > 1 && parts[0] != "builtins" {
				suspects = append(suspects, parts[0])
			}
			continue
		}

		if m := pyFrameRegex.FindStringSubmatch(lines[i]); len(m) > 1 {
			filePath := m[1]
			lineNo, _ := strconv.Atoi(m[2])
			fn := ""
			if len(m) > 3 {
				fn = m[3]
			}

			// In Python, the last frame in the traceback is the immediate failing site
			if r.CulpritFile == "" {
				r.CulpritFile = filePath
				r.CulpritLine = lineNo
				r.CulpritFunction = fn
			}

			if pkgMatch := pySitePkgRegex.FindStringSubmatch(filePath); len(pkgMatch) > 1 {
				pkgName := pkgMatch[1]
				pkgName = strings.TrimSuffix(pkgName, ".py")
				suspects = append(suspects, pkgName)
			}
		}
	}

	r.SuspectTargets = suspects
	return r
}

// Node.js stack trace patterns
var (
	nodeErrorRegex     = regexp.MustCompile(`^([a-zA-Z0-9_]*Error|[a-zA-Z0-9_]*Exception):\s*(.*)$`)
	nodeFrameRegex     = regexp.MustCompile(`^\s*at\s+(?:([^\(]+?)\s+\()?([^\(\):]+):(\d+):(\d+)\)?$`)
	nodeModulePkgRegex = regexp.MustCompile(`node_modules/(@[a-zA-Z0-9_\-\.]+\/[a-zA-Z0-9_\-\.]+|[a-zA-Z0-9_\-\.]+)`)
)

func parseNodeStackTrace(raw string) *CrashReport {
	if !strings.Contains(raw, "    at ") && !strings.Contains(raw, "node_modules/") {
		return nil
	}

	lines := strings.Split(raw, "\n")
	var r *CrashReport
	var suspects []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if r == nil {
			if m := nodeErrorRegex.FindStringSubmatch(trimmed); len(m) > 1 {
				r = &CrashReport{
					Language:  "javascript",
					ErrorType: m[1],
					Message:   m[2],
					RawLog:    raw,
				}
				continue
			}
		}

		if m := nodeFrameRegex.FindStringSubmatch(line); len(m) > 2 {
			if r == nil {
				r = &CrashReport{
					Language:  "javascript",
					ErrorType: "Error",
					RawLog:    raw,
				}
			}

			fn := strings.TrimSpace(m[1])
			filePath := strings.TrimSpace(m[2])
			lineNo, _ := strconv.Atoi(m[3])

			if r.CulpritFile == "" && !strings.HasPrefix(filePath, "node:internal/") {
				r.CulpritFile = filePath
				r.CulpritLine = lineNo
				r.CulpritFunction = fn
			}

			if modMatch := nodeModulePkgRegex.FindStringSubmatch(filePath); len(modMatch) > 1 {
				suspects = append(suspects, modMatch[1])
			}
		}
	}

	if r != nil {
		r.SuspectTargets = suspects
	}
	return r
}

// Rust panic patterns
var (
	rustPanicRegex = regexp.MustCompile(`(?m)thread '([^']+)' panicked at (?:'([^']+)', )?([^:]+):(\d+):(\d+)`)
	rustCrateRegex = regexp.MustCompile(`(?:registry/src/[^/]+/|cargo/git/checkouts/[^/]+/[^/]+/)([a-zA-Z0-9_\-]+)-[0-9.]+`)
	rustFrameRegex = regexp.MustCompile(`^\s*\d+:\s*([a-zA-Z0-9_:]+)`)
)

func parseRustPanic(raw string) *CrashReport {
	if !strings.Contains(raw, "panicked at") && !strings.Contains(raw, "stack backtrace:") {
		return nil
	}

	r := &CrashReport{
		Language:  "rust",
		ErrorType: "panic",
		RawLog:    raw,
	}

	if m := rustPanicRegex.FindStringSubmatch(raw); len(m) > 3 {
		r.Message = m[2]
		r.CulpritFile = m[3]
		r.CulpritLine, _ = strconv.Atoi(m[4])
	}

	lines := strings.Split(raw, "\n")
	var suspects []string

	for _, line := range lines {
		if crateMatch := rustCrateRegex.FindStringSubmatch(line); len(crateMatch) > 1 {
			suspects = append(suspects, crateMatch[1])
		}
		if frameMatch := rustFrameRegex.FindStringSubmatch(line); len(frameMatch) > 1 {
			sym := frameMatch[1]
			parts := strings.Split(sym, "::")
			if len(parts) > 0 {
				root := parts[0]
				if root != "std" && root != "core" && root != "alloc" && root != "rust_begin_unwind" {
					suspects = append(suspects, root)
				}
			}
		}
	}

	r.SuspectTargets = suspects
	return r
}

// Native segfault and signal patterns
var (
	nativeSegfaultRegex = regexp.MustCompile(`(?m)([a-zA-Z0-9_\-]+)(?:\[\d+\])?: segfault at [0-9a-fA-F]+ ip [0-9a-fA-F]+ sp [0-9a-fA-F]+ error \d+ in ([a-zA-Z0-9_\-\.]+)(?:\[[0-9a-fA-F]+\+[0-9a-fA-F]+\])?`)
	nativeSignalRegex   = regexp.MustCompile(`(?m)(SIGSEGV|SIGBUS|SIGABRT|SIGILL|SIGFPE)(?::\s*(.*))?`)
	nativeLibRegex      = regexp.MustCompile(`\b(?:in|from)\s+([a-zA-Z0-9_\-\.]+\.so(?:\.[0-9]+)*)`)
)

func parseNativeCrash(raw string) *CrashReport {
	hasSegfault := strings.Contains(raw, "segfault at") || nativeSegfaultRegex.MatchString(raw)
	hasSignal := nativeSignalRegex.MatchString(raw)

	if !hasSegfault && !hasSignal {
		return nil
	}

	r := &CrashReport{
		Language:  "native",
		ErrorType: "SIGSEGV",
		RawLog:    raw,
	}

	var suspects []string

	if m := nativeSegfaultRegex.FindStringSubmatch(raw); len(m) > 2 {
		binName := m[1]
		libName := m[2]
		r.Message = fmt.Sprintf("Segmentation fault in %s (%s)", libName, binName)
		r.CulpritFile = libName
		suspects = append(suspects, normalizeNativeLib(libName))
		suspects = append(suspects, binName)
	} else if sigMatch := nativeSignalRegex.FindStringSubmatch(raw); len(sigMatch) > 1 {
		r.ErrorType = sigMatch[1]
		if len(sigMatch) > 2 {
			r.Message = strings.TrimSpace(sigMatch[2])
		}
	}

	if libMatch := nativeLibRegex.FindStringSubmatch(raw); len(libMatch) > 1 {
		suspects = append(suspects, normalizeNativeLib(libMatch[1]))
	}

	r.SuspectTargets = suspects
	return r
}

func normalizeNativeLib(lib string) string {
	clean := strings.TrimPrefix(lib, "lib")
	idx := strings.Index(clean, ".so")
	if idx > 0 {
		clean = clean[:idx]
	}
	return clean
}

func parseGenericCrash(raw string) *CrashReport {
	r := &CrashReport{
		Language:  "unknown",
		ErrorType: "Crash",
		RawLog:    raw,
	}

	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "FATAL:") || strings.HasPrefix(trimmed, "ERROR:") {
			r.Message = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trimmed, "FATAL:"), "ERROR:"))
			r.ErrorType = "FatalError"
			break
		}
	}
	if r.Message == "" && len(lines) > 0 {
		r.Message = strings.TrimSpace(lines[0])
	}

	return r
}
