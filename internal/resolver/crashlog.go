package resolver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/scrubber"
)

const (
	// MaxCrashLogBytes caps post-mortem log buffering to 256 KiB.
	MaxCrashLogBytes = 256 * 1024
	// DefaultCrashTimeout bounds subprocess queries to 3s.
	DefaultCrashTimeout = 3 * time.Second
)

var (
	reWindowsFaultingApp = regexp.MustCompile(`(?i)Faulting application name:\s*([^\r\n,]+)`)
	reWindowsWERApp      = regexp.MustCompile(`(?i)(?:AppName|OriginalFilename)=([^\r\n]+)`)
	reLinuxExecutable    = regexp.MustCompile(`(?i)(?:Executable|ExecutablePath):\s*([^\r\n]+)`)
	reLinuxPackage       = regexp.MustCompile(`(?i)Package:\s*([^\r\n\s]+)`)
	reLinuxProcessMsg    = regexp.MustCompile(`(?i)Message:\s*Process\s+\d+\s+\(([^)]+)\)`)
	reDarwinProcess      = regexp.MustCompile(`(?im)^Process:\s+([^\[\r\n]+?)(?:\s*\[\d+\])?\s*$`)
	reDarwinAppNameJSON  = regexp.MustCompile(`(?i)"app_name"\s*:\s*"([^"]+)"`)
)

// CrashLogResult represents the structured evaluation of a native system crash record.
type CrashLogResult struct {
	Suspect        string                `json:"suspect,omitempty"`
	Candidates     []TraceCandidate      `json:"candidates"`
	ResolvedTarget *Target               `json:"resolved_target,omitempty"`
	ScrubbedLog    scrubber.ScrubbedText `json:"scrubbed_log"`
	NextActions    []string              `json:"next_actions,omitempty"`
}

// CrashReader extracts system post-mortem records under bounded execution.
type CrashReader struct {
	run         CmdRunner
	goos        string
	homeDir     func() (string, error)
	linuxDirs   []string
	darwinDirs  []string
	windowsDirs []string
}

func newDefaultCrashReader() *CrashReader {
	localAppData := os.Getenv("LOCALAPPDATA")
	return &CrashReader{
		run:     defaultCmdRunner,
		goos:    runtime.GOOS,
		homeDir: os.UserHomeDir,
		linuxDirs: []string{
			"/var/crash",
			"/var/lib/systemd/coredump",
		},
		darwinDirs: []string{
			"/Library/Logs/DiagnosticReports",
		},
		windowsDirs: []string{
			filepath.Join(localAppData, "CrashDumps"),
			filepath.Join(localAppData, "Microsoft", "Windows", "WER", "ReportArchive"),
			`C:\ProgramData\Microsoft\Windows\WER\ReportArchive`,
		},
	}
}

var defaultCrashReader = newDefaultCrashReader()

// SetCrashReaderForTest temporarily overrides the crash reader instance during tests.
func SetCrashReaderForTest(r *CrashReader) func() {
	prev := defaultCrashReader
	defaultCrashReader = r
	return func() {
		defaultCrashReader = prev
	}
}

// NewCrashReader creates a configurable post-mortem crash reader.
func NewCrashReader(goos string, runner CmdRunner) *CrashReader {
	cr := newDefaultCrashReader()
	cr.goos = goos
	if runner != nil {
		cr.run = runner
	}
	return cr
}

// ReadLatestCrash extracts the latest native operating system post-mortem crash log
// and suspect binary or package name on demand without background daemons.
func ReadLatestCrash(ctx context.Context) (string, string, error) {
	return defaultCrashReader.Read(ctx)
}

// Read inspects post-mortem system logs on the configured operating system.
func (r *CrashReader) Read(ctx context.Context) (string, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}

	switch r.goos {
	case "linux":
		return r.readLinux(ctx)
	case "windows":
		return r.readWindows(ctx)
	case "darwin":
		return r.readDarwin(ctx)
	default:
		return "", "", fmt.Errorf("unsupported operating system for crash log reader: %s", r.goos)
	}
}

func (r *CrashReader) readLinux(ctx context.Context) (string, string, error) {
	subCtx, cancel := context.WithTimeout(ctx, DefaultCrashTimeout)
	defer cancel()

	if r.run != nil {
		out, err := r.run(subCtx, "coredumpctl", "info")
		if err == nil && len(strings.TrimSpace(string(out))) > 0 {
			rawLog := string(out)
			suspect := extractSuspect(rawLog)
			return rawLog, suspect, nil
		}
	}

	return r.scanDirectoriesForCrash(r.linuxDirs)
}

func (r *CrashReader) readWindows(ctx context.Context) (string, string, error) {
	subCtx, cancel := context.WithTimeout(ctx, DefaultCrashTimeout)
	defer cancel()

	if r.run != nil {
		out, err := r.run(subCtx, "powershell", "-NoProfile", "-Command", "Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000} -MaxEvents 1")
		if err == nil && len(strings.TrimSpace(string(out))) > 0 {
			rawLog := string(out)
			suspect := extractSuspect(rawLog)
			return rawLog, suspect, nil
		}
	}

	rawLog, suspect, werErr := r.scanDirectoriesForCrash(r.windowsDirs)
	if werErr == nil && len(rawLog) > 0 {
		return rawLog, suspect, nil
	}

	return "", "", errors.New("no Windows post-mortem crash records found")
}

func (r *CrashReader) readDarwin(ctx context.Context) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}

	dirs := r.getDarwinDirs()
	return r.scanDirectoriesForCrash(dirs)
}

func (r *CrashReader) getDarwinDirs() []string {
	var dirs []string
	if r.homeDir != nil {
		if home, err := r.homeDir(); err == nil && home != "" {
			dirs = append(dirs, filepath.Join(home, "Library", "Logs", "DiagnosticReports"))
		}
	}
	dirs = append(dirs, r.darwinDirs...)
	return dirs
}

type crashCandidateFile struct {
	path    string
	modTime time.Time
}

func (r *CrashReader) scanDirectoriesForCrash(dirs []string) (string, string, error) {
	var newest *crashCandidateFile

	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			fullPath := filepath.Join(dir, entry.Name())
			if newest == nil || info.ModTime().After(newest.modTime) {
				newest = &crashCandidateFile{
					path:    fullPath,
					modTime: info.ModTime(),
				}
			}
		}
	}

	if newest == nil {
		return "", "", errors.New("no post-mortem crash records found")
	}

	f, err := os.Open(newest.path)
	if err != nil {
		return "", "", fmt.Errorf("open crash file %s: %w", newest.path, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			// Read-only file handle release.
		}
	}()

	lr := io.LimitReader(f, MaxCrashLogBytes)
	data, err := io.ReadAll(lr)
	if err != nil {
		return "", "", fmt.Errorf("read crash file %s: %w", newest.path, err)
	}

	rawLog := string(data)
	suspect := extractSuspect(rawLog)
	if suspect == "" {
		suspect = extractSuspectFromFilename(newest.path)
	}
	return rawLog, suspect, nil
}

func extractSuspect(rawLog string) string {
	if m := reWindowsFaultingApp.FindStringSubmatch(rawLog); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	if m := reWindowsWERApp.FindStringSubmatch(rawLog); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	if m := reLinuxExecutable.FindStringSubmatch(rawLog); len(m) > 1 {
		return filepath.Base(strings.TrimSpace(m[1]))
	}
	if m := reLinuxPackage.FindStringSubmatch(rawLog); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	if m := reLinuxProcessMsg.FindStringSubmatch(rawLog); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	if m := reDarwinAppNameJSON.FindStringSubmatch(rawLog); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	if m := reDarwinProcess.FindStringSubmatch(rawLog); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}

	if candidates := ExtractTargetsFromLog(rawLog); len(candidates) > 0 {
		return candidates[0].Query
	}

	return ""
}

func extractSuspectFromFilename(filename string) string {
	base := filepath.Base(filename)
	if strings.HasSuffix(base, ".crash") && strings.HasPrefix(base, "_") {
		trimmed := strings.TrimSuffix(base, ".crash")
		parts := strings.Split(trimmed, ".")
		if len(parts) > 0 {
			subParts := strings.Split(parts[0], "_")
			for i := len(subParts) - 1; i >= 0; i-- {
				if subParts[i] != "" {
					return subParts[i]
				}
			}
		}
	}
	if strings.HasPrefix(base, "core.") {
		parts := strings.Split(base, ".")
		if len(parts) > 1 && parts[1] != "" {
			return parts[1]
		}
	}
	if idx := strings.IndexAny(base, "_-."); idx > 0 {
		return base[:idx]
	}
	return base
}
