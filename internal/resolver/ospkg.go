package resolver

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// CmdRunner executes an external command with context and returns capped output.
type CmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// OSPackageProbe resolves Linux system packages and binaries via package managers.
type OSPackageProbe struct {
	run      CmdRunner
	lookPath func(string) (string, error)
}

func defaultCmdRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("create stdout pipe for %s: %w", name, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", name, err)
	}

	const maxOutputBytes = 256 * 1024
	limitedReader := io.LimitReader(stdout, maxOutputBytes+1)
	out, readErr := io.ReadAll(limitedReader)
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("read %s stdout: %w", name, readErr)
	}
	if int64(len(out)) > maxOutputBytes {
		return nil, fmt.Errorf("%s output exceeded %d bytes limit", name, maxOutputBytes)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("execute %s: %w", name, waitErr)
	}
	return out, nil
}

// NewOSPackageProbe initializes an OS package probe using system execution utilities.
func NewOSPackageProbe() *OSPackageProbe {
	return &OSPackageProbe{
		run:      defaultCmdRunner,
		lookPath: exec.LookPath,
	}
}

// Name returns the probe identifier.
func (p *OSPackageProbe) Name() string {
	return "os-pkg"
}

// Layer returns the resolution layer classification.
func (p *OSPackageProbe) Layer() SourceLayer {
	return LayerOSPackage
}

func parseDpkgSPackage(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "diversion") {
			continue
		}
		pkgPart, _, found := strings.Cut(line, ": ")
		if !found {
			pkgPart, _, found = strings.Cut(line, ":")
		}
		if found {
			pkg := strings.TrimSpace(pkgPart)
			if idx := strings.Index(pkg, ":"); idx != -1 {
				pkg = pkg[:idx]
			}
			if pkg != "" {
				return pkg
			}
		}
	}
	return ""
}

type osPkgMeta struct {
	name       string
	version    string
	bugs       string
	homepage   string
	maintainer string
}

func parseAptCacheShow(output string) (*osPkgMeta, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	meta := &osPkgMeta{}
	found := false

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			if found {
				break
			}
			continue
		}

		key, val, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)

		switch key {
		case "Package":
			meta.name = val
			found = true
		case "Version":
			meta.version = val
		case "Bugs":
			meta.bugs = val
		case "Homepage":
			meta.homepage = val
		case "Original-Maintainer":
			if meta.maintainer == "" {
				meta.maintainer = val
			}
		case "Maintainer":
			if meta.maintainer == "" {
				meta.maintainer = val
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan apt-cache output: %w", err)
	}
	if !found {
		return nil, ErrNotFound
	}
	return meta, nil
}

// Resolve searches system binary paths and dpkg/apt metadata to identify the upstream tracker.
func (p *OSPackageProbe) Resolve(ctx context.Context, query string) (*Target, error) {
	if strings.ContainsAny(query, "/\\ \t\r\n") || strings.HasPrefix(query, "-") {
		return nil, ErrNotFound
	}

	candidatePkg := query
	if resolvedPath, err := p.lookPath(query); err == nil && resolvedPath != "" {
		out, err := p.run(ctx, "dpkg", "-S", resolvedPath)
		if err != nil && strings.HasPrefix(resolvedPath, "/bin/") {
			usrPath := "/usr/bin/" + strings.TrimPrefix(resolvedPath, "/bin/")
			out, err = p.run(ctx, "dpkg", "-S", usrPath)
		} else if err != nil && strings.HasPrefix(resolvedPath, "/usr/bin/") {
			binPath := "/bin/" + strings.TrimPrefix(resolvedPath, "/usr/bin/")
			out, err = p.run(ctx, "dpkg", "-S", binPath)
		}

		if err == nil {
			if pkg := parseDpkgSPackage(string(out)); pkg != "" {
				candidatePkg = pkg
			}
		}
	}

	var meta *osPkgMeta
	// 1. Try dpkg-query
	format := "-f=${Package}\n${Version}\n${Bugs}\n${Homepage}\n${Maintainer}\n"
	dpkgOut, err := p.run(ctx, "dpkg-query", "-W", format, candidatePkg)
	if err == nil {
		lines := strings.Split(string(dpkgOut), "\n")
		if len(lines) >= 5 && strings.TrimSpace(lines[0]) != "" {
			meta = &osPkgMeta{
				name:       strings.TrimSpace(lines[0]),
				version:    strings.TrimSpace(lines[1]),
				bugs:       strings.TrimSpace(lines[2]),
				homepage:   strings.TrimSpace(lines[3]),
				maintainer: strings.TrimSpace(lines[4]),
			}
		}
	}

	// 2. Fallback to apt-cache show
	if meta == nil {
		aptOut, err := p.run(ctx, "apt-cache", "show", candidatePkg)
		if err != nil {
			return nil, ErrNotFound
		}
		parsed, err := parseAptCacheShow(string(aptOut))
		if err != nil {
			return nil, ErrNotFound
		}
		meta = parsed
	}

	canonicalName := meta.name
	if canonicalName == "" {
		canonicalName = candidatePkg
	}

	hasUpstreamGit := strings.Contains(meta.bugs, "github.com") ||
		strings.Contains(meta.bugs, "gitlab.") ||
		strings.Contains(meta.bugs, "codeberg.org") ||
		strings.Contains(meta.bugs, "sr.ht")

	var tracker TrackerInfo
	var normRepo string

	if !hasUpstreamGit && (strings.Contains(meta.homepage, "gnu.org/software/") || strings.Contains(meta.maintainer, "@gnu.org")) {
		tracker = TrackerInfo{
			Protocol: ProtocolDebbugs,
			Email:    "bug-" + canonicalName + "@gnu.org",
			URL:      "https://debbugs.gnu.org/cgi/pkgreport.cgi?package=" + canonicalName,
		}
		normRepo = NormalizeRepoURL(meta.homepage)
	} else {
		tracker, normRepo = ClassifyTracker(meta.bugs, "", meta.homepage)
	}

	return &Target{
		Query:         query,
		CanonicalName: canonicalName,
		LocalVersion:  meta.version,
		Layer:         LayerOSPackage,
		RepositoryURL: normRepo,
		Tracker:       tracker,
	}, nil
}
