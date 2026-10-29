package resolver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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
	if readErr != nil {
		if cmd.Process != nil {
			if killErr := cmd.Process.Kill(); killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
				// Process termination is non-fatal if already dead.
			}
		}
		waitErr := cmd.Wait()
		if waitErr != nil {
			return nil, fmt.Errorf("read %s stdout: %w; wait: %v", name, readErr, waitErr)
		}
		return nil, fmt.Errorf("read %s stdout: %w", name, readErr)
	}

	// Kill child process before calling Wait if output exceeds limit to avoid pipe deadlock.
	if int64(len(out)) > maxOutputBytes {
		if cmd.Process != nil {
			if killErr := cmd.Process.Kill(); killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
				// Process termination is non-fatal if already dead.
			}
		}
		waitErr := cmd.Wait()
		if waitErr != nil {
			return nil, fmt.Errorf("%s output exceeded %d bytes limit", name, maxOutputBytes)
		}
		return nil, fmt.Errorf("%s output exceeded %d bytes limit", name, maxOutputBytes)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("execute %s: %w", name, err)
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

func parseRPMQueryInfo(output string) (*osPkgMeta, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	meta := &osPkgMeta{}
	found := false

	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		switch key {
		case "Name":
			meta.name = val
			found = true
		case "Version":
			meta.version = val
		case "URL":
			meta.homepage = val
		case "Bug URL":
			meta.bugs = val
		case "Packager":
			if meta.maintainer == "" {
				meta.maintainer = val
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan rpm output: %w", err)
	}
	if !found || meta.name == "" {
		return nil, ErrNotFound
	}
	return meta, nil
}

func parsePacmanQueryInfo(output string) (*osPkgMeta, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	meta := &osPkgMeta{}
	found := false

	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		switch key {
		case "Name":
			meta.name = val
			found = true
		case "Version":
			meta.version = val
		case "URL":
			meta.homepage = val
		case "Packager":
			meta.maintainer = val
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan pacman output: %w", err)
	}
	if !found || meta.name == "" {
		return nil, ErrNotFound
	}
	return meta, nil
}

func parseFlatpakInfo(output string) (*osPkgMeta, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	meta := &osPkgMeta{}
	found := false

	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		switch key {
		case "id":
			meta.name = val
			found = true
		case "version":
			meta.version = val
		case "homepage", "website", "url":
			meta.homepage = val
		case "bugtracker", "bugs", "contact":
			meta.bugs = val
		case "origin":
			if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
				if meta.homepage == "" {
					meta.homepage = val
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan flatpak output: %w", err)
	}
	if !found || meta.name == "" {
		return nil, ErrNotFound
	}
	return meta, nil
}

func parseSnapInfo(output string) (*osPkgMeta, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	meta := &osPkgMeta{}
	found := false

	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		switch key {
		case "name":
			meta.name = val
			found = true
		case "contact":
			meta.bugs = val
		case "website":
			meta.homepage = val
		case "installed":
			fields := strings.Fields(val)
			if len(fields) > 0 {
				meta.version = fields[0]
			}
		case "version":
			if meta.version == "" {
				meta.version = val
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan snap output: %w", err)
	}
	if !found || meta.name == "" {
		return nil, ErrNotFound
	}
	return meta, nil
}

func parseWingetShow(output string) (*osPkgMeta, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	meta := &osPkgMeta{}
	found := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "Found ") {
			trimmed := strings.TrimPrefix(line, "Found ")
			if idx := strings.Index(trimmed, " ["); idx != -1 {
				meta.name = strings.TrimSpace(trimmed[:idx])
			} else {
				meta.name = strings.TrimSpace(trimmed)
			}
			found = true
			continue
		}

		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		switch key {
		case "name":
			if meta.name == "" {
				meta.name = val
				found = true
			}
		case "id":
			if meta.name == "" {
				meta.name = val
				found = true
			}
		case "version":
			meta.version = val
		case "publisher support url":
			meta.bugs = val
		case "package url":
			meta.homepage = val
		case "homepage":
			if meta.homepage == "" {
				meta.homepage = val
			}
		case "publisher url":
			if meta.homepage == "" {
				meta.homepage = val
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan winget output: %w", err)
	}
	if !found || meta.name == "" {
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
	var resolvedPath string
	if pth, err := p.lookPath(query); err == nil && pth != "" {
		resolvedPath = pth
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
		if aptOut, aptErr := p.run(ctx, "apt-cache", "show", candidatePkg); aptErr == nil {
			if parsed, parseErr := parseAptCacheShow(string(aptOut)); parseErr == nil {
				meta = parsed
			}
		}
	}

	// 3. Fallback to RPM (Fedora, RHEL, CentOS, openSUSE)
	if meta == nil {
		rpmCandidate := query
		if resolvedPath != "" {
			if rpmQf, qfErr := p.run(ctx, "rpm", "-qf", "--qf", "%{NAME}\n", resolvedPath); qfErr == nil {
				lines := strings.Split(strings.TrimSpace(string(rpmQf)), "\n")
				if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
					rpmCandidate = strings.TrimSpace(lines[0])
				}
			}
		}
		if rpmOut, rpmErr := p.run(ctx, "rpm", "-qi", rpmCandidate); rpmErr == nil {
			if parsed, parseErr := parseRPMQueryInfo(string(rpmOut)); parseErr == nil {
				meta = parsed
			}
		}
	}

	// 4. Fallback to Pacman (Arch Linux)
	if meta == nil {
		pacmanCandidate := query
		if resolvedPath != "" {
			if pacmanQo, qoErr := p.run(ctx, "pacman", "-Qoq", resolvedPath); qoErr == nil {
				lines := strings.Split(strings.TrimSpace(string(pacmanQo)), "\n")
				if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
					pacmanCandidate = strings.TrimSpace(lines[0])
				}
			}
		}
		if pacmanOut, pacmanErr := p.run(ctx, "pacman", "-Qi", pacmanCandidate); pacmanErr == nil {
			if parsed, parseErr := parsePacmanQueryInfo(string(pacmanOut)); parseErr == nil {
				meta = parsed
			}
		}
	}

	// 5. Fallback to Linux Flatpak
	if meta == nil {
		if flatpakOut, flatpakErr := p.run(ctx, "flatpak", "info", query); flatpakErr == nil {
			if parsed, parseErr := parseFlatpakInfo(string(flatpakOut)); parseErr == nil {
				meta = parsed
			}
		}
	}

	// 6. Fallback to Linux Snap
	if meta == nil {
		if snapOut, snapErr := p.run(ctx, "snap", "info", query); snapErr == nil {
			if parsed, parseErr := parseSnapInfo(string(snapOut)); parseErr == nil {
				meta = parsed
			}
		}
	}

	// 7. Fallback to Windows winget
	if meta == nil {
		if wingetOut, wingetErr := p.run(ctx, "winget", "show", "--id", query); wingetErr == nil {
			if parsed, parseErr := parseWingetShow(string(wingetOut)); parseErr == nil {
				meta = parsed
			}
		} else {
			if wingetOut2, wingetErr2 := p.run(ctx, "winget", "show", query); wingetErr2 == nil {
				if parsed, parseErr := parseWingetShow(string(wingetOut2)); parseErr == nil {
					meta = parsed
				}
			}
		}
	}

	if meta == nil {
		return nil, ErrNotFound
	}

	canonicalName := meta.name
	if canonicalName == "" {
		canonicalName = candidatePkg
	}

	hasUpstreamBugs := strings.Contains(meta.bugs, "github.com") ||
		strings.Contains(meta.bugs, "gitlab.") ||
		strings.Contains(meta.bugs, "codeberg.org") ||
		strings.Contains(meta.bugs, "projects.blender.org") ||
		strings.Contains(meta.bugs, "gitea.") ||
		strings.Contains(meta.bugs, "forgejo.") ||
		strings.Contains(meta.bugs, "sr.ht")

	hasUpstreamHomepage := strings.Contains(meta.homepage, "github.com") ||
		strings.Contains(meta.homepage, "gitlab.") ||
		strings.Contains(meta.homepage, "codeberg.org") ||
		strings.Contains(meta.homepage, "projects.blender.org") ||
		strings.Contains(meta.homepage, "gitea.") ||
		strings.Contains(meta.homepage, "forgejo.") ||
		strings.Contains(meta.homepage, "sr.ht")

	var tracker TrackerInfo
	var normRepo string

	if !hasUpstreamBugs && (strings.Contains(meta.homepage, "gnu.org/software/") || strings.Contains(meta.maintainer, "@gnu.org")) {
		tracker = TrackerInfo{
			Protocol: ProtocolDebbugs,
			Email:    "bug-" + canonicalName + "@gnu.org",
			URL:      "https://debbugs.gnu.org/cgi/pkgreport.cgi?package=" + canonicalName,
		}
		normRepo = NormalizeRepoURL(meta.homepage)
	} else if !hasUpstreamBugs && hasUpstreamHomepage {
		tracker, normRepo = ClassifyTracker("", "", meta.homepage)
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
