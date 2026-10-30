package resolver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
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

func parseBrewInfo(output string) (*osPkgMeta, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" || strings.HasPrefix(trimmed, "Error:") {
		return nil, ErrNotFound
	}

	if strings.HasPrefix(trimmed, "{") {
		return parseBrewInfoJSON(trimmed)
	}

	scanner := bufio.NewScanner(strings.NewReader(trimmed))
	meta := &osPkgMeta{}
	firstLine := true

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if firstLine {
			firstLine = false
			lineClean := strings.TrimPrefix(line, "==> ")
			namePart, rest, ok := strings.Cut(lineClean, ":")
			if !ok {
				continue
			}
			meta.name = strings.TrimSpace(namePart)
			rest = strings.TrimSpace(rest)
			if strings.HasPrefix(rest, "stable ") {
				fields := strings.Fields(strings.TrimPrefix(rest, "stable "))
				if len(fields) > 0 {
					meta.version = strings.Trim(fields[0], ",()")
				}
			} else {
				fields := strings.Fields(rest)
				if len(fields) > 0 {
					meta.version = strings.Trim(fields[0], ",()")
				}
			}
			continue
		}

		// Avoid picking up Homebrew formula tap git URLs as upstream homepage
		if strings.Contains(line, "github.com/Homebrew/homebrew-") {
			continue
		}

		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			if meta.homepage == "" {
				meta.homepage = line
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan brew output: %w", err)
	}
	if meta.name == "" {
		return nil, ErrNotFound
	}
	return meta, nil
}

func parseBrewInfoJSON(data string) (*osPkgMeta, error) {
	var payload struct {
		Formulae []struct {
			Name     string `json:"name"`
			Homepage string `json:"homepage"`
			Versions struct {
				Stable string `json:"stable"`
			} `json:"versions"`
		} `json:"formulae"`
		Casks []struct {
			Token    string `json:"token"`
			Version  string `json:"version"`
			Homepage string `json:"homepage"`
		} `json:"casks"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return nil, fmt.Errorf("unmarshal brew json: %w", err)
	}
	if len(payload.Formulae) > 0 {
		f := payload.Formulae[0]
		return &osPkgMeta{
			name:     f.Name,
			version:  f.Versions.Stable,
			homepage: f.Homepage,
		}, nil
	}
	if len(payload.Casks) > 0 {
		c := payload.Casks[0]
		return &osPkgMeta{
			name:     c.Token,
			version:  c.Version,
			homepage: c.Homepage,
		}, nil
	}
	return nil, ErrNotFound
}

func parsePortInfo(output string) (*osPkgMeta, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" || strings.HasPrefix(trimmed, "Error:") {
		return nil, ErrNotFound
	}

	scanner := bufio.NewScanner(strings.NewReader(trimmed))
	meta := &osPkgMeta{}
	firstLine := true

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if firstLine {
			firstLine = false
			if namePart, verPart, found := strings.Cut(line, "@"); found {
				meta.name = strings.TrimSpace(namePart)
				verPart = strings.TrimSpace(verPart)
				fields := strings.Fields(verPart)
				if len(fields) > 0 {
					meta.version = strings.Trim(fields[0], ",()")
				}
				continue
			}
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
			}
		case "homepage", "website", "url":
			if meta.homepage == "" {
				meta.homepage = val
			}
		case "bugs", "bugtracker":
			if meta.bugs == "" {
				meta.bugs = val
			}
		case "maintainers", "maintainer":
			if meta.maintainer == "" {
				meta.maintainer = val
			}
		case "version":
			if meta.version == "" {
				meta.version = val
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan port output: %w", err)
	}
	if meta.name == "" {
		return nil, ErrNotFound
	}
	return meta, nil
}

func extractApkName(pkgVer string) string {
	idxRev := strings.LastIndex(pkgVer, "-r")
	if idxRev <= 0 {
		return pkgVer
	}
	sub := pkgVer[:idxRev]
	idxVer := strings.LastIndex(sub, "-")
	if idxVer <= 0 {
		return sub
	}
	if idxVer+1 < len(sub) && sub[idxVer+1] >= '0' && sub[idxVer+1] <= '9' {
		return sub[:idxVer]
	}
	return sub
}

func extractApkVersion(pkgVer string, query string) string {
	if query != "" && strings.HasPrefix(pkgVer, query+"-") {
		return strings.TrimPrefix(pkgVer, query+"-")
	}
	name := extractApkName(pkgVer)
	if name != "" && strings.HasPrefix(pkgVer, name+"-") {
		return strings.TrimPrefix(pkgVer, name+"-")
	}
	return ""
}

func parseApkWhoOwns(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		const sep = " is owned by "
		if idx := strings.Index(line, sep); idx != -1 {
			pkgVer := strings.TrimSpace(line[idx+len(sep):])
			return extractApkName(pkgVer)
		}
	}
	return ""
}

func parseApkInfo(output string, query string) (*osPkgMeta, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" || strings.HasPrefix(trimmed, "ERROR:") {
		return nil, ErrNotFound
	}

	scanner := bufio.NewScanner(strings.NewReader(trimmed))
	meta := &osPkgMeta{name: query}
	var currentSection string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasSuffix(line, ":") {
			header := strings.TrimSuffix(line, ":")
			parts := strings.Fields(header)
			if len(parts) >= 2 {
				pkgVer := parts[0]
				currentSection = strings.ToLower(parts[1])
				if meta.version == "" {
					meta.version = extractApkVersion(pkgVer, query)
				}
				if n := extractApkName(pkgVer); n != "" {
					meta.name = n
				}
			} else {
				currentSection = strings.ToLower(header)
			}
			continue
		}

		switch currentSection {
		case "webpage", "url", "website":
			if meta.homepage == "" && (strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://")) {
				meta.homepage = line
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan apk output: %w", err)
	}
	if meta.homepage == "" && meta.version == "" {
		return nil, ErrNotFound
	}
	return meta, nil
}

func parseApkPolicy(output string, query string) (*osPkgMeta, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" || strings.HasPrefix(trimmed, "ERROR:") {
		return nil, ErrNotFound
	}

	scanner := bufio.NewScanner(strings.NewReader(trimmed))
	meta := &osPkgMeta{
		name: query,
		bugs: "https://gitlab.alpinelinux.org/alpine/aports/-/issues",
	}
	found := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasSuffix(line, " policy:") {
			meta.name = strings.TrimSuffix(line, " policy:")
			found = true
			continue
		}

		if found && meta.version == "" && strings.HasSuffix(line, ":") {
			candidateVer := strings.TrimSuffix(line, ":")
			if strings.Contains(candidateVer, "-r") {
				meta.version = candidateVer
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan apk policy output: %w", err)
	}
	if !found || meta.version == "" {
		return nil, ErrNotFound
	}
	return meta, nil
}

type cliToolchainDef struct {
	canonicalName string
	repoURL       string
	trackerURL    string
	protocol      Protocol
	versionArgs   [][]string
	parseVersion  func(output string) string
}

func parseDockerVersion(output string) string {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return ""
	}
	if !strings.Contains(trimmed, " ") && !strings.Contains(trimmed, "\n") {
		return trimmed
	}
	fields := strings.Fields(trimmed)
	for i, f := range fields {
		if strings.EqualFold(f, "version") && i+1 < len(fields) {
			return strings.Trim(fields[i+1], ",:")
		}
	}
	return ""
}

func parseKubectlVersion(output string) string {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "{") {
		var payload struct {
			ClientVersion struct {
				GitVersion string `json:"gitVersion"`
			} `json:"clientVersion"`
		}
		if err := json.Unmarshal([]byte(trimmed), &payload); err == nil && payload.ClientVersion.GitVersion != "" {
			return payload.ClientVersion.GitVersion
		}
	}
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Client Version:") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "Client Version:"))
			if idx := strings.Index(rest, `GitVersion:"`); idx != -1 {
				sub := rest[idx+len(`GitVersion:"`):]
				if end := strings.Index(sub, `"`); end != -1 {
					return sub[:end]
				}
			}
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return ""
}

func parseTerraformVersion(output string) string {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "{") {
		var payload struct {
			TerraformVersion string `json:"terraform_version"`
		}
		if err := json.Unmarshal([]byte(trimmed), &payload); err == nil && payload.TerraformVersion != "" {
			return payload.TerraformVersion
		}
	}
	fields := strings.Fields(trimmed)
	for i, f := range fields {
		if strings.EqualFold(f, "Terraform") && i+1 < len(fields) {
			return strings.TrimPrefix(fields[i+1], "v")
		}
	}
	return ""
}

func parseHelmVersion(output string) string {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "v") && !strings.Contains(trimmed, " ") && !strings.Contains(trimmed, "\n") {
		return trimmed
	}
	if idx := strings.Index(trimmed, `Version:"`); idx != -1 {
		sub := trimmed[idx+len(`Version:"`):]
		if end := strings.Index(sub, `"`); end != -1 {
			return sub[:end]
		}
	}
	fields := strings.Fields(trimmed)
	if len(fields) > 0 && strings.HasPrefix(fields[0], "v") {
		return fields[0]
	}
	return ""
}

var devCLIToolchains = map[string]cliToolchainDef{
	"docker": {
		canonicalName: "docker",
		repoURL:       "https://github.com/docker/cli",
		trackerURL:    "https://github.com/docker/cli/issues",
		protocol:      ProtocolGitHub,
		versionArgs: [][]string{
			{"version", "--format", "{{.Client.Version}}"},
			{"--version"},
			{"version"},
		},
		parseVersion: parseDockerVersion,
	},
	"kubectl": {
		canonicalName: "kubectl",
		repoURL:       "https://github.com/kubernetes/kubectl",
		trackerURL:    "https://github.com/kubernetes/kubectl/issues",
		protocol:      ProtocolGitHub,
		versionArgs: [][]string{
			{"version", "--client", "--output=json"},
			{"version", "--client"},
			{"version"},
		},
		parseVersion: parseKubectlVersion,
	},
	"terraform": {
		canonicalName: "terraform",
		repoURL:       "https://github.com/hashicorp/terraform",
		trackerURL:    "https://github.com/hashicorp/terraform/issues",
		protocol:      ProtocolGitHub,
		versionArgs: [][]string{
			{"version", "-json"},
			{"version"},
			{"--version"},
		},
		parseVersion: parseTerraformVersion,
	},
	"helm": {
		canonicalName: "helm",
		repoURL:       "https://github.com/helm/helm",
		trackerURL:    "https://github.com/helm/helm/issues",
		protocol:      ProtocolGitHub,
		versionArgs: [][]string{
			{"version", "--template", "{{.Version}}"},
			{"version", "--short"},
			{"version"},
		},
		parseVersion: parseHelmVersion,
	},
}

func (p *OSPackageProbe) resolveCLIToolchain(ctx context.Context, query string) (*Target, error) {
	def, ok := devCLIToolchains[strings.ToLower(query)]
	if !ok {
		return nil, ErrNotFound
	}

	var version string
	for _, args := range def.versionArgs {
		out, err := p.run(ctx, query, args...)
		if err == nil {
			if v := def.parseVersion(string(out)); v != "" {
				version = v
				break
			}
		}
	}

	if version == "" {
		if p.lookPath != nil {
			if _, err := p.lookPath(query); err != nil {
				return nil, ErrNotFound
			}
		} else {
			return nil, ErrNotFound
		}
	}

	return &Target{
		Query:         query,
		CanonicalName: def.canonicalName,
		LocalVersion:  version,
		Layer:         LayerOSPackage,
		RepositoryURL: def.repoURL,
		Tracker: TrackerInfo{
			Protocol: def.protocol,
			URL:      def.trackerURL,
		},
	}, nil
}

// Resolve searches system binary paths, developer toolchains, and package managers (dpkg, apt, rpm, pacman, apk, brew, port, flatpak, snap, winget).
func (p *OSPackageProbe) Resolve(ctx context.Context, query string) (*Target, error) {
	if strings.ContainsAny(query, "/\\ \t\r\n") || strings.HasPrefix(query, "-") {
		return nil, ErrNotFound
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// 0. Developer CLI toolchains (docker, kubectl, terraform, helm)
	if target, err := p.resolveCLIToolchain(cmdCtx, query); err == nil && target != nil {
		return target, nil
	}

	candidatePkg := query
	var resolvedPath string
	if pth, err := p.lookPath(query); err == nil && pth != "" {
		resolvedPath = pth
		out, err := p.run(cmdCtx, "dpkg", "-S", resolvedPath)
		if err != nil && strings.HasPrefix(resolvedPath, "/bin/") {
			usrPath := "/usr/bin/" + strings.TrimPrefix(resolvedPath, "/bin/")
			out, err = p.run(cmdCtx, "dpkg", "-S", usrPath)
		} else if err != nil && strings.HasPrefix(resolvedPath, "/usr/bin/") {
			binPath := "/bin/" + strings.TrimPrefix(resolvedPath, "/usr/bin/")
			out, err = p.run(cmdCtx, "dpkg", "-S", binPath)
		}

		if err == nil {
			if pkg := parseDpkgSPackage(string(out)); pkg != "" {
				candidatePkg = pkg
			}
		} else {
			if apkWho, whoErr := p.run(cmdCtx, "apk", "info", "-W", resolvedPath); whoErr == nil {
				if pkg := parseApkWhoOwns(string(apkWho)); pkg != "" {
					candidatePkg = pkg
				}
			}
		}
	}

	var meta *osPkgMeta
	// 1. Try dpkg-query
	format := "-f=${Package}\n${Version}\n${Bugs}\n${Homepage}\n${Maintainer}\n"
	dpkgOut, err := p.run(cmdCtx, "dpkg-query", "-W", format, candidatePkg)
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
		if aptOut, aptErr := p.run(cmdCtx, "apt-cache", "show", candidatePkg); aptErr == nil {
			if parsed, parseErr := parseAptCacheShow(string(aptOut)); parseErr == nil {
				meta = parsed
			}
		}
	}

	// 3. Fallback to RPM (Fedora, RHEL, CentOS, openSUSE)
	if meta == nil {
		rpmCandidate := query
		if resolvedPath != "" {
			if rpmQf, qfErr := p.run(cmdCtx, "rpm", "-qf", "--qf", "%{NAME}\n", resolvedPath); qfErr == nil {
				lines := strings.Split(strings.TrimSpace(string(rpmQf)), "\n")
				if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
					rpmCandidate = strings.TrimSpace(lines[0])
				}
			}
		}
		if rpmOut, rpmErr := p.run(cmdCtx, "rpm", "-qi", rpmCandidate); rpmErr == nil {
			if parsed, parseErr := parseRPMQueryInfo(string(rpmOut)); parseErr == nil {
				meta = parsed
			}
		}
	}

	// 4. Fallback to Pacman (Arch Linux)
	if meta == nil {
		pacmanCandidate := query
		if resolvedPath != "" {
			if pacmanQo, qoErr := p.run(cmdCtx, "pacman", "-Qoq", resolvedPath); qoErr == nil {
				lines := strings.Split(strings.TrimSpace(string(pacmanQo)), "\n")
				if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
					pacmanCandidate = strings.TrimSpace(lines[0])
				}
			}
		}
		if pacmanOut, pacmanErr := p.run(cmdCtx, "pacman", "-Qi", pacmanCandidate); pacmanErr == nil {
			if parsed, parseErr := parsePacmanQueryInfo(string(pacmanOut)); parseErr == nil {
				meta = parsed
			}
		}
	}

	// 5. Fallback to Alpine Linux (apk info -d or apk policy)
	if meta == nil {
		if apkOut, apkErr := p.run(cmdCtx, "apk", "info", "-d", candidatePkg); apkErr == nil {
			if parsed, parseErr := parseApkInfo(string(apkOut), candidatePkg); parseErr == nil {
				meta = parsed
			}
		}
		if meta == nil {
			if policyOut, policyErr := p.run(cmdCtx, "apk", "policy", candidatePkg); policyErr == nil {
				if parsed, parseErr := parseApkPolicy(string(policyOut), candidatePkg); parseErr == nil {
					meta = parsed
				}
			}
		}
	}

	// 6. Fallback to macOS Homebrew (brew info)
	if meta == nil {
		if brewOut, brewErr := p.run(cmdCtx, "brew", "info", query); brewErr == nil {
			if parsed, parseErr := parseBrewInfo(string(brewOut)); parseErr == nil {
				meta = parsed
			}
		}
	}

	// 7. Fallback to macOS MacPorts (port info)
	if meta == nil {
		if portOut, portErr := p.run(cmdCtx, "port", "info", query); portErr == nil {
			if parsed, parseErr := parsePortInfo(string(portOut)); parseErr == nil {
				meta = parsed
			}
		}
	}

	// 8. Fallback to Linux Flatpak
	if meta == nil {
		if flatpakOut, flatpakErr := p.run(cmdCtx, "flatpak", "info", query); flatpakErr == nil {
			if parsed, parseErr := parseFlatpakInfo(string(flatpakOut)); parseErr == nil {
				meta = parsed
			}
		}
	}

	// 9. Fallback to Linux Snap
	if meta == nil {
		if snapOut, snapErr := p.run(cmdCtx, "snap", "info", query); snapErr == nil {
			if parsed, parseErr := parseSnapInfo(string(snapOut)); parseErr == nil {
				meta = parsed
			}
		}
	}

	// 10. Fallback to Windows winget
	if meta == nil {
		if wingetOut, wingetErr := p.run(cmdCtx, "winget", "show", "--id", query); wingetErr == nil {
			if parsed, parseErr := parseWingetShow(string(wingetOut)); parseErr == nil {
				meta = parsed
			}
		} else {
			if wingetOut2, wingetErr2 := p.run(cmdCtx, "winget", "show", query); wingetErr2 == nil {
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
