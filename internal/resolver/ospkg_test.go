package resolver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestOSPackageProbeBinaryGrep(t *testing.T) {
	fakeLookPath := func(file string) (string, error) {
		if file == "grep" {
			return "/bin/grep", nil
		}
		return "", errors.New("not found")
	}

	fakeRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "dpkg" && len(args) >= 2 && args[0] == "-S" && args[1] == "/bin/grep" {
			return []byte("grep: /bin/grep\n"), nil
		}
		if name == "dpkg-query" && len(args) >= 3 && args[2] == "grep" {
			out := "grep\n3.8-5\n\nhttps://www.gnu.org/software/grep/\nGNU Grep Maintainers <bug-grep@gnu.org>\n"
			return []byte(out), nil
		}
		return nil, errors.New("command failed")
	}

	probe := &OSPackageProbe{
		run:      fakeRunner,
		lookPath: fakeLookPath,
	}

	target, err := probe.Resolve(context.Background(), "grep")
	if err != nil {
		t.Fatalf("resolve grep: %v", err)
	}
	if target.CanonicalName != "grep" {
		t.Errorf("CanonicalName = %q, want grep", target.CanonicalName)
	}
	if target.Tracker.Protocol != ProtocolDebbugs {
		t.Errorf("Protocol = %q, want debbugs", target.Tracker.Protocol)
	}
	if target.Tracker.Email != "bug-grep@gnu.org" {
		t.Errorf("Email = %q, want bug-grep@gnu.org", target.Tracker.Email)
	}
	if target.Tracker.URL != "https://debbugs.gnu.org/cgi/pkgreport.cgi?package=grep" {
		t.Errorf("URL = %q, want https://debbugs.gnu.org/cgi/pkgreport.cgi?package=grep", target.Tracker.URL)
	}
}

func TestOSPackageProbeRipgrepAptCache(t *testing.T) {
	fakeLookPath := func(file string) (string, error) {
		return "", errors.New("not on path")
	}

	fakeRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "dpkg-query" {
			return nil, errors.New("package not installed")
		}
		if name == "apt-cache" && len(args) >= 2 && args[0] == "show" && args[1] == "ripgrep" {
			stanza := `Package: ripgrep
Version: 13.0.0-4
Homepage: https://github.com/BurntSushi/ripgrep
Maintainer: Debian Rust Maintainers <pkg-rust-maintainers@alioth-lists.debian.net>
Description: fast line-oriented search tool

Package: ripgrep
Version: 12.0.0-1
`
			return []byte(stanza), nil
		}
		return nil, errors.New("command failed")
	}

	probe := &OSPackageProbe{
		run:      fakeRunner,
		lookPath: fakeLookPath,
	}

	target, err := probe.Resolve(context.Background(), "ripgrep")
	if err != nil {
		t.Fatalf("resolve ripgrep: %v", err)
	}
	if target.CanonicalName != "ripgrep" {
		t.Errorf("CanonicalName = %q, want ripgrep", target.CanonicalName)
	}
	if target.LocalVersion != "13.0.0-4" {
		t.Errorf("LocalVersion = %q, want 13.0.0-4", target.LocalVersion)
	}
	if target.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", target.Tracker.Protocol)
	}
	if target.Tracker.URL != "https://github.com/BurntSushi/ripgrep/issues" {
		t.Errorf("URL = %q, want https://github.com/BurntSushi/ripgrep/issues", target.Tracker.URL)
	}
}

func TestOSPackageProbeUnknown(t *testing.T) {
	fakeLookPath := func(file string) (string, error) {
		return "", errors.New("not found")
	}
	fakeRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("not found")
	}

	probe := &OSPackageProbe{
		run:      fakeRunner,
		lookPath: fakeLookPath,
	}

	_, err := probe.Resolve(context.Background(), "unknownpkgxyz")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}

	for _, bad := range []string{"-invalid", "bad/query", "bad\\query", "bad name"} {
		_, err := probe.Resolve(context.Background(), bad)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("expected ErrNotFound for %q, got: %v", bad, err)
		}
	}
}

func TestOSPackageProbeRPM(t *testing.T) {
	fakeLookPath := func(file string) (string, error) {
		if file == "rg" {
			return "/usr/bin/rg", nil
		}
		return "", errors.New("not found")
	}

	fakeRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "dpkg" || name == "dpkg-query" || name == "apt-cache" {
			return nil, errors.New("not a debian system")
		}
		if name == "rpm" && len(args) >= 4 && args[0] == "-qf" && args[1] == "--qf" && args[3] == "/usr/bin/rg" {
			return []byte("ripgrep\n"), nil
		}
		if name == "rpm" && len(args) >= 2 && args[0] == "-qi" && args[1] == "ripgrep" {
			out := `Name        : ripgrep
Version     : 14.1.0
Release     : 1.fc40
Architecture: x86_64
URL         : https://github.com/BurntSushi/ripgrep
Bug URL     : https://bugz.fedoraproject.org/ripgrep
Summary     : Fast search tool based on Rust's regex engine
`
			return []byte(out), nil
		}
		return nil, errors.New("command failed")
	}

	probe := &OSPackageProbe{
		run:      fakeRunner,
		lookPath: fakeLookPath,
	}

	target, err := probe.Resolve(context.Background(), "rg")
	if err != nil {
		t.Fatalf("resolve rg via rpm: %v", err)
	}
	if target.CanonicalName != "ripgrep" {
		t.Errorf("CanonicalName = %q, want ripgrep", target.CanonicalName)
	}
	if target.LocalVersion != "14.1.0" {
		t.Errorf("LocalVersion = %q, want 14.1.0", target.LocalVersion)
	}
	if target.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", target.Tracker.Protocol)
	}
	if target.Tracker.URL != "https://github.com/BurntSushi/ripgrep/issues" {
		t.Errorf("URL = %q, want https://github.com/BurntSushi/ripgrep/issues", target.Tracker.URL)
	}
}

func TestOSPackageProbePacman(t *testing.T) {
	fakeLookPath := func(file string) (string, error) {
		if file == "rg" {
			return "/usr/bin/rg", nil
		}
		return "", errors.New("not found")
	}

	fakeRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "dpkg" || name == "dpkg-query" || name == "apt-cache" || name == "rpm" {
			return nil, errors.New("not supported")
		}
		if name == "pacman" && len(args) >= 2 && args[0] == "-Qoq" && args[1] == "/usr/bin/rg" {
			return []byte("ripgrep\n"), nil
		}
		if name == "pacman" && len(args) >= 2 && args[0] == "-Qi" && args[1] == "ripgrep" {
			out := `Name            : ripgrep
Version         : 14.1.0-1
URL             : https://github.com/BurntSushi/ripgrep
Packager        : Arch Linux
`
			return []byte(out), nil
		}
		return nil, errors.New("command failed")
	}

	probe := &OSPackageProbe{
		run:      fakeRunner,
		lookPath: fakeLookPath,
	}

	target, err := probe.Resolve(context.Background(), "rg")
	if err != nil {
		t.Fatalf("resolve rg via pacman: %v", err)
	}
	if target.CanonicalName != "ripgrep" {
		t.Errorf("CanonicalName = %q, want ripgrep", target.CanonicalName)
	}
	if target.LocalVersion != "14.1.0-1" {
		t.Errorf("LocalVersion = %q, want 14.1.0-1", target.LocalVersion)
	}
	if target.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", target.Tracker.Protocol)
	}
}

func TestDefaultCmdRunnerPipeDeadlock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// "yes" produces continuous output far exceeding 256 KiB
	_, err := defaultCmdRunner(ctx, "yes")
	if err == nil {
		t.Fatal("expected error on oversized output, got nil")
	}
	if !strings.Contains(err.Error(), "output exceeded") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestParseDesktopPackageOutputs(t *testing.T) {
	// 1. Flatpak
	flatpakRaw := `Blender - Very fast and versatile 3D modeller/renderer

          ID: org.blender.Blender
         Ref: app/org.blender.Blender/x86_64/stable
        Arch: x86_64
      Branch: stable
     Version: 4.2.0
     License: GPL-2.0+
      Origin: flathub
Installation: system
    Homepage: https://projects.blender.org/blender/blender
`
	flatpakMeta, err := parseFlatpakInfo(flatpakRaw)
	if err != nil {
		t.Fatalf("parseFlatpakInfo failed: %v", err)
	}
	if flatpakMeta.name != "org.blender.Blender" {
		t.Errorf("name = %q, want org.blender.Blender", flatpakMeta.name)
	}
	if flatpakMeta.version != "4.2.0" {
		t.Errorf("version = %q, want 4.2.0", flatpakMeta.version)
	}
	if flatpakMeta.homepage != "https://projects.blender.org/blender/blender" {
		t.Errorf("homepage = %q, want https://projects.blender.org/blender/blender", flatpakMeta.homepage)
	}

	// 2. Snap
	snapRaw := `name:      blender
summary:   Blender is the free and open source 3D creation suite.
publisher: Blender Foundation (blenderfoundation✓)
store-url: https://snapcraft.io/blender
contact:   https://projects.blender.org/blender/blender/issues
website:   https://www.blender.org
license:   GPL-2.0-or-later
installed: 4.2.0 (5103) 378MB -
`
	snapMeta, err := parseSnapInfo(snapRaw)
	if err != nil {
		t.Fatalf("parseSnapInfo failed: %v", err)
	}
	if snapMeta.name != "blender" {
		t.Errorf("name = %q, want blender", snapMeta.name)
	}
	if snapMeta.version != "4.2.0" {
		t.Errorf("version = %q, want 4.2.0", snapMeta.version)
	}
	if snapMeta.bugs != "https://projects.blender.org/blender/blender/issues" {
		t.Errorf("bugs = %q, want https://projects.blender.org/blender/blender/issues", snapMeta.bugs)
	}
	if snapMeta.homepage != "https://www.blender.org" {
		t.Errorf("homepage = %q, want https://www.blender.org", snapMeta.homepage)
	}

	// 3. Winget
	wingetRaw := `Found Blender [BlenderFoundation.Blender]
Version: 4.2.0
Publisher: Blender Foundation
Publisher Url: https://www.blender.org
Publisher Support Url: https://projects.blender.org/blender/blender/issues
Author: Blender Foundation
Moniker: blender
Description: Blender is the free and open source 3D creation suite.
Homepage: https://www.blender.org
Package Url: https://projects.blender.org/blender/blender
License: GPL-2.0 or later
`
	wingetMeta, err := parseWingetShow(wingetRaw)
	if err != nil {
		t.Fatalf("parseWingetShow failed: %v", err)
	}
	if wingetMeta.name != "Blender" {
		t.Errorf("name = %q, want Blender", wingetMeta.name)
	}
	if wingetMeta.version != "4.2.0" {
		t.Errorf("version = %q, want 4.2.0", wingetMeta.version)
	}
	if wingetMeta.bugs != "https://projects.blender.org/blender/blender/issues" {
		t.Errorf("bugs = %q, want https://projects.blender.org/blender/blender/issues", wingetMeta.bugs)
	}
	if wingetMeta.homepage != "https://projects.blender.org/blender/blender" {
		t.Errorf("homepage = %q, want https://projects.blender.org/blender/blender", wingetMeta.homepage)
	}
}

func TestOSPackageProbeDesktopProbes(t *testing.T) {
	fakeLookPath := func(file string) (string, error) {
		return "", errors.New("not found")
	}

	// 1. Flatpak resolve
	fakeRunnerFlatpak := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "flatpak" && len(args) >= 2 && args[0] == "info" && args[1] == "org.blender.Blender" {
			out := `ID: org.blender.Blender
Version: 4.2.0
Homepage: https://projects.blender.org/blender/blender
`
			return []byte(out), nil
		}
		return nil, errors.New("command not found")
	}

	probeFlatpak := &OSPackageProbe{
		run:      fakeRunnerFlatpak,
		lookPath: fakeLookPath,
	}

	targetF, err := probeFlatpak.Resolve(context.Background(), "org.blender.Blender")
	if err != nil {
		t.Fatalf("resolve flatpak org.blender.Blender: %v", err)
	}
	if targetF.CanonicalName != "org.blender.Blender" {
		t.Errorf("CanonicalName = %q, want org.blender.Blender", targetF.CanonicalName)
	}
	if targetF.Tracker.Protocol != ProtocolGitea {
		t.Errorf("Protocol = %q, want gitea", targetF.Tracker.Protocol)
	}
	if targetF.Tracker.URL != "https://projects.blender.org/blender/blender/issues" {
		t.Errorf("URL = %q, want https://projects.blender.org/blender/blender/issues", targetF.Tracker.URL)
	}

	// 2. Snap resolve
	fakeRunnerSnap := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "snap" && len(args) >= 2 && args[0] == "info" && args[1] == "blender" {
			out := `name: blender
contact: https://projects.blender.org/blender/blender/issues
website: https://www.blender.org
installed: 4.2.0
`
			return []byte(out), nil
		}
		return nil, errors.New("command not found")
	}

	probeSnap := &OSPackageProbe{
		run:      fakeRunnerSnap,
		lookPath: fakeLookPath,
	}

	targetS, err := probeSnap.Resolve(context.Background(), "blender")
	if err != nil {
		t.Fatalf("resolve snap blender: %v", err)
	}
	if targetS.CanonicalName != "blender" {
		t.Errorf("CanonicalName = %q, want blender", targetS.CanonicalName)
	}
	if targetS.Tracker.Protocol != ProtocolGitea {
		t.Errorf("Protocol = %q, want gitea", targetS.Tracker.Protocol)
	}

	// 3. Winget resolve
	fakeRunnerWinget := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "winget" && len(args) >= 3 && args[0] == "show" && args[1] == "--id" && args[2] == "BlenderFoundation.Blender" {
			out := `Found Blender [BlenderFoundation.Blender]
Version: 4.2.0
Publisher Support Url: https://projects.blender.org/blender/blender/issues
`
			return []byte(out), nil
		}
		return nil, errors.New("command not found")
	}

	probeWinget := &OSPackageProbe{
		run:      fakeRunnerWinget,
		lookPath: fakeLookPath,
	}

	targetW, err := probeWinget.Resolve(context.Background(), "BlenderFoundation.Blender")
	if err != nil {
		t.Fatalf("resolve winget BlenderFoundation.Blender: %v", err)
	}
	if targetW.CanonicalName != "Blender" {
		t.Errorf("CanonicalName = %q, want Blender", targetW.CanonicalName)
	}
	if targetW.Tracker.Protocol != ProtocolGitea {
		t.Errorf("Protocol = %q, want gitea", targetW.Tracker.Protocol)
	}
}

func TestParseBrewInfo(t *testing.T) {
	// 1. Standard Formula
	rawFormula := `==> ripgrep: stable 14.1.0 (bottled), HEAD
Fast line-oriented regex search tool, similar to ag and ack
https://github.com/BurntSushi/ripgrep
/opt/homebrew/Cellar/ripgrep/14.1.0 (12 files, 5.2MB) *
From: https://github.com/Homebrew/homebrew-core/blob/HEAD/Formula/r/ripgrep.rb
License: Unlicense or MIT
`
	meta, err := parseBrewInfo(rawFormula)
	if err != nil {
		t.Fatalf("parseBrewInfo formula failed: %v", err)
	}
	if meta.name != "ripgrep" {
		t.Errorf("name = %q, want ripgrep", meta.name)
	}
	if meta.version != "14.1.0" {
		t.Errorf("version = %q, want 14.1.0", meta.version)
	}
	if meta.homepage != "https://github.com/BurntSushi/ripgrep" {
		t.Errorf("homepage = %q, want https://github.com/BurntSushi/ripgrep", meta.homepage)
	}

	// 2. Cask
	rawCask := `==> visual-studio-code: 1.89.1
https://code.visualstudio.com/
/opt/homebrew/Caskroom/visual-studio-code/1.89.1 (8,765 files, 400MB)
From: https://github.com/Homebrew/homebrew-cask/blob/HEAD/Casks/v/visual-studio-code.rb
==> Name
Visual Studio Code
`
	metaCask, err := parseBrewInfo(rawCask)
	if err != nil {
		t.Fatalf("parseBrewInfo cask failed: %v", err)
	}
	if metaCask.name != "visual-studio-code" {
		t.Errorf("name = %q, want visual-studio-code", metaCask.name)
	}
	if metaCask.version != "1.89.1" {
		t.Errorf("version = %q, want 1.89.1", metaCask.version)
	}
	if metaCask.homepage != "https://code.visualstudio.com/" {
		t.Errorf("homepage = %q, want https://code.visualstudio.com/", metaCask.homepage)
	}

	// 3. JSON format
	rawJSON := `{"formulae":[{"name":"wget","homepage":"https://www.gnu.org/software/wget/","versions":{"stable":"1.24.5"}}],"casks":[]}`
	metaJSON, err := parseBrewInfo(rawJSON)
	if err != nil {
		t.Fatalf("parseBrewInfo JSON failed: %v", err)
	}
	if metaJSON.name != "wget" || metaJSON.version != "1.24.5" || metaJSON.homepage != "https://www.gnu.org/software/wget/" {
		t.Errorf("unexpected parsed JSON meta: %+v", metaJSON)
	}

	// 4. Not found
	if _, err := parseBrewInfo("Error: No available formula or cask with the name \"unknown\"."); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for missing formula, got: %v", err)
	}
	if _, err := parseBrewInfo(""); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for empty string, got: %v", err)
	}
}

func TestParsePortInfo(t *testing.T) {
	// 1. Standard Port
	rawPort := `ripgrep @14.1.0 (textproc)
Variants:             universal

Description:          Fast line-oriented search tool.
Homepage:             https://github.com/BurntSushi/ripgrep

Build Dependencies:   cargo, rust
Platforms:            darwin
License:              MIT or Unlicense
Maintainers:          Email: maintainer@macports.org
`
	meta, err := parsePortInfo(rawPort)
	if err != nil {
		t.Fatalf("parsePortInfo failed: %v", err)
	}
	if meta.name != "ripgrep" {
		t.Errorf("name = %q, want ripgrep", meta.name)
	}
	if meta.version != "14.1.0" {
		t.Errorf("version = %q, want 14.1.0", meta.version)
	}
	if meta.homepage != "https://github.com/BurntSushi/ripgrep" {
		t.Errorf("homepage = %q, want https://github.com/BurntSushi/ripgrep", meta.homepage)
	}
	if meta.maintainer != "Email: maintainer@macports.org" {
		t.Errorf("maintainer = %q, want Email: maintainer@macports.org", meta.maintainer)
	}

	// 2. Port with Revision in version
	rawCurl := `curl @8.7.1, Revision 1 (net, www)
Homepage:             https://curl.se/
`
	metaCurl, err := parsePortInfo(rawCurl)
	if err != nil {
		t.Fatalf("parsePortInfo curl failed: %v", err)
	}
	if metaCurl.name != "curl" || metaCurl.version != "8.7.1" || metaCurl.homepage != "https://curl.se/" {
		t.Errorf("unexpected parsed curl meta: %+v", metaCurl)
	}

	// 3. Not found
	if _, err := parsePortInfo("Error: Port xyz not found"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for port not found, got: %v", err)
	}
}

func TestParseApkInfoAndPolicy(t *testing.T) {
	// 1. apk info -d
	rawApk := `ripgrep-14.1.0-r0 description:
Fast line-oriented regex search tool, similar to ag and ack

ripgrep-14.1.0-r0 webpage:
https://github.com/BurntSushi/ripgrep

ripgrep-14.1.0-r0 installed size:
5619712
`
	meta, err := parseApkInfo(rawApk, "ripgrep")
	if err != nil {
		t.Fatalf("parseApkInfo failed: %v", err)
	}
	if meta.name != "ripgrep" {
		t.Errorf("name = %q, want ripgrep", meta.name)
	}
	if meta.version != "14.1.0-r0" {
		t.Errorf("version = %q, want 14.1.0-r0", meta.version)
	}
	if meta.homepage != "https://github.com/BurntSushi/ripgrep" {
		t.Errorf("homepage = %q, want https://github.com/BurntSushi/ripgrep", meta.homepage)
	}

	// 2. apk policy
	rawPolicy := `ripgrep policy:
  14.1.0-r0:
    lib/apk/db/installed
    https://dl-cdn.alpinelinux.org/alpine/v3.20/main
`
	metaPolicy, err := parseApkPolicy(rawPolicy, "ripgrep")
	if err != nil {
		t.Fatalf("parseApkPolicy failed: %v", err)
	}
	if metaPolicy.name != "ripgrep" {
		t.Errorf("name = %q, want ripgrep", metaPolicy.name)
	}
	if metaPolicy.version != "14.1.0-r0" {
		t.Errorf("version = %q, want 14.1.0-r0", metaPolicy.version)
	}
	if metaPolicy.bugs != "https://gitlab.alpinelinux.org/alpine/aports/-/issues" {
		t.Errorf("bugs = %q, want https://gitlab.alpinelinux.org/alpine/aports/-/issues", metaPolicy.bugs)
	}

	// 3. apk info -W who owns
	owner := parseApkWhoOwns("/usr/bin/rg is owned by ripgrep-14.1.0-r0\n")
	if owner != "ripgrep" {
		t.Errorf("owner = %q, want ripgrep", owner)
	}

	// Complex package name with hyphen
	hyphenOwner := parseApkWhoOwns("/etc/ssl/certs is owned by ca-certificates-20240226-r0\n")
	if hyphenOwner != "ca-certificates" {
		t.Errorf("hyphenOwner = %q, want ca-certificates", hyphenOwner)
	}
}

func TestParseDevCLIToolchains(t *testing.T) {
	// 1. Docker
	if v := parseDockerVersion("26.1.1\n"); v != "26.1.1" {
		t.Errorf("docker format version = %q, want 26.1.1", v)
	}
	if v := parseDockerVersion("Docker version 26.1.1, build 4cf500e\n"); v != "26.1.1" {
		t.Errorf("docker standard version = %q, want 26.1.1", v)
	}

	// 2. Kubectl
	kubeJSON := `{"clientVersion":{"major":"1","minor":"30","gitVersion":"v1.30.0"}}`
	if v := parseKubectlVersion(kubeJSON); v != "v1.30.0" {
		t.Errorf("kubectl json version = %q, want v1.30.0", v)
	}
	if v := parseKubectlVersion("Client Version: v1.30.0\nKustomize Version: v5.0.4\n"); v != "v1.30.0" {
		t.Errorf("kubectl text version = %q, want v1.30.0", v)
	}

	// 3. Terraform
	tfJSON := `{"terraform_version":"1.8.2","platform":"linux_amd64"}`
	if v := parseTerraformVersion(tfJSON); v != "1.8.2" {
		t.Errorf("terraform json version = %q, want 1.8.2", v)
	}
	if v := parseTerraformVersion("Terraform v1.8.2\non linux_amd64\n"); v != "1.8.2" {
		t.Errorf("terraform text version = %q, want 1.8.2", v)
	}

	// 4. Helm
	if v := parseHelmVersion("v3.14.4\n"); v != "v3.14.4" {
		t.Errorf("helm template version = %q, want v3.14.4", v)
	}
	if v := parseHelmVersion("version.BuildInfo{Version:\"v3.14.4\", GitCommit:\"abc\"}\n"); v != "v3.14.4" {
		t.Errorf("helm buildinfo version = %q, want v3.14.4", v)
	}
}

func TestOSPackageProbeExtendedResolvers(t *testing.T) {
	fakeLookPathNone := func(file string) (string, error) {
		return "", errors.New("not found")
	}

	// 1. Homebrew Formula (ripgrep)
	fakeRunnerBrew := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "brew" && len(args) >= 2 && args[0] == "info" && args[1] == "ripgrep" {
			out := `==> ripgrep: stable 14.1.0 (bottled), HEAD
Fast line-oriented regex search tool
https://github.com/BurntSushi/ripgrep
/opt/homebrew/Cellar/ripgrep/14.1.0
From: https://github.com/Homebrew/homebrew-core/blob/HEAD/Formula/r/ripgrep.rb
`
			return []byte(out), nil
		}
		return nil, errors.New("command not supported")
	}
	probeBrew := &OSPackageProbe{run: fakeRunnerBrew, lookPath: fakeLookPathNone}
	targetBrew, err := probeBrew.Resolve(context.Background(), "ripgrep")
	if err != nil {
		t.Fatalf("resolve brew ripgrep: %v", err)
	}
	if targetBrew.CanonicalName != "ripgrep" {
		t.Errorf("CanonicalName = %q, want ripgrep", targetBrew.CanonicalName)
	}
	if targetBrew.LocalVersion != "14.1.0" {
		t.Errorf("LocalVersion = %q, want 14.1.0", targetBrew.LocalVersion)
	}
	if targetBrew.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", targetBrew.Tracker.Protocol)
	}
	if targetBrew.Tracker.URL != "https://github.com/BurntSushi/ripgrep/issues" {
		t.Errorf("URL = %q, want https://github.com/BurntSushi/ripgrep/issues", targetBrew.Tracker.URL)
	}

	// 2. Homebrew GNU Formula (wget -> Debbugs)
	fakeRunnerBrewGNU := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "brew" && len(args) >= 2 && args[0] == "info" && args[1] == "wget" {
			out := `==> wget: stable 1.24.5 (bottled), HEAD
Internet file retriever
https://www.gnu.org/software/wget/
`
			return []byte(out), nil
		}
		return nil, errors.New("command not supported")
	}
	probeBrewGNU := &OSPackageProbe{run: fakeRunnerBrewGNU, lookPath: fakeLookPathNone}
	targetWget, err := probeBrewGNU.Resolve(context.Background(), "wget")
	if err != nil {
		t.Fatalf("resolve brew wget: %v", err)
	}
	if targetWget.Tracker.Protocol != ProtocolDebbugs {
		t.Errorf("Protocol = %q, want debbugs", targetWget.Tracker.Protocol)
	}
	if targetWget.Tracker.Email != "bug-wget@gnu.org" {
		t.Errorf("Email = %q, want bug-wget@gnu.org", targetWget.Tracker.Email)
	}

	// 3. MacPorts (ripgrep)
	fakeRunnerPort := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "port" && len(args) >= 2 && args[0] == "info" && args[1] == "ripgrep" {
			out := `ripgrep @14.1.0 (textproc)
Homepage: https://github.com/BurntSushi/ripgrep
`
			return []byte(out), nil
		}
		return nil, errors.New("command not supported")
	}
	probePort := &OSPackageProbe{run: fakeRunnerPort, lookPath: fakeLookPathNone}
	targetPort, err := probePort.Resolve(context.Background(), "ripgrep")
	if err != nil {
		t.Fatalf("resolve port ripgrep: %v", err)
	}
	if targetPort.CanonicalName != "ripgrep" || targetPort.LocalVersion != "14.1.0" {
		t.Errorf("unexpected targetPort: %+v", targetPort)
	}
	if targetPort.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", targetPort.Tracker.Protocol)
	}

	// 4. Alpine Linux (apk info -d)
	fakeRunnerApk := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "apk" && len(args) >= 3 && args[0] == "info" && args[1] == "-d" && args[2] == "ripgrep" {
			out := `ripgrep-14.1.0-r0 webpage:
https://github.com/BurntSushi/ripgrep
`
			return []byte(out), nil
		}
		return nil, errors.New("command not supported")
	}
	probeApk := &OSPackageProbe{run: fakeRunnerApk, lookPath: fakeLookPathNone}
	targetApk, err := probeApk.Resolve(context.Background(), "ripgrep")
	if err != nil {
		t.Fatalf("resolve apk ripgrep: %v", err)
	}
	if targetApk.CanonicalName != "ripgrep" || targetApk.LocalVersion != "14.1.0-r0" {
		t.Errorf("unexpected targetApk: %+v", targetApk)
	}
	if targetApk.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", targetApk.Tracker.Protocol)
	}

	// 5. Alpine Linux fallback to policy (aports issue tracker)
	fakeRunnerApkPolicy := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "apk" && len(args) >= 2 && args[0] == "policy" && args[1] == "alpinelib" {
			out := `alpinelib policy:
  1.0.0-r1:
    lib/apk/db/installed
`
			return []byte(out), nil
		}
		return nil, errors.New("command not supported")
	}
	probeApkPolicy := &OSPackageProbe{run: fakeRunnerApkPolicy, lookPath: fakeLookPathNone}
	targetPolicy, err := probeApkPolicy.Resolve(context.Background(), "alpinelib")
	if err != nil {
		t.Fatalf("resolve apk policy: %v", err)
	}
	if targetPolicy.Tracker.Protocol != ProtocolGitLab {
		t.Errorf("Protocol = %q, want gitlab", targetPolicy.Tracker.Protocol)
	}
	if targetPolicy.Tracker.URL != "https://gitlab.alpinelinux.org/alpine/aports/-/issues" {
		t.Errorf("URL = %q, want aports issues url", targetPolicy.Tracker.URL)
	}

	// 6. Alpine binary ownership resolution (/usr/bin/rg)
	fakeLookPathRg := func(file string) (string, error) {
		if file == "rg" {
			return "/usr/bin/rg", nil
		}
		return "", errors.New("not found")
	}
	fakeRunnerApkWho := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "apk" && len(args) >= 3 && args[0] == "info" && args[1] == "-W" && args[2] == "/usr/bin/rg" {
			return []byte("/usr/bin/rg is owned by ripgrep-14.1.0-r0\n"), nil
		}
		if name == "apk" && len(args) >= 3 && args[0] == "info" && args[1] == "-d" && args[2] == "ripgrep" {
			return []byte("ripgrep-14.1.0-r0 webpage:\nhttps://github.com/BurntSushi/ripgrep\n"), nil
		}
		return nil, errors.New("command not supported")
	}
	probeApkWho := &OSPackageProbe{run: fakeRunnerApkWho, lookPath: fakeLookPathRg}
	targetWho, err := probeApkWho.Resolve(context.Background(), "rg")
	if err != nil {
		t.Fatalf("resolve apk who-owns rg: %v", err)
	}
	if targetWho.CanonicalName != "ripgrep" {
		t.Errorf("CanonicalName = %q, want ripgrep", targetWho.CanonicalName)
	}

	// 7. Developer CLI Toolchains: docker
	fakeRunnerDocker := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "docker" && len(args) >= 3 && args[0] == "version" && args[1] == "--format" {
			return []byte("26.1.1\n"), nil
		}
		return nil, errors.New("command failed")
	}
	probeDocker := &OSPackageProbe{run: fakeRunnerDocker, lookPath: fakeLookPathNone}
	targetDocker, err := probeDocker.Resolve(context.Background(), "docker")
	if err != nil {
		t.Fatalf("resolve docker: %v", err)
	}
	if targetDocker.CanonicalName != "docker" {
		t.Errorf("CanonicalName = %q, want docker", targetDocker.CanonicalName)
	}
	if targetDocker.LocalVersion != "26.1.1" {
		t.Errorf("LocalVersion = %q, want 26.1.1", targetDocker.LocalVersion)
	}
	if targetDocker.RepositoryURL != "https://github.com/docker/cli" {
		t.Errorf("RepositoryURL = %q, want https://github.com/docker/cli", targetDocker.RepositoryURL)
	}
	if targetDocker.Tracker.URL != "https://github.com/docker/cli/issues" {
		t.Errorf("Tracker URL = %q, want https://github.com/docker/cli/issues", targetDocker.Tracker.URL)
	}

	// 8. Developer CLI Toolchains: kubectl
	fakeRunnerKubectl := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "kubectl" && len(args) >= 3 && args[0] == "version" && args[1] == "--client" {
			return []byte(`{"clientVersion":{"gitVersion":"v1.30.0"}}`), nil
		}
		return nil, errors.New("command failed")
	}
	probeKubectl := &OSPackageProbe{run: fakeRunnerKubectl, lookPath: fakeLookPathNone}
	targetKubectl, err := probeKubectl.Resolve(context.Background(), "kubectl")
	if err != nil {
		t.Fatalf("resolve kubectl: %v", err)
	}
	if targetKubectl.CanonicalName != "kubectl" || targetKubectl.LocalVersion != "v1.30.0" {
		t.Errorf("unexpected kubectl target: %+v", targetKubectl)
	}
	if targetKubectl.RepositoryURL != "https://github.com/kubernetes/kubectl" {
		t.Errorf("RepositoryURL = %q, want https://github.com/kubernetes/kubectl", targetKubectl.RepositoryURL)
	}

	// 9. Developer CLI Toolchains: terraform
	fakeRunnerTF := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "terraform" && len(args) >= 2 && args[0] == "version" && args[1] == "-json" {
			return []byte(`{"terraform_version":"1.8.2"}`), nil
		}
		return nil, errors.New("command failed")
	}
	probeTF := &OSPackageProbe{run: fakeRunnerTF, lookPath: fakeLookPathNone}
	targetTF, err := probeTF.Resolve(context.Background(), "terraform")
	if err != nil {
		t.Fatalf("resolve terraform: %v", err)
	}
	if targetTF.CanonicalName != "terraform" || targetTF.LocalVersion != "1.8.2" {
		t.Errorf("unexpected terraform target: %+v", targetTF)
	}
	if targetTF.RepositoryURL != "https://github.com/hashicorp/terraform" {
		t.Errorf("RepositoryURL = %q, want https://github.com/hashicorp/terraform", targetTF.RepositoryURL)
	}

	// 10. Developer CLI Toolchains: helm
	fakeRunnerHelm := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "helm" && len(args) >= 3 && args[0] == "version" && args[1] == "--template" {
			return []byte("v3.14.4\n"), nil
		}
		return nil, errors.New("command failed")
	}
	probeHelm := &OSPackageProbe{run: fakeRunnerHelm, lookPath: fakeLookPathNone}
	targetHelm, err := probeHelm.Resolve(context.Background(), "helm")
	if err != nil {
		t.Fatalf("resolve helm: %v", err)
	}
	if targetHelm.CanonicalName != "helm" || targetHelm.LocalVersion != "v3.14.4" {
		t.Errorf("unexpected helm target: %+v", targetHelm)
	}
	if targetHelm.RepositoryURL != "https://github.com/helm/helm" {
		t.Errorf("RepositoryURL = %q, want https://github.com/helm/helm", targetHelm.RepositoryURL)
	}
}
