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
