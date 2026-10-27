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
