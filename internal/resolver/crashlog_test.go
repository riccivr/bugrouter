package resolver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtractSuspect(t *testing.T) {
	tests := []struct {
		name        string
		log         string
		wantSuspect string
	}{
		{
			name: "windows event id 1000",
			log: `TimeCreated: 10/17/2026 3:18:40 PM
Faulting application name: l2.exe, version: 4.0.76.0, time stamp: 0x695dea1d
Faulting module name: client.dll, version: 0.0.0.0, time stamp: 0x6a66e1cf
Exception code: 0xc0000409`,
			wantSuspect: "l2.exe",
		},
		{
			name: "windows wer file",
			log: `Version=1
EventType=AppCrash
AppName=notepad.exe
AppPath=C:\Windows\System32\notepad.exe`,
			wantSuspect: "notepad.exe",
		},
		{
			name: "linux coredumpctl info executable",
			log: `           PID: 41235 (blender)
           UID: 1000 (ricci)
        Signal: 11 (SEGV)
    Executable: /usr/bin/blender
  Command Line: /usr/bin/blender`,
			wantSuspect: "blender",
		},
		{
			name: "linux apport crash file",
			log: `ProblemType: Crash
ExecutablePath: /usr/bin/curl
Package: curl 7.88.1-10
Title: curl crashed with SIGSEGV`,
			wantSuspect: "curl",
		},
		{
			name:        "linux process message fallback",
			log:         `Message: Process 12345 (ffmpeg) of user 1000 dumped core.`,
			wantSuspect: "ffmpeg",
		},
		{
			name: "darwin modern ips json",
			log: `{"app_name":"Safari","timestamp":"2026-10-30 11:00:00.00 +0100","slice_uuid":"abc"}
Thread 0 Crashed:
0   libsystem_kernel.dylib`,
			wantSuspect: "Safari",
		},
		{
			name: "darwin classic crash report",
			log: `Process:               DaVinci Resolve [9876]
Path:                  /Applications/DaVinci Resolve.app/Contents/MacOS/DaVinci Resolve
Identifier:            com.blackmagic-design.DaVinciResolve`,
			wantSuspect: "DaVinci Resolve",
		},
		{
			name: "stack trace fallback candidate",
			log: `goroutine 1 [running]:
github.com/gin-gonic/gin.(*Context).Next(0xc0000a4000)
	/go/pkg/mod/github.com/gin-gonic/gin@v1.9.1/context.go:173 +0x45`,
			wantSuspect: "github.com/gin-gonic/gin",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractSuspect(tc.log)
			if got != tc.wantSuspect {
				t.Errorf("extractSuspect() = %q, want %q", got, tc.wantSuspect)
			}
		})
	}
}

func TestExtractSuspectFromFilename(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"_usr_bin_curl.1000.crash", "curl"},
		{"_usr_lib_firefox_firefox.1000.crash", "firefox"},
		{"core.nginx.1000.12345", "nginx"},
		{"Safari_2026-10-30-101112_MacBook.ips", "Safari"},
		{"GIMP-2026-10-29.crash", "GIMP"},
	}

	for _, tc := range tests {
		got := extractSuspectFromFilename(tc.filename)
		if got != tc.want {
			t.Errorf("extractSuspectFromFilename(%q) = %q, want %q", tc.filename, got, tc.want)
		}
	}
}

func TestCrashReaderLinuxCoredumpctl(t *testing.T) {
	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "coredumpctl" && len(args) > 0 && args[0] == "info" {
			return []byte(`           PID: 1234 (curl)
    Executable: /usr/bin/curl
       Message: Process 1234 (curl) of user 1000 dumped core.`), nil
		}
		return nil, errors.New("command not found")
	}

	cr := NewCrashReader("linux", mockRunner)
	ctx := context.Background()
	rawLog, suspect, err := cr.Read(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if suspect != "curl" {
		t.Errorf("suspect = %q, want curl", suspect)
	}
	if !strings.Contains(rawLog, "/usr/bin/curl") {
		t.Errorf("rawLog missing expected content: %s", rawLog)
	}
}

func TestCrashReaderLinuxDirectoryFallback(t *testing.T) {
	tmpDir := t.TempDir()
	crashFile := filepath.Join(tmpDir, "_usr_bin_whoopsie.0.crash")
	content := "ProblemType: Crash\nExecutablePath: /usr/bin/whoopsie\nPackage: whoopsie 0.2.77\n"
	if err := os.WriteFile(crashFile, []byte(content), 0600); err != nil {
		t.Fatalf("write crash file: %v", err)
	}

	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("coredumpctl: No match found")
	}

	cr := NewCrashReader("linux", mockRunner)
	cr.linuxDirs = []string{tmpDir}

	rawLog, suspect, err := cr.Read(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if suspect != "whoopsie" {
		t.Errorf("suspect = %q, want whoopsie", suspect)
	}
	if !strings.Contains(rawLog, "ProblemType: Crash") {
		t.Errorf("rawLog missing expected content: %s", rawLog)
	}
}

func TestCrashReaderWindowsPowerShell(t *testing.T) {
	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "powershell" {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "Get-WinEvent") && strings.Contains(joined, "Id=1000") {
				return []byte(`
   ProviderName: Application Error
TimeCreated: 10/30/2026 10:00:00 AM
Message: Faulting application name: blender.exe, version: 4.1.0.0
Faulting module name: nvoglv64.dll, version: 32.0.15.5585
Exception code: 0xc0000005
`), nil
			}
		}
		return nil, errors.New("powershell command failed")
	}

	cr := NewCrashReader("windows", mockRunner)
	rawLog, suspect, err := cr.Read(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if suspect != "blender.exe" {
		t.Errorf("suspect = %q, want blender.exe", suspect)
	}
	if !strings.Contains(rawLog, "Faulting application name: blender.exe") {
		t.Errorf("rawLog missing expected content: %s", rawLog)
	}
}

func TestCrashReaderWindowsWERFallback(t *testing.T) {
	tmpDir := t.TempDir()
	werFile := filepath.Join(tmpDir, "Report.wer")
	content := "Version=1\nEventType=AppCrash\nAppName=gimp.exe\nOriginalFilename=gimp.exe\n"
	if err := os.WriteFile(werFile, []byte(content), 0600); err != nil {
		t.Fatalf("write wer file: %v", err)
	}

	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("Get-WinEvent: No events were found")
	}

	cr := NewCrashReader("windows", mockRunner)
	cr.windowsDirs = []string{tmpDir}

	rawLog, suspect, err := cr.Read(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if suspect != "gimp.exe" {
		t.Errorf("suspect = %q, want gimp.exe", suspect)
	}
	if !strings.Contains(rawLog, "AppName=gimp.exe") {
		t.Errorf("rawLog missing expected content: %s", rawLog)
	}
}

func TestCrashReaderDarwinDiagnosticReports(t *testing.T) {
	tmpDir := t.TempDir()
	oldFile := filepath.Join(tmpDir, "OldApp_2026-10-01.ips")
	newFile := filepath.Join(tmpDir, "PhotoShop_2026-10-30.ips")

	if err := os.WriteFile(oldFile, []byte(`{"app_name":"OldApp"}`), 0600); err != nil {
		t.Fatalf("write oldFile: %v", err)
	}
	past := time.Now().Add(-1 * time.Hour)
	if err := os.Chtimes(oldFile, past, past); err != nil {
		t.Fatalf("chtimes oldFile: %v", err)
	}

	newContent := `{"app_name":"PhotoShop","bundle_id":"com.adobe.photoshop"}
Process: PhotoShop [54321]
Thread 0 Crashed:
`
	if err := os.WriteFile(newFile, []byte(newContent), 0600); err != nil {
		t.Fatalf("write newFile: %v", err)
	}

	cr := NewCrashReader("darwin", nil)
	cr.darwinDirs = []string{tmpDir}
	cr.homeDir = func() (string, error) { return "", errors.New("no home") }

	rawLog, suspect, err := cr.Read(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if suspect != "PhotoShop" {
		t.Errorf("suspect = %q, want PhotoShop", suspect)
	}
	if !strings.Contains(rawLog, "com.adobe.photoshop") {
		t.Errorf("rawLog missing expected content: %s", rawLog)
	}
}

func TestCrashReaderNoCrashesFound(t *testing.T) {
	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("command not found")
	}

	cr := NewCrashReader("linux", mockRunner)
	cr.linuxDirs = []string{t.TempDir()}

	_, _, err := cr.Read(context.Background())
	if err == nil {
		t.Fatal("expected error when no crash records exist, got nil")
	}
	if !strings.Contains(err.Error(), "no post-mortem crash records found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCrashReaderCancelledContext(t *testing.T) {
	cr := NewCrashReader("linux", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := cr.Read(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestReadLatestCrashDefaultInvocation(t *testing.T) {
	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("Executable: /usr/bin/obs-studio\nMessage: Process 9999 (obs-studio) crashed."), nil
	}

	cr := NewCrashReader("linux", mockRunner)
	restore := SetCrashReaderForTest(cr)
	defer restore()

	rawLog, suspect, err := ReadLatestCrash(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if suspect != "obs-studio" {
		t.Errorf("suspect = %q, want obs-studio", suspect)
	}
	if !strings.Contains(rawLog, "obs-studio") {
		t.Errorf("rawLog missing expected content: %s", rawLog)
	}
}
