package resolver

import (
	"context"
	"strings"
	"testing"
)

func TestParseGoPanic(t *testing.T) {
	log := `panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x102345]

goroutine 1 [running]:
github.com/gin-gonic/gin.(*Context).Next(0xc0000a4000)
	/go/pkg/mod/github.com/gin-gonic/gin@v1.9.1/context.go:173 +0x45
github.com/example/my-app/handlers.HandleUser(0xc0000a4000)
	/app/handlers/user.go:42 +0x120
main.main()
	/app/main.go:15 +0x30
`

	rep := ParseCrashTrace(log)
	if rep == nil {
		t.Fatalf("expected non-nil report")
	}

	if rep.Language != "go" {
		t.Errorf("Language = %q, want go", rep.Language)
	}
	if rep.ErrorType != "panic" {
		t.Errorf("ErrorType = %q, want panic", rep.ErrorType)
	}
	if !strings.Contains(rep.Message, "invalid memory address") {
		t.Errorf("Message unexpected: %q", rep.Message)
	}
	if rep.CulpritLine != 173 {
		t.Errorf("CulpritLine = %d, want 173", rep.CulpritLine)
	}
	if !strings.Contains(rep.CulpritFile, "context.go") {
		t.Errorf("CulpritFile = %q, want context.go", rep.CulpritFile)
	}
	if len(rep.SuspectTargets) == 0 {
		t.Fatalf("expected suspect targets, got none")
	}
	if rep.PrimaryTarget != "github.com/gin-gonic/gin" {
		t.Errorf("PrimaryTarget = %q, want github.com/gin-gonic/gin", rep.PrimaryTarget)
	}

	title := rep.SuggestedTitle()
	if !strings.Contains(title, "[github.com/gin-gonic/gin] panic:") {
		t.Errorf("SuggestedTitle unexpected: %q", title)
	}

	summary := rep.SuggestedSummary()
	if !strings.Contains(summary, "attributed to target github.com/gin-gonic/gin") {
		t.Errorf("SuggestedSummary missing target attribution: %s", summary)
	}
}

func TestParsePythonTraceback(t *testing.T) {
	log := `Traceback (most recent call last):
  File "/app/main.py", line 45, in <module>
    fetch_data()
  File "/app/main.py", line 32, in fetch_data
    response = requests.get("https://example.com")
  File "/usr/local/lib/python3.11/site-packages/requests/api.py", line 73, in get
    return request("get", url, params=params, **kwargs)
  File "/usr/local/lib/python3.11/site-packages/requests/adapters.py", line 520, in send
    raise SSLError(e, request=request)
requests.exceptions.SSLError: HTTPSConnectionPool(host='example.com', port=443): Max retries exceeded
`

	rep := ParseCrashTrace(log)
	if rep == nil {
		t.Fatalf("expected non-nil report")
	}

	if rep.Language != "python" {
		t.Errorf("Language = %q, want python", rep.Language)
	}
	if rep.ErrorType != "requests.exceptions.SSLError" {
		t.Errorf("ErrorType = %q, want requests.exceptions.SSLError", rep.ErrorType)
	}
	if !strings.Contains(rep.Message, "Max retries exceeded") {
		t.Errorf("Message unexpected: %q", rep.Message)
	}
	if rep.CulpritLine != 520 {
		t.Errorf("CulpritLine = %d, want 520", rep.CulpritLine)
	}
	if !strings.Contains(rep.CulpritFile, "adapters.py") {
		t.Errorf("CulpritFile = %q, want adapters.py", rep.CulpritFile)
	}
	if rep.PrimaryTarget != "requests" {
		t.Errorf("PrimaryTarget = %q, want requests", rep.PrimaryTarget)
	}
}

func TestParseNodeStackTrace(t *testing.T) {
	log := `TypeError: Cannot read properties of undefined (reading 'split')
    at parseHeader (/app/node_modules/axios/lib/adapters/http.js:142:25)
    at dispatchHttpRequest (/app/node_modules/axios/lib/adapters/http.js:180:13)
    at new Promise (<anonymous>)
    at httpAdapter (/app/node_modules/axios/lib/adapters/http.js:46:10)
`

	rep := ParseCrashTrace(log)
	if rep == nil {
		t.Fatalf("expected non-nil report")
	}

	if rep.Language != "javascript" {
		t.Errorf("Language = %q, want javascript", rep.Language)
	}
	if rep.ErrorType != "TypeError" {
		t.Errorf("ErrorType = %q, want TypeError", rep.ErrorType)
	}
	if rep.CulpritLine != 142 {
		t.Errorf("CulpritLine = %d, want 142", rep.CulpritLine)
	}
	if rep.PrimaryTarget != "axios" {
		t.Errorf("PrimaryTarget = %q, want axios", rep.PrimaryTarget)
	}
}

func TestParseRustPanic(t *testing.T) {
	log := `thread 'main' panicked at 'called Result::unwrap() on an Err value', /cargo/registry/src/github.com-1ecc6299db9ec823/tokio-1.28.0/src/runtime/task/mod.rs:350:18
stack backtrace:
   0: rust_begin_unwind
   1: core::panicking::panic_fmt
   2: tokio::runtime::task::raw::poll
`

	rep := ParseCrashTrace(log)
	if rep == nil {
		t.Fatalf("expected non-nil report")
	}

	if rep.Language != "rust" {
		t.Errorf("Language = %q, want rust", rep.Language)
	}
	if rep.CulpritLine != 350 {
		t.Errorf("CulpritLine = %d, want 350", rep.CulpritLine)
	}
	if rep.PrimaryTarget != "tokio" {
		t.Errorf("PrimaryTarget = %q, want tokio", rep.PrimaryTarget)
	}
}

func TestParseNativeSegfault(t *testing.T) {
	log := `nginx[1234]: segfault at 7f9b8c000000 ip 00007f9b8c234560 sp 00007ffd12345678 error 4 in libssl.so.3[7f9b8c200000+45000]`

	rep := ParseCrashTrace(log)
	if rep == nil {
		t.Fatalf("expected non-nil report")
	}

	if rep.Language != "native" {
		t.Errorf("Language = %q, want native", rep.Language)
	}
	if rep.PrimaryTarget != "ssl" && rep.PrimaryTarget != "nginx" {
		t.Errorf("PrimaryTarget = %q, want ssl or nginx", rep.PrimaryTarget)
	}
}

func TestTraceAttributorResolution(t *testing.T) {
	// Mock waterfall probe
	matches := map[string]*Target{
		"github.com/gin-gonic/gin": {
			Query:         "github.com/gin-gonic/gin",
			CanonicalName: "github.com/gin-gonic/gin",
			Layer:         LayerOrgCloud,
			Tracker: TrackerInfo{
				Protocol: ProtocolGitHub,
				URL:      "https://github.com/gin-gonic/gin/issues",
			},
		},
	}
	probe := &mockProbe{
		name:  "mock-direct",
		layer: LayerOrgCloud,
		resolve: func(_ context.Context, query string) (*Target, error) {
			if t, ok := matches[query]; ok {
				return t, nil
			}
			return nil, ErrNotFound
		},
	}
	wf := NewWaterfall(0, probe)
	attributor := NewTraceAttributor(wf)

	log := `panic: slice bounds out of range [:10] with capacity 5

goroutine 1 [running]:
github.com/gin-gonic/gin.(*Context).Next(0xc0000a4000)
	/go/pkg/mod/github.com/gin-gonic/gin@v1.9.1/context.go:210 +0x45
`

	target, rep, err := attributor.AttributeAndResolve(context.Background(), log)
	if err != nil {
		t.Fatalf("AttributeAndResolve failed: %v", err)
	}
	if target == nil {
		t.Fatalf("expected target, got nil")
	}
	if target.CanonicalName != "github.com/gin-gonic/gin" {
		t.Errorf("target canonical name = %q, want github.com/gin-gonic/gin", target.CanonicalName)
	}
	if rep.PrimaryTarget != "github.com/gin-gonic/gin" {
		t.Errorf("rep PrimaryTarget = %q, want github.com/gin-gonic/gin", rep.PrimaryTarget)
	}
}
