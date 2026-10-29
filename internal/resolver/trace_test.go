package resolver

import (
	"strings"
	"testing"
)

func TestExtractTargetsFromLog(t *testing.T) {
	tests := []struct {
		name       string
		log        string
		wantQuery  string
		wantSource string
	}{
		{
			name: "node_modules unscoped",
			log: `TypeError: Cannot read properties of undefined
    at parseHeader (/app/node_modules/axios/lib/adapters/http.js:142:25)
    at dispatchHttpRequest (/app/node_modules/axios/lib/adapters/http.js:180:13)`,
			wantQuery:  "axios",
			wantSource: "node_modules",
		},
		{
			name: "node_modules scoped",
			log: `Error: Client not initialized
    at Client.connect (/app/node_modules/@prisma/client/runtime/index.js:42:10)`,
			wantQuery:  "@prisma/client",
			wantSource: "node_modules",
		},
		{
			name: "go module path in panic",
			log: `panic: runtime error: slice bounds out of range [:20] with capacity 10

goroutine 1 [running]:
github.com/gin-gonic/gin.(*Context).Next(0xc0000a4000)
	/go/pkg/mod/github.com/gin-gonic/gin@v1.9.1/context.go:173 +0x45`,
			wantQuery:  "github.com/gin-gonic/gin",
			wantSource: "go_module",
		},
		{
			name: "python site-packages traceback",
			log: `Traceback (most recent call last):
  File "/app/main.py", line 45, in <module>
    fetch_data()
  File "/usr/local/lib/python3.11/site-packages/requests/api.py", line 73, in get
    return request("get", url, params=params, **kwargs)`,
			wantQuery:  "requests",
			wantSource: "python_pkg",
		},
		{
			name: "rust cargo registry panic",
			log: `thread 'main' panicked at 'called Result::unwrap() on an Err value', /home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/tokio-1.28.0/src/runtime/task/mod.rs:350:18
stack backtrace:
   0: rust_begin_unwind`,
			wantQuery:  "tokio",
			wantSource: "rust_crate",
		},
		{
			name:       "cli binary prefix error",
			log:        `grep: unrecognized option '--invalid-flag'`,
			wantQuery:  "grep",
			wantSource: "cli_binary",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidates := ExtractTargetsFromLog(tc.log)
			if len(candidates) == 0 {
				t.Fatalf("expected candidates, got 0")
			}
			found := false
			for _, c := range candidates {
				if c.Query == tc.wantQuery && c.Source == tc.wantSource {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("candidate %s (%s) not found in: %+v", tc.wantQuery, tc.wantSource, candidates)
			}
		})
	}
}

func TestExtractTargetsCapAndScrubbing(t *testing.T) {
	multiLog := `
/app/node_modules/pkg1/index.js
/app/node_modules/pkg2/index.js
/app/node_modules/pkg3/index.js
github.com/org/pkg4/main.go
site-packages/pkg5/init.py
site-packages/pkg6/init.py
`
	candidates := ExtractTargetsFromLog(multiLog)
	if len(candidates) != 5 {
		t.Fatalf("expected exactly 5 candidates capped, got %d: %+v", len(candidates), candidates)
	}

	// Verify order is preserved
	expectedQueries := []string{"pkg1", "pkg2", "pkg3", "github.com/org/pkg4", "pkg5"}
	for i, q := range expectedQueries {
		if candidates[i].Query != q {
			t.Errorf("candidates[%d].Query = %q, want %q", i, candidates[i].Query, q)
		}
	}

	// Test secret scrubbing in evidence line
	secretLog := `grep: unrecognized option '--token=ghp_12345678901234567890'`
	candidates = ExtractTargetsFromLog(secretLog)
	if len(candidates) == 0 {
		t.Fatal("expected candidate for grep")
	}
	if strings.Contains(candidates[0].Evidence, "ghp_1234567890") {
		t.Errorf("evidence leaked raw github token: %s", candidates[0].Evidence)
	}
	if !strings.Contains(candidates[0].Evidence, "[REDACTED_GITHUB_TOKEN]") {
		t.Errorf("evidence missing redaction marker: %s", candidates[0].Evidence)
	}
}
