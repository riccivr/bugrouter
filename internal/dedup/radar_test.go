package dedup

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/resolver"
)

func TestBuildStackRadar(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items": [{"number": 99, "title": "Memory leak regression in worker", "html_url": "https://github.com/myorg/worker/issues/99", "state": "open"}]}`)
	}))
	defer ts.Close()

	tempDir := t.TempDir()
	pkgJsonContent := `{
		"dependencies": {
			"https://github.com/myorg/worker": "1.0.0"
		}
	}`
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(pkgJsonContent), 0600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	wf := resolver.NewWaterfall(time.Second, resolver.NewDirectProbe())
	finder := NewFinder(httpx.NewTestClient(time.Second)).WithEndpoints(Endpoints{
		GitHubAPIBaseURL: ts.URL,
	})

	// 1. Without checkUpstream
	report1, err := BuildStackRadar(context.Background(), wf, finder, tempDir, false)
	if err != nil {
		t.Fatalf("BuildStackRadar (checkUpstream=false) failed: %v", err)
	}
	if report1.Total != 1 || report1.Resolved != 1 {
		t.Errorf("expected 1 total/resolved, got %d/%d", report1.Total, report1.Resolved)
	}
	if len(report1.Entries[0].UpstreamBugs) != 0 {
		t.Errorf("expected 0 upstream bugs without checkUpstream, got %d", len(report1.Entries[0].UpstreamBugs))
	}

	// 2. With checkUpstream
	report2, err := BuildStackRadar(context.Background(), wf, finder, tempDir, true)
	if err != nil {
		t.Fatalf("BuildStackRadar (checkUpstream=true) failed: %v", err)
	}
	if len(report2.Entries[0].UpstreamBugs) != 1 {
		t.Fatalf("expected 1 upstream bug with checkUpstream, got %d", len(report2.Entries[0].UpstreamBugs))
	}
	if report2.Entries[0].UpstreamBugs[0].ID != "99" {
		t.Errorf("expected bug ID 99, got %s", report2.Entries[0].UpstreamBugs[0].ID)
	}
}
