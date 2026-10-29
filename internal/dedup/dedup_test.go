package dedup

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/scrubber"
)

func TestExtractSearchTermsAndScoring(t *testing.T) {
	// 1. Secret redaction and stop word filtering
	rawTitle := scrubber.ScrubbedText("Crash when using AKIAIOSFODNN7EXAMPLE into buffer with deadlock")
	terms := ExtractSearchTerms(rawTitle)

	// AKIAIOSFODNN7EXAMPLE should become [REDACTED_AWS_KEY] and get removed.
	// "when", "using", "into", "with", "crash" should be stop words or filtered.
	for _, term := range terms {
		if strings.Contains(term, "akia") || strings.Contains(term, "redacted") {
			t.Errorf("Secret or redaction marker leaked into search terms: %v", terms)
		}
		if stopWords[term] {
			t.Errorf("Stop word %q found in search terms: %v", term, terms)
		}
	}

	expectedTerms := []string{"buffer", "deadlock"}
	if !reflect.DeepEqual(terms, expectedTerms) {
		t.Errorf("ExtractSearchTerms = %v, want %v", terms, expectedTerms)
	}

	// 2. Maximum 5 terms cap
	longTitle := scrubber.ScrubbedText("alpha bravo charlie delta echo foxtrot golf")
	cappedTerms := ExtractSearchTerms(longTitle)
	if len(cappedTerms) != 5 {
		t.Errorf("expected 5 capped terms, got %d: %v", len(cappedTerms), cappedTerms)
	}

	// 3. Similarity scoring
	// Identical
	scoreIdentical := ScoreSimilarity([]string{"buffer", "overflow"}, "Buffer overflow")
	if scoreIdentical != 1.0 {
		t.Errorf("ScoreSimilarity for identical = %v, want 1.0", scoreIdentical)
	}

	// Partial overlap
	scorePartial := ScoreSimilarity([]string{"buffer", "overflow"}, "Buffer overflow in packet parser")
	if scorePartial <= 0.0 || scorePartial > 1.0 {
		t.Errorf("ScoreSimilarity for partial = %v, want between 0.0 and 1.0", scorePartial)
	}

	// No overlap
	scoreNone := ScoreSimilarity([]string{"buffer", "overflow"}, "Database connection timeout")
	if scoreNone != 0.0 {
		t.Errorf("ScoreSimilarity for no overlap = %v, want 0.0", scoreNone)
	}
}

func TestFindDuplicatesGitHubGitLabBugzilla(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/search/issues"):
			// GitHub search
			q := r.URL.Query().Get("q")
			if !strings.Contains(q, "repo:example-org/repo") {
				http.Error(w, "missing repo in query", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"total_count": 2,
				"items": [
					{"number": 101, "title": "Worker buffer overflow on large input", "html_url": "https://github.com/example-org/repo/issues/101", "state": "open"},
					{"number": 55, "title": "Unrelated network timeout", "html_url": "https://github.com/example-org/repo/issues/55", "state": "closed"}
				]
			}`)

		case strings.Contains(r.URL.EscapedPath(), "/api/v4/projects/group%2Fproject/issues"):
			// GitLab search
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[
				{"iid": 202, "title": "Buffer overflow crash in parser", "web_url": "https://gitlab.com/group/project/-/issues/202", "state": "opened"}
			]`)

		case strings.HasPrefix(r.URL.Path, "/rest/bug"):
			// Bugzilla search
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"bugs": [
					{"id": 303, "summary": "Buffer overflow in protocol worker", "status": "NEW"}
				]
			}`)

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client := httpx.NewTestClient(time.Second)
	finder := NewFinder(client).WithEndpoints(Endpoints{
		GitHubAPIBaseURL: ts.URL,
		GitLabBaseURL:    ts.URL,
	})

	// 1. GitHub deduplication
	ghTarget := resolver.Target{
		CanonicalName: "repo",
		RepositoryURL: "https://github.com/example-org/repo",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolGitHub,
			URL:      "https://github.com/example-org/repo/issues",
		},
	}

	ghDups, err := finder.FindDuplicates(context.Background(), ghTarget, scrubber.ScrubbedText("Buffer overflow crash"))
	if err != nil {
		t.Fatalf("FindDuplicates GitHub failed: %v", err)
	}
	if len(ghDups) != 1 {
		t.Fatalf("expected 1 duplicate (unrelated filtered out), got %d: %+v", len(ghDups), ghDups)
	}
	if ghDups[0].ID != "101" {
		t.Errorf("ghDups[0].ID = %q, want 101", ghDups[0].ID)
	}
	if ghDups[0].Score < 0.20 {
		t.Errorf("ghDups[0].Score = %v, want >= 0.20", ghDups[0].Score)
	}

	// 2. GitLab deduplication
	glTarget := resolver.Target{
		CanonicalName: "project",
		RepositoryURL: "https://gitlab.com/group/project",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolGitLab,
			URL:      "https://gitlab.com/group/project/-/issues",
		},
	}

	glDups, err := finder.FindDuplicates(context.Background(), glTarget, scrubber.ScrubbedText("Buffer overflow"))
	if err != nil {
		t.Fatalf("FindDuplicates GitLab failed: %v", err)
	}
	if len(glDups) != 1 {
		t.Fatalf("expected 1 duplicate, got %d", len(glDups))
	}
	if glDups[0].ID != "202" {
		t.Errorf("glDups[0].ID = %q, want 202", glDups[0].ID)
	}

	// 3. Bugzilla deduplication
	bzTarget := resolver.Target{
		CanonicalName: "firefox",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolBugzilla,
			URL:      ts.URL + "/enter_bug.cgi",
		},
	}

	bzDups, err := finder.FindDuplicates(context.Background(), bzTarget, scrubber.ScrubbedText("Buffer overflow worker"))
	if err != nil {
		t.Fatalf("FindDuplicates Bugzilla failed: %v", err)
	}
	if len(bzDups) != 1 {
		t.Fatalf("expected 1 duplicate, got %d", len(bzDups))
	}
	if bzDups[0].ID != "303" {
		t.Errorf("bzDups[0].ID = %q, want 303", bzDups[0].ID)
	}
	expectedBZURL := ts.URL + "/show_bug.cgi?id=303"
	if bzDups[0].URL != expectedBZURL {
		t.Errorf("bzDups[0].URL = %q, want %q", bzDups[0].URL, expectedBZURL)
	}
}

func TestFindDuplicatesEnterpriseHostDerivation(t *testing.T) {
	var ghEnterpriseHit, glEnterpriseHit bool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v3/search/issues"):
			ghEnterpriseHit = true
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"total_count": 1,
				"items": [
					{"number": 404, "title": "Enterprise buffer overflow", "html_url": "https://github.corp/myorg/myrepo/issues/404", "state": "open"}
				]
			}`)
		case strings.Contains(r.URL.EscapedPath(), "/api/v4/projects/mygroup%2Fmyproject/issues"):
			glEnterpriseHit = true
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[
				{"iid": 505, "title": "Self-managed buffer overflow crash", "web_url": "https://gitlab.corp/mygroup/myproject/-/issues/505", "state": "opened"}
			]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client := httpx.NewTestClient(0)
	finder := NewFinder(client) // Uses default endpoints: https://api.github.com, https://gitlab.com

	// 1. GitHub Enterprise target
	ghTarget := resolver.Target{
		CanonicalName: "enterprise-pkg",
		RepositoryURL: ts.URL + "/myorg/myrepo",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolGitHub,
			URL:      ts.URL + "/myorg/myrepo/issues",
		},
	}

	ghDups, err := finder.FindDuplicates(context.Background(), ghTarget, scrubber.ScrubbedText("Buffer overflow"))
	if err != nil {
		t.Fatalf("FindDuplicates GitHub Enterprise failed: %v", err)
	}
	if !ghEnterpriseHit {
		t.Error("GitHub Enterprise /api/v3 base URL was not derived")
	}
	if len(ghDups) != 1 || ghDups[0].ID != "404" {
		t.Errorf("unexpected GitHub Enterprise dups: %+v", ghDups)
	}

	// 2. GitLab Self-Managed target
	glTarget := resolver.Target{
		CanonicalName: "gitlab-self-managed-pkg",
		RepositoryURL: ts.URL + "/mygroup/myproject",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolGitLab,
			URL:      ts.URL + "/mygroup/myproject/-/issues",
		},
	}

	glDups, err := finder.FindDuplicates(context.Background(), glTarget, scrubber.ScrubbedText("Buffer overflow"))
	if err != nil {
		t.Fatalf("FindDuplicates GitLab Self-Managed failed: %v", err)
	}
	if !glEnterpriseHit {
		t.Error("GitLab Self-Managed host base URL was not derived")
	}
	if len(glDups) != 1 || glDups[0].ID != "505" {
		t.Errorf("unexpected GitLab Self-Managed dups: %+v", glDups)
	}
}

func TestFindDuplicatesGitHubAuthHeader(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_dedup_secret_xyz789")
	authHeaderReceived := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer ghp_dedup_secret_xyz789" {
			authHeaderReceived = true
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items": []}`)
	}))
	defer ts.Close()

	client := httpx.NewTestClient(time.Second)
	finder := NewFinder(client).WithEndpoints(Endpoints{
		GitHubAPIBaseURL: ts.URL,
		GitLabBaseURL:    ts.URL,
	})

	target := resolver.Target{
		CanonicalName: "repo",
		RepositoryURL: "https://github.com/myorg/repo",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolGitHub,
			URL:      "https://github.com/myorg/repo/issues",
		},
	}

	_, err := finder.FindDuplicates(context.Background(), target, scrubber.ScrubbedText("Crash on launch"))
	if err != nil {
		t.Fatalf("FindDuplicates failed: %v", err)
	}
	if !authHeaderReceived {
		t.Error("expected Authorization: Bearer ghp_dedup_secret_xyz789 header to be sent")
	}
}

func TestFindDuplicatesBugzillaDoesNotLeakGitLabToken(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "glpat-secret-do-not-leak")
	var leakedPrivateToken, leakedAuth string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakedPrivateToken = r.Header.Get("PRIVATE-TOKEN")
		leakedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"bugs": []}`)
	}))
	defer ts.Close()

	client := httpx.NewTestClient(time.Second)
	finder := NewFinder(client)

	target := resolver.Target{
		CanonicalName: "firefox",
		Tracker: resolver.TrackerInfo{
			Protocol: resolver.ProtocolBugzilla,
			URL:      ts.URL + "/enter_bug.cgi",
		},
	}

	_, err := finder.FindDuplicates(context.Background(), target, scrubber.ScrubbedText("Crash on launch"))
	if err != nil {
		t.Fatalf("FindDuplicates failed: %v", err)
	}
	if leakedPrivateToken != "" {
		t.Errorf("leaked PRIVATE-TOKEN to Bugzilla: %q", leakedPrivateToken)
	}
	if leakedAuth != "" {
		t.Errorf("leaked Authorization to Bugzilla: %q", leakedAuth)
	}
}
