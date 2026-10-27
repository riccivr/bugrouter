package resolver

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/riccivr/bugrouter/internal/httpx"
)

// RegistryEndpoints holds the base URLs for package registry APIs.
type RegistryEndpoints struct {
	NPMBaseURL    string
	PyPIBaseURL   string
	CratesBaseURL string
}

// DefaultRegistryEndpoints returns canonical public registry URLs.
func DefaultRegistryEndpoints() RegistryEndpoints {
	return RegistryEndpoints{
		NPMBaseURL:    "https://registry.npmjs.org",
		PyPIBaseURL:   "https://pypi.org",
		CratesBaseURL: "https://crates.io",
	}
}

// RegistryProbe resolves software targets by querying upstream ecosystem registries.
type RegistryProbe struct {
	client    *httpx.Client
	endpoints RegistryEndpoints
}

// NewRegistryProbe creates a probe querying npm, PyPI, and Crates.io registries.
func NewRegistryProbe(client *httpx.Client, endpoints RegistryEndpoints) *RegistryProbe {
	return &RegistryProbe{
		client:    client,
		endpoints: endpoints,
	}
}

// Name returns the probe identifier.
func (r *RegistryProbe) Name() string {
	return "registry"
}

// Layer returns the resolution layer classification.
func (r *RegistryProbe) Layer() SourceLayer {
	return LayerRegistry
}

func isValidTracker(t TrackerInfo) bool {
	return t.URL != "" || t.Email != ""
}

type pypiResponse struct {
	Info struct {
		Name        string            `json:"name"`
		BugtrackURL string            `json:"bugtrack_url"`
		HomePage    string            `json:"home_page"`
		ProjectURLs map[string]string `json:"project_urls"`
	} `json:"info"`
}

type cratesResponse struct {
	Crate struct {
		Name       string `json:"name"`
		Repository string `json:"repository"`
		Homepage   string `json:"homepage"`
	} `json:"crate"`
}

// Resolve queries public package registries concurrently in deterministic priority order.
func (r *RegistryProbe) Resolve(ctx context.Context, query string) (*Target, error) {
	if strings.ContainsAny(query, " \t\r\n") || strings.Contains(query, "..") || strings.HasPrefix(query, "http://") || strings.HasPrefix(query, "https://") {
		return nil, ErrNotFound
	}

	// Results array holds per-registry resolution indexed by priority: 0=npm, 1=PyPI, 2=Crates.io.
	var results [3]*Target
	var wg sync.WaitGroup

	// 0. npm lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		npmURL := fmt.Sprintf("%s/%s/latest", strings.TrimRight(r.endpoints.NPMBaseURL, "/"), strings.TrimLeft(query, "/"))
		var npmPkg nodePackage
		if err := r.client.GetJSON(ctx, npmURL, &npmPkg); err == nil {
			bugsURL, bugsEmail := parseBugs(npmPkg.Bugs)
			repoURL := parseRepository(npmPkg.Repository)
			tracker, normRepo := ClassifyTracker(bugsURL, bugsEmail, repoURL)
			if isValidTracker(tracker) {
				canonicalName := npmPkg.Name
				if canonicalName == "" {
					canonicalName = query
				}
				results[0] = &Target{
					Query:         query,
					CanonicalName: canonicalName,
					Layer:         LayerRegistry,
					RepositoryURL: normRepo,
					Tracker:       tracker,
				}
			}
		}
	}()

	// 1. PyPI lookup (scoped packages with @ are npm-specific)
	if !strings.HasPrefix(query, "@") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pypiURL := fmt.Sprintf("%s/pypi/%s/json", strings.TrimRight(r.endpoints.PyPIBaseURL, "/"), query)
			var pypiPkg pypiResponse
			if err := r.client.GetJSON(ctx, pypiURL, &pypiPkg); err == nil {
				var bugsURL string
				var repoURL string

				// Sort keys for deterministic inspection
				keys := make([]string, 0, len(pypiPkg.Info.ProjectURLs))
				for k := range pypiPkg.Info.ProjectURLs {
					keys = append(keys, k)
				}
				sort.Strings(keys)

				for _, k := range keys {
					val := strings.TrimSpace(pypiPkg.Info.ProjectURLs[k])
					if val == "" {
						continue
					}
					lk := strings.ToLower(k)
					if bugsURL == "" && (strings.Contains(lk, "bug") || strings.Contains(lk, "issue") || strings.Contains(lk, "tracker")) {
						bugsURL = val
					}
					if repoURL == "" && (strings.Contains(lk, "source") || strings.Contains(lk, "repository") || strings.Contains(lk, "code") || strings.Contains(lk, "github") || strings.Contains(lk, "gitlab")) {
						repoURL = val
					}
				}

				if bugsURL == "" {
					bugsURL = pypiPkg.Info.BugtrackURL
				}
				if repoURL == "" {
					repoURL = pypiPkg.Info.HomePage
				}

				tracker, normRepo := ClassifyTracker(bugsURL, "", repoURL)
				if isValidTracker(tracker) {
					canonicalName := pypiPkg.Info.Name
					if canonicalName == "" {
						canonicalName = query
					}
					results[1] = &Target{
						Query:         query,
						CanonicalName: canonicalName,
						Layer:         LayerRegistry,
						RepositoryURL: normRepo,
						Tracker:       tracker,
					}
				}
			}
		}()
	}

	// 2. Crates.io lookup (crates cannot contain slashes or scoped @ prefixes)
	if !strings.HasPrefix(query, "@") && !strings.Contains(query, "/") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cratesURL := fmt.Sprintf("%s/api/v1/crates/%s", strings.TrimRight(r.endpoints.CratesBaseURL, "/"), query)
			var cratesPkg cratesResponse
			if err := r.client.GetJSON(ctx, cratesURL, &cratesPkg); err == nil {
				repo := cratesPkg.Crate.Repository
				if repo == "" {
					repo = cratesPkg.Crate.Homepage
				}
				tracker, normRepo := ClassifyTracker("", "", repo)
				if isValidTracker(tracker) {
					canonicalName := cratesPkg.Crate.Name
					if canonicalName == "" {
						canonicalName = query
					}
					results[2] = &Target{
						Query:         query,
						CanonicalName: canonicalName,
						Layer:         LayerRegistry,
						RepositoryURL: normRepo,
						Tracker:       tracker,
					}
				}
			}
		}()
	}

	wg.Wait()

	// Return the first non-nil match in deterministic priority order: npm -> PyPI -> Crates.io.
	for i := 0; i < len(results); i++ {
		if results[i] != nil {
			return results[i], nil
		}
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return nil, ErrNotFound
}
