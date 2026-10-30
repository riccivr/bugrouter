package resolver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/riccivr/bugrouter/internal/httpx"
)

// RegistryEndpoints holds the base URLs for package registry APIs.
type RegistryEndpoints struct {
	NPMBaseURL       string
	PyPIBaseURL      string
	CratesBaseURL    string
	MavenBaseURL     string
	NuGetBaseURL     string
	RubyGemsBaseURL  string
	PackagistBaseURL string
}

// DefaultRegistryEndpoints returns canonical public registry URLs.
func DefaultRegistryEndpoints() RegistryEndpoints {
	return RegistryEndpoints{
		NPMBaseURL:       "https://registry.npmjs.org",
		PyPIBaseURL:      "https://pypi.org",
		CratesBaseURL:    "https://crates.io",
		MavenBaseURL:     "https://search.maven.org",
		NuGetBaseURL:     "https://api.nuget.org",
		RubyGemsBaseURL:  "https://rubygems.org",
		PackagistBaseURL: "https://repo.packagist.org",
	}
}

// RegistryProbe resolves software targets by querying upstream ecosystem registries.
type RegistryProbe struct {
	client    *httpx.Client
	endpoints RegistryEndpoints
}

// NewRegistryProbe creates a probe querying npm, PyPI, Crates.io, Maven Central, NuGet, RubyGems, and Packagist.
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

type mavenResponse struct {
	Response struct {
		NumFound int `json:"numFound"`
		Docs     []struct {
			ID            string   `json:"id"`
			G             string   `json:"g"`
			A             string   `json:"a"`
			LatestVersion string   `json:"latestVersion"`
			Repository    string   `json:"repository"`
			URL           string   `json:"url"`
			Text          []string `json:"text"`
		} `json:"docs"`
	} `json:"response"`
}

type nugetResponse struct {
	Count int `json:"count"`
	Items []struct {
		Count int `json:"count"`
		Items []struct {
			CatalogEntry struct {
				ID         string `json:"id"`
				Version    string `json:"version"`
				ProjectURL string `json:"projectUrl"`
				Repository string `json:"repository"`
			} `json:"catalogEntry"`
		} `json:"items"`
		CatalogEntry *struct {
			ID         string `json:"id"`
			Version    string `json:"version"`
			ProjectURL string `json:"projectUrl"`
			Repository string `json:"repository"`
		} `json:"catalogEntry"`
	} `json:"items"`
}

type rubyGemsResponse struct {
	Name          string `json:"name"`
	SourceCodeURI string `json:"source_code_uri"`
	BugTrackerURI string `json:"bug_tracker_uri"`
	HomepageURI   string `json:"homepage_uri"`
	ProjectURI    string `json:"project_uri"`
	Metadata      struct {
		SourceCodeURI string `json:"source_code_uri"`
		BugTrackerURI string `json:"bug_tracker_uri"`
	} `json:"metadata"`
}

type packagistVersion struct {
	Name     string `json:"name"`
	Homepage string `json:"homepage"`
	Source   struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"source"`
	Support struct {
		Issues string `json:"issues"`
		Source string `json:"source"`
	} `json:"support"`
}

type packagistResponse struct {
	Packages map[string]json.RawMessage `json:"packages"`
}

// Resolve queries public package registries concurrently in deterministic priority order.
func (r *RegistryProbe) Resolve(ctx context.Context, query string) (*Target, error) {
	if strings.ContainsAny(query, " \t\r\n") || strings.Contains(query, "..") || strings.HasPrefix(query, "http://") || strings.HasPrefix(query, "https://") {
		return nil, ErrNotFound
	}

	// Results array holds per-registry resolution indexed by priority:
	// 0=npm, 1=PyPI, 2=Crates.io, 3=Maven, 4=NuGet, 5=RubyGems, 6=Packagist.
	var results [7]*Target
	var wg sync.WaitGroup

	// 0. npm lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		npmBase := r.endpoints.NPMBaseURL
		if npmBase == "" {
			npmBase = "https://registry.npmjs.org"
		}
		npmURL := fmt.Sprintf("%s/%s/latest", strings.TrimRight(npmBase, "/"), strings.TrimLeft(query, "/"))
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
			pypiBase := r.endpoints.PyPIBaseURL
			if pypiBase == "" {
				pypiBase = "https://pypi.org"
			}
			pypiURL := fmt.Sprintf("%s/pypi/%s/json", strings.TrimRight(pypiBase, "/"), query)
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
			cratesBase := r.endpoints.CratesBaseURL
			if cratesBase == "" {
				cratesBase = "https://crates.io"
			}
			cratesURL := fmt.Sprintf("%s/api/v1/crates/%s", strings.TrimRight(cratesBase, "/"), query)
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

	// 3. Maven Central lookup (Java: groupId:artifactId or groupId/artifactId)
	var mavenG, mavenA string
	if strings.Contains(query, ":") {
		parts := strings.SplitN(query, ":", 2)
		mavenG = parts[0]
		mavenA = parts[1]
	} else if strings.Contains(query, "/") && !strings.HasPrefix(query, "@") {
		parts := strings.SplitN(query, "/", 2)
		mavenG = parts[0]
		mavenA = parts[1]
	} else if !strings.HasPrefix(query, "@") {
		mavenG = query
		mavenA = query
	}

	if !strings.HasPrefix(query, "@") && mavenG != "" && mavenA != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mavenBase := r.endpoints.MavenBaseURL
			if mavenBase == "" {
				mavenBase = "https://search.maven.org"
			}
			mavenURL := fmt.Sprintf("%s/solrsearch/select?q=g:\"%s\"+AND+a:\"%s\"&rows=1&wt=json", strings.TrimRight(mavenBase, "/"), mavenG, mavenA)
			var mavenPkg mavenResponse
			if err := r.client.GetJSON(ctx, mavenURL, &mavenPkg); err == nil && len(mavenPkg.Response.Docs) > 0 {
				doc := mavenPkg.Response.Docs[0]
				repoURL := doc.Repository
				if repoURL == "" {
					repoURL = doc.URL
				}
				if repoURL == "" {
					for _, t := range doc.Text {
						if strings.HasPrefix(t, "https://") || strings.HasPrefix(t, "http://") {
							repoURL = t
							break
						}
					}
				}
				if repoURL == "" {
					if strings.HasPrefix(doc.G, "com.github.") {
						repoURL = fmt.Sprintf("https://github.com/%s/%s", strings.TrimPrefix(doc.G, "com.github."), doc.A)
					} else if strings.HasPrefix(doc.G, "io.github.") {
						repoURL = fmt.Sprintf("https://github.com/%s/%s", strings.TrimPrefix(doc.G, "io.github."), doc.A)
					} else if strings.HasPrefix(doc.G, "com.gitlab.") {
						repoURL = fmt.Sprintf("https://gitlab.com/%s/%s", strings.TrimPrefix(doc.G, "com.gitlab."), doc.A)
					}
				}

				tracker, normRepo := ClassifyTracker("", "", repoURL)
				if isValidTracker(tracker) {
					canonicalName := doc.ID
					if canonicalName == "" {
						canonicalName = fmt.Sprintf("%s:%s", doc.G, doc.A)
					}
					if canonicalName == ":" || canonicalName == "" {
						canonicalName = query
					}
					results[3] = &Target{
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

	// 4. NuGet (.NET) lookup
	if !strings.HasPrefix(query, "@") && !strings.Contains(query, "/") && !strings.Contains(query, ":") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nugetBase := r.endpoints.NuGetBaseURL
			if nugetBase == "" {
				nugetBase = "https://api.nuget.org"
			}
			nugetURL := fmt.Sprintf("%s/v3/registration5-semver1/%s/index.json", strings.TrimRight(nugetBase, "/"), strings.ToLower(query))
			var nugetPkg nugetResponse
			if err := r.client.GetJSON(ctx, nugetURL, &nugetPkg); err == nil && len(nugetPkg.Items) > 0 {
				var projectURL, repoURL, canonicalName string
				for _, page := range nugetPkg.Items {
					if page.CatalogEntry != nil {
						if projectURL == "" {
							projectURL = page.CatalogEntry.ProjectURL
						}
						if repoURL == "" {
							repoURL = page.CatalogEntry.Repository
						}
						if canonicalName == "" {
							canonicalName = page.CatalogEntry.ID
						}
					}
					for _, leaf := range page.Items {
						if projectURL == "" {
							projectURL = leaf.CatalogEntry.ProjectURL
						}
						if repoURL == "" {
							repoURL = leaf.CatalogEntry.Repository
						}
						if canonicalName == "" {
							canonicalName = leaf.CatalogEntry.ID
						}
					}
				}

				targetURL := repoURL
				if targetURL == "" {
					targetURL = projectURL
				}
				tracker, normRepo := ClassifyTracker("", "", targetURL)
				if isValidTracker(tracker) {
					if canonicalName == "" {
						canonicalName = query
					}
					results[4] = &Target{
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

	// 5. RubyGems lookup
	if !strings.HasPrefix(query, "@") && !strings.Contains(query, "/") && !strings.Contains(query, ":") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rubyBase := r.endpoints.RubyGemsBaseURL
			if rubyBase == "" {
				rubyBase = "https://rubygems.org"
			}
			rubyURL := fmt.Sprintf("%s/api/v1/gems/%s.json", strings.TrimRight(rubyBase, "/"), query)
			var rubyPkg rubyGemsResponse
			if err := r.client.GetJSON(ctx, rubyURL, &rubyPkg); err == nil {
				bugsURL := strings.TrimSpace(rubyPkg.BugTrackerURI)
				if bugsURL == "" {
					bugsURL = strings.TrimSpace(rubyPkg.Metadata.BugTrackerURI)
				}
				repoURL := strings.TrimSpace(rubyPkg.SourceCodeURI)
				if repoURL == "" {
					repoURL = strings.TrimSpace(rubyPkg.Metadata.SourceCodeURI)
				}
				if repoURL == "" {
					repoURL = strings.TrimSpace(rubyPkg.HomepageURI)
				}
				if repoURL == "" && bugsURL == "" {
					repoURL = strings.TrimSpace(rubyPkg.ProjectURI)
				}

				tracker, normRepo := ClassifyTracker(bugsURL, "", repoURL)
				if isValidTracker(tracker) {
					canonicalName := rubyPkg.Name
					if canonicalName == "" {
						canonicalName = query
					}
					results[5] = &Target{
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

	// 6. Packagist (PHP) lookup
	if !strings.HasPrefix(query, "@") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			packagistBase := r.endpoints.PackagistBaseURL
			if packagistBase == "" {
				packagistBase = "https://repo.packagist.org"
			}
			packagistPkg := query
			if strings.Contains(packagistPkg, ":") {
				packagistPkg = strings.Replace(packagistPkg, ":", "/", 1)
			}
			packagistURL := fmt.Sprintf("%s/p/%s.json", strings.TrimRight(packagistBase, "/"), packagistPkg)
			var packagistPkgResp packagistResponse
			if err := r.client.GetJSON(ctx, packagistURL, &packagistPkgResp); err == nil {
				for _, rawBytes := range packagistPkgResp.Packages {
					var versions []packagistVersion
					raw := bytes.TrimSpace(rawBytes)
					if len(raw) > 0 && raw[0] == '[' {
						if unmarshalErr := json.Unmarshal(raw, &versions); unmarshalErr != nil {
							continue
						}
					} else if len(raw) > 0 && raw[0] == '{' {
						var verMap map[string]packagistVersion
						if unmarshalErr := json.Unmarshal(raw, &verMap); unmarshalErr == nil {
							for _, v := range verMap {
								versions = append(versions, v)
							}
						} else {
							var single packagistVersion
							if singleErr := json.Unmarshal(raw, &single); singleErr == nil {
								versions = append(versions, single)
							}
						}
					}

					for _, v := range versions {
						issuesURL := strings.TrimSpace(v.Support.Issues)
						repoURL := strings.TrimSpace(v.Support.Source)
						if repoURL == "" {
							repoURL = strings.TrimSpace(v.Source.URL)
						}
						if repoURL == "" {
							repoURL = strings.TrimSpace(v.Homepage)
						}
						if repoURL == "" && issuesURL == "" {
							repoURL = fmt.Sprintf("https://packagist.org/packages/%s", v.Name)
						}

						tracker, normRepo := ClassifyTracker(issuesURL, "", repoURL)
						if isValidTracker(tracker) {
							canonicalName := v.Name
							if canonicalName == "" {
								canonicalName = query
							}
							results[6] = &Target{
								Query:         query,
								CanonicalName: canonicalName,
								Layer:         LayerRegistry,
								RepositoryURL: normRepo,
								Tracker:       tracker,
							}
							return
						}
					}
				}
			}
		}()
	}

	wg.Wait()

	// Return the first non-nil match in deterministic priority order:
	// npm -> PyPI -> Crates.io -> Maven -> NuGet -> RubyGems -> Packagist.
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
