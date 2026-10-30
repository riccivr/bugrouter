package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/riccivr/bugrouter/internal/httpx"
)

func TestRegistryProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/express/latest":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"name": "express",
				"version": "4.18.2",
				"repository": {"type": "git", "url": "https://github.com/expressjs/express.git"},
				"bugs": {"url": "https://github.com/expressjs/express/issues"}
			}`)

		case r.URL.Path == "/pypi/requests/json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"info": {
					"name": "requests",
					"home_page": "https://requests.readthedocs.io",
					"project_urls": {
						"Source": "https://github.com/psf/requests",
						"Issue Tracker": "https://github.com/psf/requests/issues"
					}
				}
			}`)

		case r.URL.Path == "/api/v1/crates/serde":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"crate": {
					"name": "serde",
					"repository": "https://github.com/serde-rs/serde"
				}
			}`)

		case r.URL.Path == "/delayed/latest":
			time.Sleep(30 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"name": "delayed-npm",
				"repository": "https://github.com/npm-org/delayed.git",
				"bugs": "https://github.com/npm-org/delayed/issues"
			}`)

		case r.URL.Path == "/pypi/delayed/json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"info": {
					"name": "fast-pypi",
					"project_urls": {
						"Source": "https://github.com/pypi-org/fast"
					}
				}
			}`)

		// Maven Central
		case r.URL.Path == "/solrsearch/select":
			q := r.URL.Query().Get("q")
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(q, "commons-lang3") {
				fmt.Fprint(w, `{
					"response": {
						"numFound": 1,
						"docs": [
							{
								"id": "org.apache.commons:commons-lang3",
								"g": "org.apache.commons",
								"a": "commons-lang3",
								"latestVersion": "3.14.0",
								"repository": "https://github.com/apache/commons-lang"
							}
						]
					}
				}`)
			} else if strings.Contains(q, "inferred-lib") {
				fmt.Fprint(w, `{
					"response": {
						"numFound": 1,
						"docs": [
							{
								"id": "com.github.sampleuser:inferred-lib",
								"g": "com.github.sampleuser",
								"a": "inferred-lib",
								"latestVersion": "1.0.0"
							}
						]
					}
				}`)
			} else if strings.Contains(q, "multi-compete") {
				time.Sleep(10 * time.Millisecond)
				fmt.Fprint(w, `{
					"response": {
						"numFound": 1,
						"docs": [
							{
								"id": "com.example:multi-compete",
								"g": "com.example",
								"a": "multi-compete",
								"repository": "https://github.com/maven-org/multi-compete"
							}
						]
					}
				}`)
			} else {
				fmt.Fprint(w, `{"response": {"numFound": 0, "docs": []}}`)
			}

		// NuGet
		case r.URL.Path == "/v3/registration5-semver1/newtonsoft.json/index.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"count": 1,
				"items": [
					{
						"count": 1,
						"items": [
							{
								"catalogEntry": {
									"id": "Newtonsoft.Json",
									"version": "13.0.3",
									"projectUrl": "https://github.com/JamesNK/Newtonsoft.Json"
								}
							}
						]
					}
				]
			}`)

		case r.URL.Path == "/v3/registration5-semver1/multi-compete/index.json":
			// Fast response to test priority ordering (Maven is slower but higher priority)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"count": 1,
				"items": [
					{
						"catalogEntry": {
							"id": "multi-compete",
							"projectUrl": "https://github.com/nuget-org/multi-compete"
						}
					}
				]
			}`)

		// RubyGems
		case r.URL.Path == "/api/v1/gems/rails.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"name": "rails",
				"source_code_uri": "https://github.com/rails/rails",
				"bug_tracker_uri": "https://github.com/rails/rails/issues",
				"homepage_uri": "https://rubyonrails.org"
			}`)

		case r.URL.Path == "/api/v1/gems/devise.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"name": "devise",
				"metadata": {
					"source_code_uri": "https://github.com/heartcombo/devise",
					"bug_tracker_uri": "https://github.com/heartcombo/devise/issues"
				}
			}`)

		case r.URL.Path == "/api/v1/gems/gem-compete.json":
			time.Sleep(15 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"name": "gem-compete",
				"source_code_uri": "https://github.com/ruby-org/gem-compete",
				"bug_tracker_uri": "https://github.com/ruby-org/gem-compete/issues"
			}`)

		// Packagist
		case r.URL.Path == "/p/monolog/monolog.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"packages": {
					"monolog/monolog": [
						{
							"name": "monolog/monolog",
							"source": {
								"type": "git",
								"url": "https://github.com/Seldaek/monolog.git"
							},
							"support": {
								"issues": "https://github.com/Seldaek/monolog/issues"
							}
						}
					]
				}
			}`)

		case r.URL.Path == "/p/symfony/console.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"packages": {
					"symfony/console": {
						"v6.0.0": {
							"name": "symfony/console",
							"source": {
								"type": "git",
								"url": "https://github.com/symfony/console.git"
							},
							"support": {
								"issues": "https://github.com/symfony/console/issues"
							}
						}
					}
				}
			}`)

		case r.URL.Path == "/p/gem-compete.json":
			// Packagist response without delay; RubyGems has delay but higher priority
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"packages": {
					"gem-compete": [
						{
							"name": "gem-compete",
							"homepage": "https://github.com/php-org/gem-compete",
							"support": {
								"issues": "https://github.com/php-org/gem-compete/issues"
							}
						}
					]
				}
			}`)

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := httpx.NewTestClient(time.Second)
	endpoints := RegistryEndpoints{
		NPMBaseURL:       srv.URL,
		PyPIBaseURL:      srv.URL,
		CratesBaseURL:    srv.URL,
		MavenBaseURL:     srv.URL,
		NuGetBaseURL:     srv.URL,
		RubyGemsBaseURL:  srv.URL,
		PackagistBaseURL: srv.URL,
	}
	probe := NewRegistryProbe(client, endpoints)

	t.Run("npm resolution", func(t *testing.T) {
		target, err := probe.Resolve(context.Background(), "express")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.Layer != LayerRegistry {
			t.Errorf("Layer = %q, want %q", target.Layer, LayerRegistry)
		}
		if target.CanonicalName != "express" {
			t.Errorf("CanonicalName = %q, want express", target.CanonicalName)
		}
		if target.LocalVersion != "" {
			t.Errorf("LocalVersion = %q, want empty", target.LocalVersion)
		}
		if target.Tracker.Protocol != ProtocolGitHub {
			t.Errorf("Tracker.Protocol = %q, want %q", target.Tracker.Protocol, ProtocolGitHub)
		}
		if target.Tracker.URL != "https://github.com/expressjs/express/issues" {
			t.Errorf("Tracker.URL = %q, want express issues URL", target.Tracker.URL)
		}
	})

	t.Run("pypi resolution fallback", func(t *testing.T) {
		target, err := probe.Resolve(context.Background(), "requests")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.Layer != LayerRegistry {
			t.Errorf("Layer = %q, want %q", target.Layer, LayerRegistry)
		}
		if target.CanonicalName != "requests" {
			t.Errorf("CanonicalName = %q, want requests", target.CanonicalName)
		}
		if target.Tracker.Protocol != ProtocolGitHub {
			t.Errorf("Tracker.Protocol = %q, want %q", target.Tracker.Protocol, ProtocolGitHub)
		}
		if target.Tracker.URL != "https://github.com/psf/requests/issues" {
			t.Errorf("Tracker.URL = %q, want requests issues URL", target.Tracker.URL)
		}
	})

	t.Run("crates resolution fallback", func(t *testing.T) {
		target, err := probe.Resolve(context.Background(), "serde")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.Layer != LayerRegistry {
			t.Errorf("Layer = %q, want %q", target.Layer, LayerRegistry)
		}
		if target.CanonicalName != "serde" {
			t.Errorf("CanonicalName = %q, want serde", target.CanonicalName)
		}
		if target.Tracker.Protocol != ProtocolGitHub {
			t.Errorf("Tracker.Protocol = %q, want %q", target.Tracker.Protocol, ProtocolGitHub)
		}
		if target.Tracker.URL != "https://github.com/serde-rs/serde/issues" {
			t.Errorf("Tracker.URL = %q, want serde issues URL", target.Tracker.URL)
		}
	})

	t.Run("maven central resolution", func(t *testing.T) {
		target, err := probe.Resolve(context.Background(), "org.apache.commons:commons-lang3")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.Layer != LayerRegistry {
			t.Errorf("Layer = %q, want %q", target.Layer, LayerRegistry)
		}
		if target.CanonicalName != "org.apache.commons:commons-lang3" {
			t.Errorf("CanonicalName = %q, want org.apache.commons:commons-lang3", target.CanonicalName)
		}
		if target.Tracker.Protocol != ProtocolGitHub {
			t.Errorf("Tracker.Protocol = %q, want %q", target.Tracker.Protocol, ProtocolGitHub)
		}
		if target.Tracker.URL != "https://github.com/apache/commons-lang/issues" {
			t.Errorf("Tracker.URL = %q, want commons-lang issues URL", target.Tracker.URL)
		}
	})

	t.Run("maven central inferred github repository", func(t *testing.T) {
		target, err := probe.Resolve(context.Background(), "com.github.sampleuser:inferred-lib")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.Tracker.Protocol != ProtocolGitHub {
			t.Errorf("Tracker.Protocol = %q, want %q", target.Tracker.Protocol, ProtocolGitHub)
		}
		if target.Tracker.URL != "https://github.com/sampleuser/inferred-lib/issues" {
			t.Errorf("Tracker.URL = %q, want inferred issues URL", target.Tracker.URL)
		}
	})

	t.Run("nuget resolution", func(t *testing.T) {
		target, err := probe.Resolve(context.Background(), "Newtonsoft.Json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.Layer != LayerRegistry {
			t.Errorf("Layer = %q, want %q", target.Layer, LayerRegistry)
		}
		if target.CanonicalName != "Newtonsoft.Json" {
			t.Errorf("CanonicalName = %q, want Newtonsoft.Json", target.CanonicalName)
		}
		if target.Tracker.Protocol != ProtocolGitHub {
			t.Errorf("Tracker.Protocol = %q, want %q", target.Tracker.Protocol, ProtocolGitHub)
		}
		if target.Tracker.URL != "https://github.com/JamesNK/Newtonsoft.Json/issues" {
			t.Errorf("Tracker.URL = %q, want Newtonsoft.Json issues URL", target.Tracker.URL)
		}
	})

	t.Run("rubygems resolution", func(t *testing.T) {
		target, err := probe.Resolve(context.Background(), "rails")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.Layer != LayerRegistry {
			t.Errorf("Layer = %q, want %q", target.Layer, LayerRegistry)
		}
		if target.CanonicalName != "rails" {
			t.Errorf("CanonicalName = %q, want rails", target.CanonicalName)
		}
		if target.Tracker.Protocol != ProtocolGitHub {
			t.Errorf("Tracker.Protocol = %q, want %q", target.Tracker.Protocol, ProtocolGitHub)
		}
		if target.Tracker.URL != "https://github.com/rails/rails/issues" {
			t.Errorf("Tracker.URL = %q, want rails issues URL", target.Tracker.URL)
		}
	})

	t.Run("rubygems metadata fallback", func(t *testing.T) {
		target, err := probe.Resolve(context.Background(), "devise")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.CanonicalName != "devise" {
			t.Errorf("CanonicalName = %q, want devise", target.CanonicalName)
		}
		if target.Tracker.URL != "https://github.com/heartcombo/devise/issues" {
			t.Errorf("Tracker.URL = %q, want devise issues URL", target.Tracker.URL)
		}
	})

	t.Run("packagist resolution v2 array format", func(t *testing.T) {
		target, err := probe.Resolve(context.Background(), "monolog/monolog")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.Layer != LayerRegistry {
			t.Errorf("Layer = %q, want %q", target.Layer, LayerRegistry)
		}
		if target.CanonicalName != "monolog/monolog" {
			t.Errorf("CanonicalName = %q, want monolog/monolog", target.CanonicalName)
		}
		if target.Tracker.Protocol != ProtocolGitHub {
			t.Errorf("Tracker.Protocol = %q, want %q", target.Tracker.Protocol, ProtocolGitHub)
		}
		if target.Tracker.URL != "https://github.com/Seldaek/monolog/issues" {
			t.Errorf("Tracker.URL = %q, want monolog issues URL", target.Tracker.URL)
		}
	})

	t.Run("packagist resolution v1 map format", func(t *testing.T) {
		target, err := probe.Resolve(context.Background(), "symfony/console")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.CanonicalName != "symfony/console" {
			t.Errorf("CanonicalName = %q, want symfony/console", target.CanonicalName)
		}
		if target.Tracker.URL != "https://github.com/symfony/console/issues" {
			t.Errorf("Tracker.URL = %q, want symfony console issues URL", target.Tracker.URL)
		}
	})

	t.Run("concurrent priority ordering npm over pypi", func(t *testing.T) {
		// Even though PyPI responds faster, npm (priority index 0) must take precedence.
		target, err := probe.Resolve(context.Background(), "delayed")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.CanonicalName != "delayed-npm" {
			t.Errorf("CanonicalName = %q, want delayed-npm (npm priority)", target.CanonicalName)
		}
	})

	t.Run("concurrent priority ordering maven over nuget", func(t *testing.T) {
		// Maven is delayed by 10ms, NuGet responds immediately; Maven (index 3) must take precedence.
		target, err := probe.Resolve(context.Background(), "multi-compete")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.CanonicalName != "com.example:multi-compete" {
			t.Errorf("CanonicalName = %q, want com.example:multi-compete", target.CanonicalName)
		}
		if target.Tracker.URL != "https://github.com/maven-org/multi-compete/issues" {
			t.Errorf("Tracker.URL = %q, want maven multi-compete issues", target.Tracker.URL)
		}
	})

	t.Run("concurrent priority ordering rubygems over packagist", func(t *testing.T) {
		// RubyGems is delayed by 15ms, Packagist responds immediately; RubyGems (index 5) must take precedence.
		target, err := probe.Resolve(context.Background(), "gem-compete")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.CanonicalName != "gem-compete" {
			t.Errorf("CanonicalName = %q, want gem-compete", target.CanonicalName)
		}
		if target.Tracker.URL != "https://github.com/ruby-org/gem-compete/issues" {
			t.Errorf("Tracker.URL = %q, want ruby gem-compete issues", target.Tracker.URL)
		}
	})

	t.Run("invalid queries", func(t *testing.T) {
		badQueries := []string{"foo bar", "../bad", "http://example.com", "https://example.com"}
		for _, q := range badQueries {
			_, err := probe.Resolve(context.Background(), q)
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("query %q: got error %v, want ErrNotFound", q, err)
			}
		}
	})

	t.Run("scope skipping", func(t *testing.T) {
		// Scoped package skips PyPI, Crates, Maven, NuGet, RubyGems, Packagist
		_, err := probe.Resolve(context.Background(), "@org/missing")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("got error %v, want ErrNotFound", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := probe.Resolve(context.Background(), "nonexistent-package")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("got error %v, want ErrNotFound", err)
		}
	})

	t.Run("context cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := probe.Resolve(ctx, "nonexistent-package")
		if !errors.Is(err, context.Canceled) {
			t.Errorf("got error %v, want context.Canceled", err)
		}
	})
}
