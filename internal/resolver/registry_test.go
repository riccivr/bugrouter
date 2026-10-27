package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/riccivr/bugrouter/internal/httpx"
)

func TestRegistryProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/express/latest":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"name": "express",
				"version": "4.18.2",
				"repository": {"type": "git", "url": "https://github.com/expressjs/express.git"},
				"bugs": {"url": "https://github.com/expressjs/express/issues"}
			}`)

		case "/pypi/requests/json":
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

		case "/api/v1/crates/serde":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
				"crate": {
					"name": "serde",
					"repository": "https://github.com/serde-rs/serde"
				}
			}`)

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := httpx.NewClient(time.Second)
	endpoints := RegistryEndpoints{
		NPMBaseURL:    srv.URL,
		PyPIBaseURL:   srv.URL,
		CratesBaseURL: srv.URL,
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
		// Scoped package skips PyPI and Crates
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
}
