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

func TestWebDomainProbe(t *testing.T) {
	t.Run("bug-report discovery", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/bug-report" {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{
					"canonical_name": "Stripe",
					"bugs_url": "https://github.com/stripe/stripe-node/issues",
					"repository_url": "https://github.com/stripe/stripe-node"
				}`)
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		host := strings.TrimPrefix(srv.URL, "http://")
		client := httpx.NewTestClient(time.Second)
		probe := NewWebDomainProbe(client)
		probe.scheme = "http"

		target, err := probe.Resolve(context.Background(), host)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.Layer != LayerWebDomain {
			t.Errorf("Layer = %q, want %q", target.Layer, LayerWebDomain)
		}
		if target.CanonicalName != "Stripe" {
			t.Errorf("CanonicalName = %q, want Stripe", target.CanonicalName)
		}
		if target.Tracker.Protocol != ProtocolGitHub {
			t.Errorf("Tracker.Protocol = %q, want %q", target.Tracker.Protocol, ProtocolGitHub)
		}
		if target.Tracker.URL != "https://github.com/stripe/stripe-node/issues" {
			t.Errorf("Tracker.URL = %q, want issues URL", target.Tracker.URL)
		}

		// Also verify domain resolution when input includes https:// scheme prefix
		targetWithScheme, err := probe.Resolve(context.Background(), "https://"+host+"/")
		if err != nil {
			t.Fatalf("unexpected error resolving with scheme: %v", err)
		}
		if targetWithScheme.CanonicalName != "Stripe" {
			t.Errorf("CanonicalName = %q, want Stripe", targetWithScheme.CanonicalName)
		}
	})

	t.Run("security.txt fallback", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/security.txt" {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "# Security Contact\nContact: https://example.com/security\nContact: mailto:security@example.com\n")
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		host := strings.TrimPrefix(srv.URL, "http://")
		client := httpx.NewTestClient(time.Second)
		probe := NewWebDomainProbe(client)
		probe.scheme = "http"

		target, err := probe.Resolve(context.Background(), host)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.Layer != LayerWebDomain {
			t.Errorf("Layer = %q, want %q", target.Layer, LayerWebDomain)
		}
		if target.CanonicalName != host {
			t.Errorf("CanonicalName = %q, want %q", target.CanonicalName, host)
		}
		if target.Tracker.URL != "https://example.com/security" {
			t.Errorf("Tracker.URL = %q, want https://example.com/security", target.Tracker.URL)
		}
		if target.Tracker.Email != "security@example.com" {
			t.Errorf("Tracker.Email = %q, want security@example.com", target.Tracker.Email)
		}
	})

	t.Run("invalid queries", func(t *testing.T) {
		client := httpx.NewTestClient(time.Second)
		probe := NewWebDomainProbe(client)

		badQueries := []string{"nodot", "with space.com", "user@domain.com", "domain.com/path", "..", ".domain.com", "domain.com."}
		for _, q := range badQueries {
			_, err := probe.Resolve(context.Background(), q)
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("query %q: got error %v, want ErrNotFound", q, err)
			}
		}
	})

	t.Run("not found", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer srv.Close()

		host := strings.TrimPrefix(srv.URL, "http://")
		client := httpx.NewTestClient(time.Second)
		probe := NewWebDomainProbe(client)
		probe.scheme = "http"

		_, err := probe.Resolve(context.Background(), host)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("got error %v, want ErrNotFound", err)
		}
	})
}
