package resolver

import (
	"context"
	"errors"
	"testing"
)

func TestDirectProbe(t *testing.T) {
	probe := NewDirectProbe()

	tests := []struct {
		name          string
		query         string
		wantCanonical string
		wantProtocol  Protocol
		wantURL       string
	}{
		{
			name:          "github url with https",
			query:         "https://github.com/BurntSushi/ripgrep",
			wantCanonical: "ripgrep",
			wantProtocol:  ProtocolGitHub,
			wantURL:       "https://github.com/BurntSushi/ripgrep/issues",
		},
		{
			name:          "github qualified path without scheme",
			query:         "github.com/lovell/sharp",
			wantCanonical: "sharp",
			wantProtocol:  ProtocolGitHub,
			wantURL:       "https://github.com/lovell/sharp/issues",
		},
		{
			name:          "gitlab qualified path without scheme",
			query:         "gitlab.com/gnachman/iterm2",
			wantCanonical: "iterm2",
			wantProtocol:  ProtocolGitLab,
			wantURL:       "https://gitlab.com/gnachman/iterm2/issues",
		},
		{
			name:          "codeberg qualified path",
			query:         "codeberg.org/forgejo/forgejo",
			wantCanonical: "forgejo",
			wantProtocol:  ProtocolCodeberg,
			wantURL:       "https://codeberg.org/forgejo/forgejo/issues",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, err := probe.Resolve(context.Background(), tc.query)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if target.CanonicalName != tc.wantCanonical {
				t.Errorf("CanonicalName = %q, want %q", target.CanonicalName, tc.wantCanonical)
			}
			if target.Tracker.Protocol != tc.wantProtocol {
				t.Errorf("Protocol = %q, want %q", target.Tracker.Protocol, tc.wantProtocol)
			}
			if target.Tracker.URL != tc.wantURL {
				t.Errorf("URL = %q, want %q", target.Tracker.URL, tc.wantURL)
			}
			if target.Layer != LayerWebDomain {
				t.Errorf("Layer = %q, want %q", target.Layer, LayerWebDomain)
			}
		})
	}

	// Non-matching query and generic web root
	for _, nonMatch := range []string{"ripgrep", "curl", "grep", "package", "https://stripe.com"} {
		_, err := probe.Resolve(context.Background(), nonMatch)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("expected ErrNotFound for %q, got: %v", nonMatch, err)
		}
	}
}
