package resolver

import (
	"context"
	"strings"
)

// DirectProbe resolves queries that are explicit repository URLs or qualified web paths.
type DirectProbe struct{}

// NewDirectProbe initializes a probe for explicit web URL and domain resolution.
func NewDirectProbe() *DirectProbe {
	return &DirectProbe{}
}

// Name returns the probe identifier.
func (p *DirectProbe) Name() string {
	return "direct-url"
}

// Layer returns the resolution layer classification.
func (p *DirectProbe) Layer() SourceLayer {
	return LayerWebDomain
}

// Resolve identifies explicit URLs and repository paths.
func (p *DirectProbe) Resolve(ctx context.Context, query string) (*Target, error) {
	trimmed := strings.TrimSpace(query)
	hasPrefix := strings.HasPrefix(trimmed, "http://") ||
		strings.HasPrefix(trimmed, "https://") ||
		strings.HasPrefix(trimmed, "github.com/") ||
		strings.HasPrefix(trimmed, "gitlab.com/") ||
		strings.HasPrefix(trimmed, "codeberg.org/") ||
		strings.HasPrefix(trimmed, "sr.ht/")

	if !hasPrefix {
		return nil, ErrNotFound
	}

	queryURL := trimmed
	if !strings.HasPrefix(queryURL, "http://") && !strings.HasPrefix(queryURL, "https://") {
		queryURL = "https://" + queryURL
	}

	tracker, normRepo := ClassifyTracker("", "", queryURL)

	canonicalName := trimmed
	if normRepo != "" {
		parts := strings.Split(strings.TrimRight(normRepo, "/"), "/")
		if len(parts) > 0 && parts[len(parts)-1] != "" {
			canonicalName = parts[len(parts)-1]
		}
	}

	return &Target{
		Query:         query,
		CanonicalName: canonicalName,
		Layer:         LayerWebDomain,
		RepositoryURL: normRepo,
		Tracker:       tracker,
	}, nil
}
