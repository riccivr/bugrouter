package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Protocol identifies the upstream bug tracker transport mechanism.
type Protocol string

const (
	ProtocolGitHub    Protocol = "github"
	ProtocolGitLab    Protocol = "gitlab"
	ProtocolCodeberg  Protocol = "codeberg"
	ProtocolSourceHut Protocol = "sourcehut"
	ProtocolDebbugs   Protocol = "debbugs"
	ProtocolBugzilla  Protocol = "bugzilla"
	ProtocolWebURL    Protocol = "web-url"
)

// SourceLayer indicates which waterfall layer resolved the target.
type SourceLayer string

const (
	LayerOrgCloud  SourceLayer = "org-cloud"
	LayerWorkspace SourceLayer = "workspace"
	LayerOSPackage SourceLayer = "os-pkg"
	LayerRegistry  SourceLayer = "registry"
	LayerWebDomain SourceLayer = "web-domain"
)

// Target represents a resolved software artifact and its canonical bug tracker.
type Target struct {
	Query         string      `json:"query"`
	CanonicalName string      `json:"canonical_name"`
	LocalVersion  string      `json:"local_version,omitempty"`
	Layer         SourceLayer `json:"layer"`
	RepositoryURL string      `json:"repository_url,omitempty"`
	Tracker       TrackerInfo `json:"tracker"`
}

// TrackerInfo holds the endpoint and submission metadata for a bug tracker.
type TrackerInfo struct {
	Protocol Protocol `json:"protocol"`
	URL      string   `json:"url,omitempty"`
	Email    string   `json:"email,omitempty"`
}

// Probe defines a single resolution strategy in the waterfall.
type Probe interface {
	Name() string
	Layer() SourceLayer
	Resolve(ctx context.Context, query string) (*Target, error)
}

// ErrNotFound signals that no probe could resolve the requested query.
var ErrNotFound = errors.New("target not found")

// TargetCache defines optional read/write caching for resolved targets.
type TargetCache interface {
	Get(key string, dst any) (bool, error)
	Put(key string, val any) error
}

// Waterfall orchestrates ordered resolution probes with bounded timeouts.
type Waterfall struct {
	probes       []Probe
	probeTimeout time.Duration
	cache        TargetCache
}

// NewWaterfall initializes an orchestrator with a per-probe execution limit.
func NewWaterfall(timeout time.Duration, probes ...Probe) *Waterfall {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Waterfall{
		probes:       probes,
		probeTimeout: timeout,
	}
}

// WithCache attaches an optional target cache to the waterfall orchestrator.
func (w *Waterfall) WithCache(c TargetCache) *Waterfall {
	w.cache = c
	return w
}

// Resolve iterates through configured probes in sequential priority order.
func (w *Waterfall) Resolve(ctx context.Context, query string) (*Target, error) {
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return nil, errors.New("query cannot be empty")
	}

	if w.cache != nil {
		var cached Target
		hit, err := w.cache.Get(trimmed, &cached)
		if err == nil && hit {
			return &cached, nil
		}
	}

	var probeErrs []error
	for _, probe := range w.probes {
		probeCtx, cancel := context.WithTimeout(ctx, w.probeTimeout)
		target, err := probe.Resolve(probeCtx, trimmed)
		cancel()

		if err == nil && target != nil {
			if w.cache != nil {
				if putErr := w.cache.Put(trimmed, target); putErr != nil {
					// Non-fatal cache write error; resolution succeeded.
				}
			}
			return target, nil
		}
		if err != nil {
			probeErrs = append(probeErrs, fmt.Errorf("probe %s: %w", probe.Name(), err))
		}
	}

	if len(probeErrs) > 0 {
		return nil, errors.Join(append([]error{ErrNotFound}, probeErrs...)...)
	}
	return nil, ErrNotFound
}
