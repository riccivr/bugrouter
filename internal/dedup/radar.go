package dedup

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/scrubber"
)

// StackRadarEntry combines a discovered dependency with potential open upstream bugs.
type StackRadarEntry struct {
	Dependency   resolver.StackDependency `json:"dependency"`
	UpstreamBugs []ExistingIssue          `json:"upstream_bugs,omitempty"`
}

// StackRadarReport encapsulates the full workspace dependency inventory and downstream radar.
type StackRadarReport struct {
	RootDir   string            `json:"root_dir"`
	ScannedAt time.Time         `json:"scanned_at"`
	Total     int               `json:"total"`
	Resolved  int               `json:"resolved"`
	Entries   []StackRadarEntry `json:"entries"`
}

// BuildStackRadar scans workspace manifests via Waterfall and optionally queries
// upstream trackers for open bugs affecting the discovered dependencies.
func BuildStackRadar(ctx context.Context, wf *resolver.Waterfall, finder *Finder, rootDir string, checkUpstream bool) (*StackRadarReport, error) {
	if wf == nil {
		return nil, fmt.Errorf("waterfall resolver cannot be nil")
	}

	inv, err := wf.ScanStack(ctx, rootDir)
	if err != nil {
		return nil, fmt.Errorf("scan stack: %w", err)
	}

	entries := make([]StackRadarEntry, len(inv.Dependencies))
	for i, dep := range inv.Dependencies {
		entries[i] = StackRadarEntry{
			Dependency: dep,
		}
	}

	if checkUpstream && finder != nil {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 5)

		for i := range entries {
			dep := entries[i].Dependency
			if dep.Target == nil {
				continue
			}

			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				queryStr := dep.Name
				if dep.Target.CanonicalName != "" {
					queryStr = dep.Target.CanonicalName
				}
				if dep.Version != "" {
					queryStr += " " + dep.Version
				}
				queryStr += " bug crash regression"

				bugs, findErr := finder.FindDuplicates(ctx, *dep.Target, scrubber.Scrub(queryStr))
				if findErr == nil && len(bugs) > 0 {
					entries[idx].UpstreamBugs = bugs
				}
			}(i)
		}
		wg.Wait()
	}

	if entries == nil {
		entries = []StackRadarEntry{}
	}

	return &StackRadarReport{
		RootDir:   inv.RootDir,
		ScannedAt: inv.ScannedAt,
		Total:     inv.Total,
		Resolved:  inv.Resolved,
		Entries:   entries,
	}, nil
}
