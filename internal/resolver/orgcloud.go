package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ServiceEntry defines an internal service or repository ownership record.
type ServiceEntry struct {
	Name          string      `json:"name"`
	Aliases       []string    `json:"aliases,omitempty"`
	RepositoryURL string      `json:"repository_url"`
	Tracker       TrackerInfo `json:"tracker"`
}

// OrgCloudRegistry holds enterprise service mappings loaded from disk or environment.
type OrgCloudRegistry struct {
	Services []ServiceEntry `json:"services"`
}

// OrgCloudProbe inspects enterprise service catalogs to resolve private internal trackers.
type OrgCloudProbe struct {
	configPath string
	registry   *OrgCloudRegistry
}

// ResolveOrgCloudConfigPath discovers the canonical file path for enterprise services.json.
func ResolveOrgCloudConfigPath() string {
	return resolveOrgCloudConfigPath()
}

func resolveOrgCloudConfigPath() string {
	if env := os.Getenv("BUGROUTER_SERVICES_FILE"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		p := filepath.Join(xdg, "bugrouter", "services.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	} else if home, err := os.UserHomeDir(); err == nil && home != "" {
		p := filepath.Join(home, ".config", "bugrouter", "services.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if _, err := os.Stat("/etc/bugrouter/services.json"); err == nil {
		return "/etc/bugrouter/services.json"
	}
	if env := os.Getenv("BUGROUTER_SERVICES_FILE"); env != "" {
		return env
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "bugrouter", "services.json")
	} else if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".config", "bugrouter", "services.json")
	}
	return "/etc/bugrouter/services.json"
}

// NewOrgCloudProbe initializes an org-cloud probe with an optional configuration path override.
func NewOrgCloudProbe(path ...string) *OrgCloudProbe {
	cfgPath := ""
	if len(path) > 0 && path[0] != "" {
		cfgPath = path[0]
	} else {
		cfgPath = resolveOrgCloudConfigPath()
	}
	return &OrgCloudProbe{
		configPath: cfgPath,
	}
}

// NewOrgCloudProbeWithRegistry initializes an org-cloud probe with an in-memory registry.
func NewOrgCloudProbeWithRegistry(reg *OrgCloudRegistry) *OrgCloudProbe {
	return &OrgCloudProbe{
		registry: reg,
	}
}

// Name returns the identifier for this resolution probe.
func (p *OrgCloudProbe) Name() string {
	return "org-cloud"
}

// Layer returns the resolution layer for org-cloud discovery.
func (p *OrgCloudProbe) Layer() SourceLayer {
	return LayerOrgCloud
}

func (p *OrgCloudProbe) loadRegistry() (*OrgCloudRegistry, error) {
	if p.registry != nil {
		return p.registry, nil
	}
	if p.configPath == "" {
		return nil, ErrNotFound
	}
	data, err := os.ReadFile(p.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("read org cloud services config %s: %w", p.configPath, err)
	}
	var reg OrgCloudRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("unmarshal org cloud services config %s: %w", p.configPath, err)
	}
	return &reg, nil
}

// Resolve searches the enterprise registry for matches by name or aliases.
func (p *OrgCloudProbe) Resolve(ctx context.Context, query string) (*Target, error) {
	trimmed := strings.ToLower(strings.TrimSpace(query))
	if trimmed == "" {
		return nil, ErrNotFound
	}

	reg, err := p.loadRegistry()
	if err != nil {
		return nil, err
	}
	if reg == nil || len(reg.Services) == 0 {
		return nil, ErrNotFound
	}

	for _, svc := range reg.Services {
		if strings.ToLower(strings.TrimSpace(svc.Name)) == trimmed {
			return buildOrgCloudTarget(query, svc), nil
		}
		for _, alias := range svc.Aliases {
			if strings.ToLower(strings.TrimSpace(alias)) == trimmed {
				return buildOrgCloudTarget(query, svc), nil
			}
		}
	}

	return nil, ErrNotFound
}

func buildOrgCloudTarget(query string, svc ServiceEntry) *Target {
	tracker := svc.Tracker
	repoURL := svc.RepositoryURL
	if tracker.Protocol == "" || (tracker.URL == "" && tracker.Email == "") {
		derivedTracker, normRepo := ClassifyTracker(tracker.URL, tracker.Email, repoURL)
		if tracker.Protocol == "" {
			tracker.Protocol = derivedTracker.Protocol
		}
		if tracker.URL == "" {
			tracker.URL = derivedTracker.URL
		}
		if tracker.Email == "" {
			tracker.Email = derivedTracker.Email
		}
		if normRepo != "" {
			repoURL = normRepo
		}
	}
	return &Target{
		Query:         query,
		CanonicalName: svc.Name,
		Layer:         LayerOrgCloud,
		RepositoryURL: repoURL,
		Tracker:       tracker,
	}
}
