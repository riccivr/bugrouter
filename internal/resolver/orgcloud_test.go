package resolver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOrgCloudProbeMatching(t *testing.T) {
	reg := &OrgCloudRegistry{
		Services: []ServiceEntry{
			{
				Name:          "payments-service",
				Aliases:       []string{"billing", "checkout-api"},
				RepositoryURL: "https://git.internal.corp/fintech/payments",
				Tracker: TrackerInfo{
					Protocol: ProtocolGitLab,
					URL:      "https://git.internal.corp/fintech/payments/-/issues",
				},
			},
			{
				Name:          "auth-gateway",
				Aliases:       []string{"idp", "sso"},
				RepositoryURL: "https://github.enterprise.corp/security/auth-gw",
				Tracker: TrackerInfo{
					Protocol: ProtocolGitHub,
					URL:      "https://github.enterprise.corp/security/auth-gw/issues",
				},
			},
		},
	}

	probe := NewOrgCloudProbeWithRegistry(reg)
	if probe.Name() != "org-cloud" {
		t.Errorf("Name = %q, want org-cloud", probe.Name())
	}
	if probe.Layer() != LayerOrgCloud {
		t.Errorf("Layer = %v, want %v", probe.Layer(), LayerOrgCloud)
	}

	// 1. Exact match on Name (case-insensitive)
	target, err := probe.Resolve(context.Background(), "PAYMENTS-SERVICE")
	if err != nil {
		t.Fatalf("Resolve payments-service failed: %v", err)
	}
	if target.CanonicalName != "payments-service" {
		t.Errorf("CanonicalName = %q, want payments-service", target.CanonicalName)
	}
	if target.Layer != LayerOrgCloud {
		t.Errorf("Layer = %v, want %v", target.Layer, LayerOrgCloud)
	}
	if target.Tracker.Protocol != ProtocolGitLab {
		t.Errorf("Protocol = %v, want %v", target.Tracker.Protocol, ProtocolGitLab)
	}

	// 2. Match on Alias
	target2, err := probe.Resolve(context.Background(), "checkout-api")
	if err != nil {
		t.Fatalf("Resolve alias checkout-api failed: %v", err)
	}
	if target2.CanonicalName != "payments-service" {
		t.Errorf("CanonicalName = %q, want payments-service", target2.CanonicalName)
	}

	target3, err := probe.Resolve(context.Background(), "IDP")
	if err != nil {
		t.Fatalf("Resolve alias IDP failed: %v", err)
	}
	if target3.CanonicalName != "auth-gateway" {
		t.Errorf("CanonicalName = %q, want auth-gateway", target3.CanonicalName)
	}

	// 3. Unknown query returns ErrNotFound
	_, err = probe.Resolve(context.Background(), "unknown-service")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for unknown service, got: %v", err)
	}

	// 4. Empty query returns ErrNotFound
	_, err = probe.Resolve(context.Background(), "   ")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for empty query, got: %v", err)
	}
}

func TestOrgCloudProbeFileResolution(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "services.json")

	content := `{
		"services": [
			{
				"name": "search-engine",
				"aliases": ["indexer"],
				"repository_url": "https://git.internal.corp/infra/search",
				"tracker": {
					"protocol": "gitlab",
					"url": "https://git.internal.corp/infra/search/-/issues"
				}
			}
		]
	}`

	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	probe := NewOrgCloudProbe(cfgPath)
	target, err := probe.Resolve(context.Background(), "indexer")
	if err != nil {
		t.Fatalf("Resolve indexer failed: %v", err)
	}
	if target.CanonicalName != "search-engine" {
		t.Errorf("CanonicalName = %q, want search-engine", target.CanonicalName)
	}

	// Test missing file fallthrough
	missingProbe := NewOrgCloudProbe(filepath.Join(tempDir, "nonexistent.json"))
	_, err = missingProbe.Resolve(context.Background(), "search-engine")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound on missing file, got: %v", err)
	}

	// Test BUGROUTER_SERVICES_FILE env var
	t.Setenv("BUGROUTER_SERVICES_FILE", cfgPath)
	envProbe := NewOrgCloudProbe()
	envTarget, err := envProbe.Resolve(context.Background(), "search-engine")
	if err != nil {
		t.Fatalf("Resolve via env failed: %v", err)
	}
	if envTarget.CanonicalName != "search-engine" {
		t.Errorf("CanonicalName = %q, want search-engine", envTarget.CanonicalName)
	}
}
