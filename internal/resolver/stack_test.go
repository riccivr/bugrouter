package resolver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParsePEP508(t *testing.T) {
	cases := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{"requests>=2.31.0", "requests", ">=2.31.0"},
		{"urllib3 (>= 1.26.0)", "urllib3", ">= 1.26.0"},
		{"fastapi[all]>=0.100.0", "fastapi", ">=0.100.0"},
		{"pydantic==2.5.0; extra == 'testing'", "pydantic", "==2.5.0"},
		{"pytest", "pytest", ""},
		{"flake8; python_version < '3.8'", "flake8", ""},
	}

	for _, tc := range cases {
		name, ver := parsePEP508(tc.input)
		if name != tc.wantName {
			t.Errorf("parsePEP508(%q) name = %q, want %q", tc.input, name, tc.wantName)
		}
		if ver != tc.wantVersion {
			t.Errorf("parsePEP508(%q) version = %q, want %q", tc.input, ver, tc.wantVersion)
		}
	}
}

func TestScanWorkspaceManifests(t *testing.T) {
	tempDir := t.TempDir()

	// 1. services.json
	servicesContent := `{
		"services": [
			{
				"name": "internal-billing-api",
				"repository_url": "https://github.corp/fintech/billing",
				"tracker": {
					"protocol": "github",
					"url": "https://github.corp/fintech/billing/issues"
				}
			}
		]
	}`
	if err := os.WriteFile(filepath.Join(tempDir, "services.json"), []byte(servicesContent), 0600); err != nil {
		t.Fatalf("write services.json: %v", err)
	}

	// 2. go.mod
	goModContent := `module github.com/example/app

go 1.22

require github.com/example/direct v1.0.0

require (
	github.com/example/blockpkg v2.1.0 // indirect
	github.com/example/other v0.9.0
)
`
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte(goModContent), 0600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	// 3. package.json
	packageJsonContent := `{
		"name": "my-node-app",
		"dependencies": {
			"express": "^4.19.2"
		},
		"devDependencies": {
			"typescript": "~5.4.0"
		}
	}`
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(packageJsonContent), 0600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	// 4. Cargo.toml
	cargoContent := `[package]
name = "my-rust-crate"
version = "0.1.0"

[dependencies]
serde = "1.0.197"
tokio = { version = "1.36.0", features = ["full"] }

[dependencies.rand]
version = "0.8.5"
`
	if err := os.WriteFile(filepath.Join(tempDir, "Cargo.toml"), []byte(cargoContent), 0600); err != nil {
		t.Fatalf("write Cargo.toml: %v", err)
	}

	// 5. pyproject.toml
	pyprojectContent := `[project]
name = "my-py-pkg"
dependencies = [
    "requests>=2.31.0",
    "fastapi[all]>=0.110.0",
]

[tool.poetry.dependencies]
python = "^3.11"
pydantic = "^2.6.4"
`
	if err := os.WriteFile(filepath.Join(tempDir, "pyproject.toml"), []byte(pyprojectContent), 0600); err != nil {
		t.Fatalf("write pyproject.toml: %v", err)
	}

	deps, err := ScanWorkspaceManifests(tempDir)
	if err != nil {
		t.Fatalf("ScanWorkspaceManifests failed: %v", err)
	}

	// Verify expected counts
	// cargo: rand, serde, tokio (3)
	// gomod: github.com/example/blockpkg, github.com/example/direct, github.com/example/other (3)
	// npm: express, typescript (2)
	// pypi: fastapi, pydantic, requests (3) - note python is excluded
	// service: internal-billing-api (1)
	// Total = 12
	if len(deps) != 12 {
		t.Fatalf("expected 12 dependencies, got %d: %+v", len(deps), deps)
	}

	// Verify sorting: cargo, gomod, npm, pypi, service
	expectedOrder := []struct {
		eco  string
		name string
	}{
		{"cargo", "rand"},
		{"cargo", "serde"},
		{"cargo", "tokio"},
		{"gomod", "github.com/example/blockpkg"},
		{"gomod", "github.com/example/direct"},
		{"gomod", "github.com/example/other"},
		{"npm", "express"},
		{"npm", "typescript"},
		{"pypi", "fastapi"},
		{"pypi", "pydantic"},
		{"pypi", "requests"},
		{"service", "internal-billing-api"},
	}

	for i, exp := range expectedOrder {
		if deps[i].Ecosystem != exp.eco || deps[i].Name != exp.name {
			t.Errorf("dep[%d] = %s:%s, want %s:%s", i, deps[i].Ecosystem, deps[i].Name, exp.eco, exp.name)
		}
	}
}

func TestWaterfallScanStack(t *testing.T) {
	tempDir := t.TempDir()

	packageJsonContent := `{
		"dependencies": {
			"https://github.com/expressjs/express": "4.19.2"
		}
	}`
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(packageJsonContent), 0600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	wf := NewWaterfall(time.Second, NewDirectProbe())
	inv, err := wf.ScanStack(context.Background(), tempDir)
	if err != nil {
		t.Fatalf("wf.ScanStack failed: %v", err)
	}

	if inv.Total != 1 {
		t.Errorf("inv.Total = %d, want 1", inv.Total)
	}
	if inv.Resolved != 1 {
		t.Errorf("inv.Resolved = %d, want 1", inv.Resolved)
	}
	if len(inv.Dependencies) != 1 {
		t.Fatalf("len(inv.Dependencies) = %d, want 1", len(inv.Dependencies))
	}

	dep := inv.Dependencies[0]
	if dep.Target == nil {
		t.Fatalf("expected Target to be resolved for express")
	}
	if dep.Target.CanonicalName != "express" {
		t.Errorf("canonical name = %s, want express", dep.Target.CanonicalName)
	}
	if dep.Target.LocalVersion != "4.19.2" {
		t.Errorf("target local version = %s, want 4.19.2", dep.Target.LocalVersion)
	}
}
