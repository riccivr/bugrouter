package resolver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceProbeNodeModules(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Unscoped package with string bugs and repository
	pkg1Dir := filepath.Join(tempDir, "node_modules", "remix")
	if err := os.MkdirAll(pkg1Dir, 0755); err != nil {
		t.Fatalf("mkdir remix: %v", err)
	}
	pkg1JSON := `{
		"name": "remix",
		"version": "2.8.1",
		"bugs": "https://github.com/remix-run/remix/issues",
		"repository": "https://github.com/remix-run/remix.git"
	}`
	if err := os.WriteFile(filepath.Join(pkg1Dir, "package.json"), []byte(pkg1JSON), 0644); err != nil {
		t.Fatalf("write remix package.json: %v", err)
	}

	// 2. Unscoped package with object bugs and repository
	pkg2Dir := filepath.Join(tempDir, "node_modules", "sharp")
	if err := os.MkdirAll(pkg2Dir, 0755); err != nil {
		t.Fatalf("mkdir sharp: %v", err)
	}
	pkg2JSON := `{
		"name": "sharp",
		"version": "0.33.2",
		"bugs": {
			"url": "https://github.com/lovell/sharp/issues",
			"email": "bugs@sharp.pixel"
		},
		"repository": {
			"type": "git",
			"url": "git+https://github.com/lovell/sharp.git"
		}
	}`
	if err := os.WriteFile(filepath.Join(pkg2Dir, "package.json"), []byte(pkg2JSON), 0644); err != nil {
		t.Fatalf("write sharp package.json: %v", err)
	}

	// 3. Scoped package
	pkg3Dir := filepath.Join(tempDir, "node_modules", "@remix-run", "node")
	if err := os.MkdirAll(pkg3Dir, 0755); err != nil {
		t.Fatalf("mkdir scoped package: %v", err)
	}
	pkg3JSON := `{
		"name": "@remix-run/node",
		"version": "2.8.1",
		"bugs": "https://github.com/remix-run/remix/issues",
		"repository": "https://github.com/remix-run/remix"
	}`
	if err := os.WriteFile(filepath.Join(pkg3Dir, "package.json"), []byte(pkg3JSON), 0644); err != nil {
		t.Fatalf("write scoped package.json: %v", err)
	}

	probe := NewWorkspaceProbe(tempDir)

	// Test remix
	t1, err := probe.Resolve(context.Background(), "remix")
	if err != nil {
		t.Fatalf("resolve remix: %v", err)
	}
	if t1.CanonicalName != "remix" {
		t.Errorf("CanonicalName = %q, want remix", t1.CanonicalName)
	}
	if t1.LocalVersion != "2.8.1" {
		t.Errorf("LocalVersion = %q, want 2.8.1", t1.LocalVersion)
	}
	if t1.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", t1.Tracker.Protocol)
	}

	// Test sharp
	t2, err := probe.Resolve(context.Background(), "sharp")
	if err != nil {
		t.Fatalf("resolve sharp: %v", err)
	}
	if t2.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", t2.Tracker.Protocol)
	}
	if t2.Tracker.Email != "bugs@sharp.pixel" {
		t.Errorf("Email = %q, want bugs@sharp.pixel", t2.Tracker.Email)
	}

	// Test scoped package
	t3, err := probe.Resolve(context.Background(), "@remix-run/node")
	if err != nil {
		t.Fatalf("resolve @remix-run/node: %v", err)
	}
	if t3.CanonicalName != "@remix-run/node" {
		t.Errorf("CanonicalName = %q, want @remix-run/node", t3.CanonicalName)
	}
}

func TestWorkspaceProbeGoMod(t *testing.T) {
	tempDir := t.TempDir()

	goModContent := `module testworkspace

go 1.22

require (
	github.com/BurntSushi/ripgrep v1.4.1
	gitlab.com/gnachman/iterm2 v0.1.0 // indirect
)

replace (
	github.com/replaced/module v1.0.0 => github.com/fork/module v1.0.1
)

exclude (
	github.com/excluded/module v1.0.0
)
`
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	probe := NewWorkspaceProbe(tempDir)

	// Resolve ripgrep
	t1, err := probe.Resolve(context.Background(), "ripgrep")
	if err != nil {
		t.Fatalf("resolve ripgrep: %v", err)
	}
	if t1.LocalVersion != "v1.4.1" {
		t.Errorf("LocalVersion = %q, want v1.4.1", t1.LocalVersion)
	}
	if t1.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", t1.Tracker.Protocol)
	}
	if t1.Tracker.URL != "https://github.com/BurntSushi/ripgrep/issues" {
		t.Errorf("Tracker URL = %q, want https://github.com/BurntSushi/ripgrep/issues", t1.Tracker.URL)
	}

	// Resolve iterm2
	t2, err := probe.Resolve(context.Background(), "iterm2")
	if err != nil {
		t.Fatalf("resolve iterm2: %v", err)
	}
	if t2.Tracker.Protocol != ProtocolGitLab {
		t.Errorf("Protocol = %q, want gitlab", t2.Tracker.Protocol)
	}

	// Replaced and excluded modules must not be resolved
	for _, query := range []string{"module", "replaced", "excluded"} {
		_, err := probe.Resolve(context.Background(), query)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("expected ErrNotFound for %q, got: %v", query, err)
		}
	}
}

func TestWorkspaceProbeSecurityAndNotFound(t *testing.T) {
	tempDir := t.TempDir()
	probe := NewWorkspaceProbe(tempDir)

	// Path traversal attempts and invalid package names
	for _, bad := range []string{"../etc", "/bin/sh", "\\windows\\system32", "a/../../b", ".", "@scope/a/b"} {
		_, err := probe.Resolve(context.Background(), bad)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("expected ErrNotFound for %q, got: %v", bad, err)
		}
	}

	// Missing dependency
	_, err := probe.Resolve(context.Background(), "nonexistent-pkg")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for nonexistent-pkg, got: %v", err)
	}
}

func TestWorkspaceProbeCargoToml(t *testing.T) {
	tempDir := t.TempDir()

	cargoTomlContent := `[package]
name = "my-rust-app"
version = "0.5.0"
edition = "2021"
repository = "https://github.com/my-org/my-rust-app"

[dependencies]
tokio = { version = "1.38", git = "https://github.com/tokio-rs/tokio" }
complex-dep = { rustc-version = "1.70", version = "1.38", git = "https://github.com/rust-lang/complex-dep.git" }
regular-crate = "0.1"

[dependencies.serde]
version = "1.0"
git = "https://github.com/serde-rs/serde"
`
	if err := os.WriteFile(filepath.Join(tempDir, "Cargo.toml"), []byte(cargoTomlContent), 0644); err != nil {
		t.Fatalf("write Cargo.toml: %v", err)
	}

	cargoLockContent := `version = 3

[[package]]
name = "my-rust-app"
version = "0.5.0"
dependencies = [
 "tokio",
 "locked-crate",
]

[[package]]
name = "locked-crate"
version = "2.1.0"
source = "git+https://github.com/custom/locked-crate.git#abcdef123456"
`
	if err := os.WriteFile(filepath.Join(tempDir, "Cargo.lock"), []byte(cargoLockContent), 0644); err != nil {
		t.Fatalf("write Cargo.lock: %v", err)
	}

	probe := NewWorkspaceProbe(tempDir)

	// 1. Resolve local package
	t1, err := probe.Resolve(context.Background(), "my-rust-app")
	if err != nil {
		t.Fatalf("resolve my-rust-app: %v", err)
	}
	if t1.CanonicalName != "my-rust-app" {
		t.Errorf("CanonicalName = %q, want my-rust-app", t1.CanonicalName)
	}
	if t1.LocalVersion != "0.5.0" {
		t.Errorf("LocalVersion = %q, want 0.5.0", t1.LocalVersion)
	}
	if t1.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", t1.Tracker.Protocol)
	}

	// 2. Resolve dependency with inline table git
	t2, err := probe.Resolve(context.Background(), "tokio")
	if err != nil {
		t.Fatalf("resolve tokio: %v", err)
	}
	if t2.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", t2.Tracker.Protocol)
	}
	if t2.RepositoryURL != "https://github.com/tokio-rs/tokio" {
		t.Errorf("RepositoryURL = %q, want https://github.com/tokio-rs/tokio", t2.RepositoryURL)
	}

	// 2b. Resolve dependency with rustc-version before version (RT-07.1)
	t2b, err := probe.Resolve(context.Background(), "complex-dep")
	if err != nil {
		t.Fatalf("resolve complex-dep: %v", err)
	}
	if t2b.LocalVersion != "1.38" {
		t.Errorf("complex-dep LocalVersion = %q, want 1.38", t2b.LocalVersion)
	}
	if t2b.RepositoryURL != "https://github.com/rust-lang/complex-dep" {
		t.Errorf("complex-dep RepositoryURL = %q, want https://github.com/rust-lang/complex-dep", t2b.RepositoryURL)
	}

	// 3. Resolve dependency with section header
	t3, err := probe.Resolve(context.Background(), "serde")
	if err != nil {
		t.Fatalf("resolve serde: %v", err)
	}
	if t3.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", t3.Tracker.Protocol)
	}

	// 4. Resolve dependency with git URL in Cargo.lock
	t4, err := probe.Resolve(context.Background(), "locked-crate")
	if err != nil {
		t.Fatalf("resolve locked-crate: %v", err)
	}
	if t4.LocalVersion != "2.1.0" {
		t.Errorf("LocalVersion = %q, want 2.1.0", t4.LocalVersion)
	}
	if t4.RepositoryURL != "https://github.com/custom/locked-crate" {
		t.Errorf("RepositoryURL = %q, want https://github.com/custom/locked-crate", t4.RepositoryURL)
	}

	// 5. Regular crate without git falls through with ErrNotFound
	_, err = probe.Resolve(context.Background(), "regular-crate")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for regular-crate, got: %v", err)
	}
}

func TestWorkspaceProbePyprojectToml(t *testing.T) {
	tempDir := t.TempDir()

	pyprojectContent := `[project]
name = "my-python-tool"
version = "1.2.3"
dependencies = ["requests[security] @ git+https://github.com/psf/requests.git#v2.31.0",
    "click>=8.0",
]

[project.urls]
Homepage = "https://example.com"
Repository = "https://github.com/my-org/my-python-tool"
"Bug Tracker" = "https://github.com/my-org/my-python-tool/issues"

[tool.poetry.dependencies]
urllib3 = { git = "https://github.com/urllib3/urllib3.git" }
`
	if err := os.WriteFile(filepath.Join(tempDir, "pyproject.toml"), []byte(pyprojectContent), 0644); err != nil {
		t.Fatalf("write pyproject.toml: %v", err)
	}

	probe := NewWorkspaceProbe(tempDir)

	// 1. Resolve local project via [project.urls] (with PEP 503 normalization: query with underscore)
	t1, err := probe.Resolve(context.Background(), "my_python_tool")
	if err != nil {
		t.Fatalf("resolve my_python_tool: %v", err)
	}
	if t1.CanonicalName != "my_python_tool" {
		t.Errorf("CanonicalName = %q, want my_python_tool", t1.CanonicalName)
	}
	if t1.LocalVersion != "1.2.3" {
		t.Errorf("LocalVersion = %q, want 1.2.3", t1.LocalVersion)
	}
	if t1.Tracker.URL != "https://github.com/my-org/my-python-tool/issues" {
		t.Errorf("Tracker URL = %q, want issues url", t1.Tracker.URL)
	}

	// 1b. Resolve with original hyphenated name
	t1b, err := probe.Resolve(context.Background(), "my-python-tool")
	if err != nil {
		t.Fatalf("resolve my-python-tool: %v", err)
	}
	if t1b.CanonicalName != "my-python-tool" {
		t.Errorf("CanonicalName = %q, want my-python-tool", t1b.CanonicalName)
	}

	// 2. Resolve PEP 508 git dependency with extras on opening array line
	t2, err := probe.Resolve(context.Background(), "requests")
	if err != nil {
		t.Fatalf("resolve requests: %v", err)
	}
	if t2.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", t2.Tracker.Protocol)
	}
	if t2.RepositoryURL != "https://github.com/psf/requests" {
		t.Errorf("RepositoryURL = %q, want https://github.com/psf/requests", t2.RepositoryURL)
	}

	// 3. Resolve Poetry git dependency
	t3, err := probe.Resolve(context.Background(), "urllib3")
	if err != nil {
		t.Fatalf("resolve urllib3: %v", err)
	}
	if t3.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Protocol = %q, want github", t3.Tracker.Protocol)
	}

	// 4. Regular dependency without git returns ErrNotFound
	_, err = probe.Resolve(context.Background(), "click")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for click, got: %v", err)
	}
}

func TestExtractInlineTableFieldExactMatch(t *testing.T) {
	table := `{ rustc-version = "1.70", version = "1.38", git = "https://github.com/rust-lang/example.git" }`
	if got := extractInlineTableField(table, "version"); got != "1.38" {
		t.Errorf("extractInlineTableField version = %q, want 1.38", got)
	}
	if got := extractInlineTableField(table, "rustc-version"); got != "1.70" {
		t.Errorf("extractInlineTableField rustc-version = %q, want 1.70", got)
	}
	if got := extractInlineTableField(table, "git"); got != "https://github.com/rust-lang/example.git" {
		t.Errorf("extractInlineTableField git = %q, want git url", got)
	}
	if got := extractInlineTableField(table, "nonexistent"); got != "" {
		t.Errorf("extractInlineTableField nonexistent = %q, want empty", got)
	}
}

func TestNormalizePyPkgName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"requests[security]", "requests"},
		{"pkg[extra1,extra2]", "pkg"},
		{"my-python-tool", "my_python_tool"},
		{"my_python_tool", "my_python_tool"},
		{"my.python.tool", "my_python_tool"},
		{"  Requests[ALL]  ", "requests"},
	}
	for _, tc := range cases {
		if got := normalizePyPkgName(tc.input); got != tc.want {
			t.Errorf("normalizePyPkgName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestWorkspaceProbePomXML(t *testing.T) {
	tempDir := t.TempDir()

	pomContent := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
	<modelVersion>4.0.0</modelVersion>
	<groupId>org.apache.commons</groupId>
	<artifactId>commons-lang3</artifactId>
	<version>3.12.0</version>
	<url>https://commons.apache.org/proper/commons-lang/</url>
	<scm>
		<url>https://github.com/apache/commons-lang</url>
		<connection>scm:git:https://github.com/apache/commons-lang.git</connection>
	</scm>
	<issueManagement>
		<system>jira</system>
		<url>https://issues.apache.org/jira/browse/LANG</url>
	</issueManagement>
	<dependencies>
		<dependency>
			<groupId>com.github.luben</groupId>
			<artifactId>zstd-jni</artifactId>
			<version>1.5.5-1</version>
		</dependency>
		<dependency>
			<groupId>org.slf4j</groupId>
			<artifactId>slf4j-api</artifactId>
			<version>2.0.9</version>
			<scm>
				<url>https://github.com/qos-ch/slf4j</url>
			</scm>
		</dependency>
		<dependency>
			<groupId>com.google.guava</groupId>
			<artifactId>guava</artifactId>
			<version>32.0.0-jre</version>
		</dependency>
	</dependencies>
</project>`

	if err := os.WriteFile(filepath.Join(tempDir, "pom.xml"), []byte(pomContent), 0644); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}

	probe := NewWorkspaceProbe(tempDir)

	// 1. Resolve root project by artifactId
	t1, err := probe.Resolve(context.Background(), "commons-lang3")
	if err != nil {
		t.Fatalf("resolve commons-lang3: %v", err)
	}
	if t1.CanonicalName != "commons-lang3" {
		t.Errorf("CanonicalName = %q, want commons-lang3", t1.CanonicalName)
	}
	if t1.LocalVersion != "3.12.0" {
		t.Errorf("LocalVersion = %q, want 3.12.0", t1.LocalVersion)
	}
	if t1.Tracker.URL != "https://issues.apache.org/jira/browse/LANG" {
		t.Errorf("Tracker URL = %q, want jira url", t1.Tracker.URL)
	}
	if t1.Tracker.Protocol != ProtocolJira {
		t.Errorf("Tracker Protocol = %q, want jira", t1.Tracker.Protocol)
	}

	// 1b. Resolve root project by groupId:artifactId
	t1b, err := probe.Resolve(context.Background(), "org.apache.commons:commons-lang3")
	if err != nil {
		t.Fatalf("resolve org.apache.commons:commons-lang3: %v", err)
	}
	if t1b.CanonicalName != "commons-lang3" {
		t.Errorf("CanonicalName = %q, want commons-lang3", t1b.CanonicalName)
	}

	// 2. Resolve dependency with inferred github forge groupId
	t2, err := probe.Resolve(context.Background(), "zstd-jni")
	if err != nil {
		t.Fatalf("resolve zstd-jni: %v", err)
	}
	if t2.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Tracker Protocol = %q, want github", t2.Tracker.Protocol)
	}
	if t2.RepositoryURL != "https://github.com/luben/zstd-jni" {
		t.Errorf("RepositoryURL = %q, want https://github.com/luben/zstd-jni", t2.RepositoryURL)
	}

	// 3. Resolve dependency with explicit scm
	t3, err := probe.Resolve(context.Background(), "slf4j-api")
	if err != nil {
		t.Fatalf("resolve slf4j-api: %v", err)
	}
	if t3.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Tracker Protocol = %q, want github", t3.Tracker.Protocol)
	}
	if t3.RepositoryURL != "https://github.com/qos-ch/slf4j" {
		t.Errorf("RepositoryURL = %q, want https://github.com/qos-ch/slf4j", t3.RepositoryURL)
	}

	// 4. Dependency without repo URL or forge prefix falls through with ErrNotFound
	_, err = probe.Resolve(context.Background(), "guava")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for guava, got: %v", err)
	}
}

func TestWorkspaceProbeDotNet(t *testing.T) {
	tempDir := t.TempDir()

	csprojContent := `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <PackageId>MyCSharpApp</PackageId>
    <Version>1.0.0</Version>
    <RepositoryUrl>https://github.com/my-org/my-csharp-app</RepositoryUrl>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" RepositoryUrl="https://github.com/JamesNK/Newtonsoft.Json" />
    <PackageReference Include="Serilog">
      <Version>3.1.1</Version>
      <RepositoryUrl>https://github.com/serilog/serilog</RepositoryUrl>
    </PackageReference>
    <PackageReference Include="Dapper" Version="2.1.28" />
  </ItemGroup>
</Project>`

	if err := os.WriteFile(filepath.Join(tempDir, "MyCSharpApp.csproj"), []byte(csprojContent), 0644); err != nil {
		t.Fatalf("write MyCSharpApp.csproj: %v", err)
	}

	probe := NewWorkspaceProbe(tempDir)

	// 1. Resolve root app
	t1, err := probe.Resolve(context.Background(), "MyCSharpApp")
	if err != nil {
		t.Fatalf("resolve MyCSharpApp: %v", err)
	}
	if t1.CanonicalName != "MyCSharpApp" {
		t.Errorf("CanonicalName = %q, want MyCSharpApp", t1.CanonicalName)
	}
	if t1.LocalVersion != "1.0.0" {
		t.Errorf("LocalVersion = %q, want 1.0.0", t1.LocalVersion)
	}
	if t1.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Tracker Protocol = %q, want github", t1.Tracker.Protocol)
	}

	// 2. Resolve package reference with attribute repository url
	t2, err := probe.Resolve(context.Background(), "Newtonsoft.Json")
	if err != nil {
		t.Fatalf("resolve Newtonsoft.Json: %v", err)
	}
	if t2.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Tracker Protocol = %q, want github", t2.Tracker.Protocol)
	}
	if t2.RepositoryURL != "https://github.com/JamesNK/Newtonsoft.Json" {
		t.Errorf("RepositoryURL = %q, want https://github.com/JamesNK/Newtonsoft.Json", t2.RepositoryURL)
	}

	// 3. Resolve package reference with element version and repository url
	t3, err := probe.Resolve(context.Background(), "Serilog")
	if err != nil {
		t.Fatalf("resolve Serilog: %v", err)
	}
	if t3.LocalVersion != "3.1.1" {
		t.Errorf("LocalVersion = %q, want 3.1.1", t3.LocalVersion)
	}
	if t3.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Tracker Protocol = %q, want github", t3.Tracker.Protocol)
	}

	// 4. Resolve package reference without repository url (falls back to nuget.org)
	t4, err := probe.Resolve(context.Background(), "Dapper")
	if err != nil {
		t.Fatalf("resolve Dapper: %v", err)
	}
	if t4.LocalVersion != "2.1.28" {
		t.Errorf("LocalVersion = %q, want 2.1.28", t4.LocalVersion)
	}
	if t4.Tracker.Protocol != ProtocolWebURL {
		t.Errorf("Tracker Protocol = %q, want web-url", t4.Tracker.Protocol)
	}
	if t4.Tracker.URL != "https://www.nuget.org/packages/Dapper" {
		t.Errorf("Tracker URL = %q, want nuget url", t4.Tracker.URL)
	}
}

func TestWorkspaceProbeDotNetPackagesConfig(t *testing.T) {
	tempDir := t.TempDir()

	configContent := `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Autofac" version="6.5.0" repositoryUrl="https://github.com/autofac/Autofac" targetFramework="net48" />
  <package id="NUnit" version="3.13.3" targetFramework="net48" />
</packages>`

	if err := os.WriteFile(filepath.Join(tempDir, "packages.config"), []byte(configContent), 0644); err != nil {
		t.Fatalf("write packages.config: %v", err)
	}

	probe := NewWorkspaceProbe(tempDir)

	// 1. Resolve package with repositoryUrl
	t1, err := probe.Resolve(context.Background(), "Autofac")
	if err != nil {
		t.Fatalf("resolve Autofac: %v", err)
	}
	if t1.LocalVersion != "6.5.0" {
		t.Errorf("LocalVersion = %q, want 6.5.0", t1.LocalVersion)
	}
	if t1.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Tracker Protocol = %q, want github", t1.Tracker.Protocol)
	}

	// 2. Resolve package without repositoryUrl (fallback to nuget)
	t2, err := probe.Resolve(context.Background(), "NUnit")
	if err != nil {
		t.Fatalf("resolve NUnit: %v", err)
	}
	if t2.Tracker.Protocol != ProtocolWebURL {
		t.Errorf("Tracker Protocol = %q, want web-url", t2.Tracker.Protocol)
	}
}

func TestWorkspaceProbeRubyGemfileLock(t *testing.T) {
	tempDir := t.TempDir()

	lockContent := `GIT
  remote: https://github.com/rails/rails.git
  revision: 7b848c08ef8cf40aefea42456bc3d395a1a0937b
  branch: main
  specs:
    rails (7.2.0.alpha)
      actioncable (= 7.2.0.alpha)
      actionmailbox (= 7.2.0.alpha)

GIT
  remote: https://github.com/sparklemotion/nokogiri.git
  revision: abcdef123456
  specs:
    nokogiri (1.16.2)

GEM
  remote: https://rubygems.org/
  specs:
    puma (6.4.2)
      nio4r (~> 2.0)
    sidekiq (7.2.2)

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri!
  puma (~> 6.4)
  rails!
  sidekiq

BUNDLED WITH
   2.5.6`

	if err := os.WriteFile(filepath.Join(tempDir, "Gemfile.lock"), []byte(lockContent), 0644); err != nil {
		t.Fatalf("write Gemfile.lock: %v", err)
	}

	gemfileContent := `source "https://rubygems.org"
gem "sidekiq", github: "sidekiq/sidekiq"`

	if err := os.WriteFile(filepath.Join(tempDir, "Gemfile"), []byte(gemfileContent), 0644); err != nil {
		t.Fatalf("write Gemfile: %v", err)
	}

	probe := NewWorkspaceProbe(tempDir)

	// 1. Resolve git locked gem (rails)
	t1, err := probe.Resolve(context.Background(), "rails")
	if err != nil {
		t.Fatalf("resolve rails: %v", err)
	}
	if t1.CanonicalName != "rails" {
		t.Errorf("CanonicalName = %q, want rails", t1.CanonicalName)
	}
	if t1.LocalVersion != "7.2.0.alpha" {
		t.Errorf("LocalVersion = %q, want 7.2.0.alpha", t1.LocalVersion)
	}
	if t1.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Tracker Protocol = %q, want github", t1.Tracker.Protocol)
	}
	if t1.RepositoryURL != "https://github.com/rails/rails" {
		t.Errorf("RepositoryURL = %q, want https://github.com/rails/rails", t1.RepositoryURL)
	}

	// 2. Resolve git locked gem (nokogiri)
	t2, err := probe.Resolve(context.Background(), "nokogiri")
	if err != nil {
		t.Fatalf("resolve nokogiri: %v", err)
	}
	if t2.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Tracker Protocol = %q, want github", t2.Tracker.Protocol)
	}

	// 3. Resolve gem section entry with github in Gemfile (sidekiq)
	t3, err := probe.Resolve(context.Background(), "sidekiq")
	if err != nil {
		t.Fatalf("resolve sidekiq: %v", err)
	}
	if t3.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Tracker Protocol = %q, want github", t3.Tracker.Protocol)
	}
	if t3.RepositoryURL != "https://github.com/sidekiq/sidekiq" {
		t.Errorf("RepositoryURL = %q, want https://github.com/sidekiq/sidekiq", t3.RepositoryURL)
	}

	// 4. Resolve gem section entry without git in Gemfile (puma -> rubygems.org)
	t4, err := probe.Resolve(context.Background(), "puma")
	if err != nil {
		t.Fatalf("resolve puma: %v", err)
	}
	if t4.LocalVersion != "6.4.2" {
		t.Errorf("LocalVersion = %q, want 6.4.2", t4.LocalVersion)
	}
	if t4.Tracker.Protocol != ProtocolWebURL {
		t.Errorf("Tracker Protocol = %q, want web-url", t4.Tracker.Protocol)
	}
	if t4.Tracker.URL != "https://rubygems.org/gems/puma" {
		t.Errorf("Tracker URL = %q, want rubygems url", t4.Tracker.URL)
	}
}

func TestWorkspaceProbeComposerLockAndJSON(t *testing.T) {
	tempDir := t.TempDir()

	composerLockContent := `{
  "packages": [
    {
      "name": "monolog/monolog",
      "version": "3.5.0",
      "source": {
        "type": "git",
        "url": "https://github.com/Seldaek/monolog.git",
        "reference": "abcdef"
      },
      "homepage": "https://seld.be",
      "support": {
        "issues": "https://github.com/Seldaek/monolog/issues",
        "source": "https://github.com/Seldaek/monolog"
      }
    },
    {
      "name": "guzzlehttp/guzzle",
      "version": "7.8.1",
      "source": {
        "type": "git",
        "url": "https://github.com/guzzle/guzzle.git",
        "reference": "123456"
      },
      "homepage": "https://guzzlephp.org",
      "support": {
        "issues": "https://github.com/guzzle/guzzle/issues",
        "source": "https://github.com/guzzle/guzzle"
      }
    }
  ],
  "packages-dev": [
    {
      "name": "phpunit/phpunit",
      "version": "10.5.9",
      "source": {
        "type": "git",
        "url": "https://github.com/sebastianbergmann/phpunit.git",
        "reference": "789012"
      },
      "support": {
        "issues": "https://github.com/sebastianbergmann/phpunit/issues"
      }
    }
  ]
}`

	if err := os.WriteFile(filepath.Join(tempDir, "composer.lock"), []byte(composerLockContent), 0644); err != nil {
		t.Fatalf("write composer.lock: %v", err)
	}

	composerJSONContent := `{
  "name": "my-org/my-php-app",
  "version": "1.0.0",
  "homepage": "https://example.com/app",
  "support": {
    "issues": "https://github.com/my-org/my-php-app/issues",
    "source": "https://github.com/my-org/my-php-app"
  }
}`

	if err := os.WriteFile(filepath.Join(tempDir, "composer.json"), []byte(composerJSONContent), 0644); err != nil {
		t.Fatalf("write composer.json: %v", err)
	}

	probe := NewWorkspaceProbe(tempDir)

	// 1. Resolve full name monolog/monolog
	t1, err := probe.Resolve(context.Background(), "monolog/monolog")
	if err != nil {
		t.Fatalf("resolve monolog/monolog: %v", err)
	}
	if t1.CanonicalName != "monolog/monolog" {
		t.Errorf("CanonicalName = %q, want monolog/monolog", t1.CanonicalName)
	}
	if t1.LocalVersion != "3.5.0" {
		t.Errorf("LocalVersion = %q, want 3.5.0", t1.LocalVersion)
	}
	if t1.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Tracker Protocol = %q, want github", t1.Tracker.Protocol)
	}
	if t1.Tracker.URL != "https://github.com/Seldaek/monolog/issues" {
		t.Errorf("Tracker URL = %q, want https://github.com/Seldaek/monolog/issues", t1.Tracker.URL)
	}

	// 1b. Resolve short name monolog
	t1b, err := probe.Resolve(context.Background(), "monolog")
	if err != nil {
		t.Fatalf("resolve monolog: %v", err)
	}
	if t1b.CanonicalName != "monolog/monolog" {
		t.Errorf("CanonicalName = %q, want monolog/monolog", t1b.CanonicalName)
	}

	// 2. Resolve guzzlehttp/guzzle
	t2, err := probe.Resolve(context.Background(), "guzzlehttp/guzzle")
	if err != nil {
		t.Fatalf("resolve guzzlehttp/guzzle: %v", err)
	}
	if t2.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Tracker Protocol = %q, want github", t2.Tracker.Protocol)
	}

	// 3. Resolve dev dependency phpunit
	t3, err := probe.Resolve(context.Background(), "phpunit")
	if err != nil {
		t.Fatalf("resolve phpunit: %v", err)
	}
	if t3.LocalVersion != "10.5.9" {
		t.Errorf("LocalVersion = %q, want 10.5.9", t3.LocalVersion)
	}
	if t3.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Tracker Protocol = %q, want github", t3.Tracker.Protocol)
	}

	// 4. Resolve root project from composer.json
	t4, err := probe.Resolve(context.Background(), "my-php-app")
	if err != nil {
		t.Fatalf("resolve my-php-app: %v", err)
	}
	if t4.CanonicalName != "my-org/my-php-app" {
		t.Errorf("CanonicalName = %q, want my-org/my-php-app", t4.CanonicalName)
	}
	if t4.Tracker.Protocol != ProtocolGitHub {
		t.Errorf("Tracker Protocol = %q, want github", t4.Tracker.Protocol)
	}
}
