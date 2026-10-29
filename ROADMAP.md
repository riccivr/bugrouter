# ROADMAP.md — bugrouter Project Roadmap & Vision

This document tracks the long-term architectural trajectory, active implementation focus, and milestone ledger for `bugrouter`. It guides current and future contributors on what has been built, what is active now, and what comes next.

---

## 1. Vision & Three Core Pillars

`bugrouter` is an autonomous upstream router and triage system designed to eliminate friction between failing software, coding agents, engineering teams, and upstream maintainers. The project is organized around three strategic pillars:

### Pillar 1 — Autonomous CLI & MCP Agentic Mode (Current Focus)
AI coding agents (such as Claude Code, Antigravity, and CI bots) hitting runtime failures, panics, or broken dependencies should never have to manually inspect stack traces, deduce repository URLs, search for duplicate tickets, or craft submission templates. Through single-shot crash attribution, upstream template introspection, duplicate detection, deterministic credential scrubbing, and an Anti-Slop Quality Gate, `bugrouter` enables agents to stage and submit maintainer-grade, high-signal bug reports with zero human babysitting.

### Pillar 2 — Tech Stack & Downstream Bug Radar for Engineering Teams (Milestone 6)
Engineering teams need continuous visibility into whether upstream bugs, regressions, or security advisories affect their pinned dependencies. Through full workspace inventory scanning (`bugrouter stack`), `bugrouter` maps every dependency in `package.json`, `go.mod`, `Cargo.toml`, `pyproject.toml`, and enterprise `services.json` to its canonical upstream tracker, surfacing active upstream issues that impact the team's local dependency tree.

### Pillar 3 — Everyday Linux & Windows PC User Experience (Milestone 7)
Desktop developers and non-technical users who encounter crashes in GUI applications (for example, GPU rendering crashes in Blender on Windows or Linux) need a zero-friction, zero-slop reporting path. `bugrouter` extends beyond developer manifests to inspect desktop package managers (`winget`, `flatpak`, `snap`, Gitea/Forgejo platforms like `projects.blender.org`), collect hardware and OS telemetry, and guide users through an interactive, human-friendly bug wizard.

---

## 2. Completed Milestones Ledger (Milestones 1–4, Specs #01–#10.1)

All milestones and specs below have been fully implemented, verified with race-detector tests, and merged into the core engine:

- **Spec #01: Zero-Dependency Core Resolver & Contract [COMPLETED]**
  - Bootstrapped CalVer versioning, bounded `httpx.Client`, and initial `resolver.Target` abstraction.
- **Spec #02: Classification Engine, DirectProbe & OSPackageProbe [COMPLETED]**
  - Added URL normalization, forge classification (GitHub, GitLab, Codeberg, SourceHut), and Debian/Ubuntu package queries (`dpkg`, `apt`).
- **Spec #03: Workspace Probe, Registry Probe & Web Domain Discovery [COMPLETED]**
  - Implemented Node.js `node_modules` and Go `go.mod` parsing, concurrent registry probing for npm, PyPI, and Crates.io, and web discovery via RFC 9116 `security.txt` and `/.well-known/bug-report`.
- **Spec #04: Type-Safe Secret Scrubber & Draft Engine [COMPLETED]**
  - Implemented immutable `ScrubbedText`, regex redaction for AWS, GitHub, Slack, OpenAI, PEM keys, and URI credentials, and local draft staging in `$XDG_DATA_HOME/bugrouter/drafts` with `0600` permissions.
- **Spec #05: Upstream Issue Template Introspector [COMPLETED]**
  - Built zero-dependency YAML and Markdown issue template parsers, Bugzilla REST schema discovery, and query parameter pre-fill adaptation.
- **Spec #06: WorkOS-Style Org Discovery & Cloud Control Plane [COMPLETED]**
  - Added Layer 0 `OrgCloudProbe` for enterprise `services.json`, embedded review queue Web UI, and authenticated OAuth connectors (GitHub, GitLab, Jira, Linear).
- **Spec #06.1: Control Plane Hardening & Post-M2 Remediation [COMPLETED]**
  - Bound forge client with `httpx.PostBytes` SSRF protection, hardened draft IDs against directory traversal, and decoupled Jira and Linear protocols.
- **Spec #07: Upstream Issue Deduplicator & Polyglot Manifests [COMPLETED]**
  - Added Rust `Cargo.toml`/`Cargo.lock` and Python `pyproject.toml` parsing, Fedora/RHEL `rpm` and Arch `pacman` probes, and token overlap duplicate detection for GitHub, GitLab, and Bugzilla.
- **Spec #07.1: Deduplication Hardening & Python PEP Normalization [COMPLETED]**
  - Fixed TOML inline table scanning, implemented PEP 503/508 package name normalization, and derived enterprise forge API base URLs.
- **Spec #08: Control Plane Security, Audit Logger & Webhooks [COMPLETED]**
  - Implemented constant-time Bearer token authentication with SHA-256 pre-hashing, CSRF origin verification, append-only JSONL audit logging (`audit.log`), and HMAC-SHA256 signed webhook dispatching (`X-Bugrouter-Signature`).
- **Spec #09: v1.0 Production Readiness, CLI Polish & Golden Path [COMPLETED]**
  - Refined secret scrubber thresholds (>= 6 chars, preserving booleans and nil), added `--timeout` context bounds, `--body-file` stdin markdown parsing, and end-to-end integration tests.
- **Spec #09.1: Red-Team Remediation & Scrubber Precision [COMPLETED]**
  - Removed private host environment bypasses, shared bounded HTTP clients across CLI workflows, and preserved quoted strings during redaction.
- **Spec #10: CLI/README Parity, MCP Audit Trail & Private Repo Auth [COMPLETED]**
  - Aligned CLI version formatting, added idempotent draft approval guards returning HTTP 409 Conflict, and added environment token authentication for private GitHub and GitLab repositories.
- **Spec #10.1: Credential Boundary Remediation [COMPLETED]**
  - Removed GitLab token leaks to Bugzilla endpoints, added automated cross-host redirect credential stripping in `httpx.Client`, and restricted GitHub token forwarding to verified API and raw download hostnames.

---

## 3. Active & Upcoming Milestones

### Milestone 5: CLI Agentic Mode & Anti-Slop Gate (Completed)
Focuses on autonomous, zero-friction developer and agent triage from terminal errors.

- **Spec #11: Crash Log Auto-Attribution, Anti-Slop Gate & Agent CLI [COMPLETED]**
  - `ROADMAP.md` master plan.
  - Deterministic Crash and Stack Trace Attribution Engine (`internal/resolver/trace.go`): extracts `TraceCandidate` slices from Node.js, Go, Python, Rust, and Unix CLI error logs.
  - Deterministic Anti-Slop Quality Linter (`internal/adapter/linter.go`): calculates a 0 to 100 quality score, checks for AI conversational filler, vague titles, and missing steps, and gates drafts via `--strict-quality`.
  - CLI Agentic Mode (`bugrouter agent triage`): single-shot crash triage command outputting structured JSON envelopes for autonomous calling agents.
  - MCP Tool `triage_crash_log`: exposes autonomous crash attribution and draft triage to MCP agent workflows.
- **Spec #12: Agentic Self-Verification & Reproduction Script Validator [COMPLETED]**
  - Bounded reproduction validator (`internal/verifier/verifier.go`): executes shell commands under isolated subshells with 256 KiB output caps, timeout handling, secret redaction, and SHA-256 proof digests.
  - Integrated `VerificationProof` into `adapter.DraftInput`, `adapter.StagedDraft`, `adapter.BuildDraft`, and `adapter.LintDraft` (+10 quality bonus, automatic logs attachment).
  - CLI subcommand `bugrouter agent verify` and `--verify-cmd` on `bugrouter draft`.
  - Exposed 9th MCP tool `verify_reproduction` and added `strict_quality` and `verify_cmd` to `draft_bug_report`.

---

### Milestone 6: Tech Stack Explorer & Downstream Bug Radar (Completed)
Shifts bugrouter from reactive ticket routing to proactive dependency health and upstream tracking.

- **Spec #13: Workspace Stack Scanner & Downstream Radar [COMPLETED]**
  - Command `bugrouter stack [--json] [--check-upstream]`: recursively catalogs all dependencies across `package.json`, `go.mod`, `Cargo.toml`, and `pyproject.toml`.
  - Maps each dependency to its upstream tracker and queries trackers for active bugs matching the local installed version.
  - Adds "Connected Tech Stack & Downstream Bugs" dashboard tab to the embedded Cloud Control Plane Web UI.
  - Exposes `scan_workspace_stack` MCP tool for AI agents.

---

### Milestone 7: Desktop/PC User Mode & Hardware Telemetry (Completed)
Brings zero-dependency bug routing to desktop operating systems and everyday GUI applications.

- **Spec #14: Desktop App Resolver, Gitea/Forgejo Support & Hardware Telemetry Collector [COMPLETED]**
  - Package probes for Windows `winget` and Linux `flatpak`/`snap` with pure deterministic output parsers.
  - Support for community forges and custom issue trackers (such as Gitea/Forgejo at `projects.blender.org`, `gitea.com`, and custom hostnames), including REST API search, template introspection, and pre-filled deep links.
  - Zero-dependency native hardware and OS telemetry collector (`internal/telemetry`) gathering GPU model, CPU architecture, OS kernel, desktop environment, and display server with type-safe scrubbing.
  - CLI integration via `bugrouter telemetry [--json]`, `bugrouter agent telemetry`, and `bugrouter draft --with-telemetry`.
  - MCP integration exposing `collect_system_telemetry` as the 11th tool and adding `include_telemetry` to `draft_bug_report`.
- **Spec #15: Guided Human Bug Wizard & Web UI Guided Composer [COMPLETED]**
  - Spec #14.1 red-team constitutional remediation: zero `_ =` assignments in `internal/dedup`, Gitea/Codeberg token support in `introspectGitea` and `ForgeClient`, removal of dead branches, and em dash, emoji, and placeholder quality lint checks.
  - Interactive terminal wizard (`bugrouter report <query>`) prompting users line-by-line for bug details with real-time Anti-Slop quality scoring, duplicate checking, and automatic hardware/OS telemetry attachment.
  - Cloud Control Plane Guided Draft Composer API (`POST /api/v1/drafts`) supporting telemetry attachment and strict quality gates (422 Unprocessable Entity), plus interactive Web UI composer modal.

---

### Milestone 8: GitHub Actions, CI/CD Matrix & Release Automation (Active)
Automates testing, cross-compilation, and autonomous upstream triage inside GitHub Actions pipelines.

- **Spec #16: GitHub Actions CI/CD & CalVer Release Pipeline [ACTIVE]**
  - `.github/workflows/ci.yml`: Zero-dependency `go fmt`, `go vet`, commit-msg lint, and `go test -race ./...` matrix across `ubuntu-latest`, `windows-latest`, and `macos-latest`.
  - `.github/workflows/release.yml`: Reproducible `CGO_ENABLED=0` static binary cross-compilation (`linux/amd64`, `linux/arm64`, `windows/amd64`, `darwin/arm64`) triggered on CalVer tags (`YYYY.0M.MICRO`) with `SHA256SUMS` provenance.
  - Composite GitHub Action (`action.yml`): Turnkey CI step allowing any GitHub Actions workflow to pipe failing test logs into `bugrouter agent triage` and stage anti-slop gated tickets automatically.
