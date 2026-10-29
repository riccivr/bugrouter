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

### Milestone 6: Tech Stack Explorer & Downstream Bug Radar (Active)
Shifts bugrouter from reactive ticket routing to proactive dependency health and upstream tracking.

- **Spec #13: Workspace Stack Scanner & Downstream Radar [ACTIVE]**
  - Command `bugrouter stack [--json] [--check-upstream]`: recursively catalogs all dependencies across `package.json`, `go.mod`, `Cargo.toml`, and `pyproject.toml`.
  - Maps each dependency to its upstream tracker and queries trackers for active bugs matching the local installed version.
  - Adds "Connected Tech Stack & Downstream Bugs" dashboard tab to the embedded Cloud Control Plane Web UI.

---

### Milestone 7: Desktop/PC User Mode & Hardware Telemetry (Planned)
Brings zero-dependency bug routing to desktop operating systems and everyday GUI applications.

- **Spec #14: Desktop App Resolver & Hardware Telemetry Collector [PLANNED]**
  - Package probes for Windows `winget` and Linux `flatpak`/`snap`.
  - Support for community forges and custom issue trackers (such as Gitea/Forgejo at `projects.blender.org`).
  - Native hardware telemetry collector (`internal/telemetry`) gathering GPU model, driver versions, CPU architecture, and OS kernel info without third-party dependencies.
- **Spec #15: Guided Human Bug Wizard [PLANNED]**
  - Interactive terminal wizard (`bugrouter report <app>`) prompting users for symptoms and reproducing steps with real-time anti-slop suggestions.
  - Web UI guided composer providing step-by-step assistance for non-technical users.
