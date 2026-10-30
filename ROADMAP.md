# ROADMAP.md — bugrouter Project Roadmap & Vision

This document tracks the long-term architectural trajectory, active implementation focus, and milestone ledger for `bugrouter`. It serves as the authoritative cross-session plan for all Architect and Implementer sessions.

---

## 1. Core Product Philosophy

`bugrouter` is built on four core principles defined by the Principal Architect:

1. **Zero External Dependencies & Modern C99-Spirit Go:**
   Implemented exclusively with the Go standard library (`net/http`, `os/exec`, `crypto/subtle`, `encoding/json`). Zero `node_modules`, zero third-party Go modules, zero supply-chain attack surface. Bounded memory execution (`io.LimitReader`), strict per-request timeouts, and type-level security guarantees.

2. **Maintainer Empathy & AI Opt-Out Guard (Zero Maintainer Harassment):**
   Open-source maintainers must never be inundated with unverified or automated AI-generated bug spam. `bugrouter` automatically scans upstream issue templates and `CONTRIBUTING.md` policies for AI/LLM opt-out rules. If an upstream repository restricts AI submissions, `bugrouter` **blocks automated API submission 100% of the time**, switches into **Companion Mode** (`companion_only`), strips automated branding footers, surfaces maintainer checklist rules, and provides pre-filled deep links for human engineers to review and file respectful, human-authored reports manually.

3. **Anti-Context-Hijacking via `<5ms` Native Session Handoff (`park_bug`):**
   When an AI coding agent spots a bug or anomaly in a 3rd-party dependency while implementing a feature, derailing into ticket filing destroys its in-context reasoning. `bugrouter park` / `park_bug` records the issue locally in `<5ms` with zero network I/O, presenting 4 clear flow preservation choices:
   - **Choice 1: Ignore & continue** the current task without friction.
   - **Choice 2: Keep parked** in `<5ms` with full contextual breadcrumbs (`park_bug`).
   - **Choice 3: Spawn a separate triage session** using native MCP Resources and Prompts (`bugrouter://parked/<id>`).
   - **Choice 4: Fork/patch locally** and maintain visibility in the dependency patch ledger (`bugrouter patch`).

4. **Dependency Patch Ledger with Automated Upstream Status Checks (`patch check`):**
   When upstream maintainers take time to fix bugs, development teams frequently fork or vendor-patch dependencies (`go.mod` `replace`, npm `overrides`/`patches/`, Cargo `[patch]`). These temporary forks often become permanent technical debt. `bugrouter` tracks every temporary patch alongside its upstream issue URL in a high-visibility ledger and provides automated upstream status checks (`bugrouter patch check`) to notify engineers the instant an upstream bug is closed and the fork is **[READY TO REVERT]**.

---

## 2. Chronological Milestones Ledger (Milestones 1–8)

All milestones below are fully implemented, verified with race-detector tests, and merged into the core engine under CalVer `2026.10.0`.

### Milestone 1: Core Foundation, Waterfall Resolver, Deterministic Scrubber [COMPLETED]
- [x] **Spec #01: Zero-Dependency Core Resolver & Contract**: Bootstrapped CalVer versioning (`2026.10.0`), bounded `httpx.Client`, and initial `resolver.Target` abstraction.
- [x] **Spec #02: Classification Engine, DirectProbe & OSPackageProbe**: Added URL normalization, forge classification (GitHub, GitLab, Codeberg, SourceHut), and Debian/Ubuntu package queries (`dpkg`, `apt`).
- [x] **Spec #03: Workspace Probe, Registry Probe & Web Domain Discovery**: Implemented Node.js `node_modules` and Go `go.mod` parsing, concurrent registry probing for npm, PyPI, and Crates.io, and web discovery via RFC 9116 `security.txt` and `/.well-known/bug-report`.
- [x] **Spec #04: Type-Safe Secret Scrubber**: Implemented immutable `ScrubbedText`, regex redaction for AWS, GitHub, Slack, OpenAI, PEM keys, and URI credentials, and local draft staging in `$XDG_DATA_HOME/bugrouter/drafts` with `0600` permissions.

### Milestone 2: Upstream Template Introspector, Duplicate Search Engine, Quality Scorer [COMPLETED]
- [x] **Spec #05: Upstream Issue Template Introspector**: Built zero-dependency YAML and Markdown issue template parsers, Bugzilla REST schema discovery, and query parameter pre-fill adaptation.
- [x] **Spec #07: Upstream Issue Deduplicator & Polyglot Manifests**: Added Rust `Cargo.toml`/`Cargo.lock` and Python `pyproject.toml` parsing, Fedora/RHEL `rpm` and Arch `pacman` probes, and token overlap duplicate detection for GitHub, GitLab, and Bugzilla.
- [x] **Spec #07.1: Deduplication Hardening & Python PEP Normalization**: Fixed TOML inline table scanning, implemented PEP 503/508 package name normalization, and derived enterprise forge API base URLs.
- [x] **Spec #11.A: Deterministic Anti-Slop Quality Linter**: Built `LintDraft` calculating 0–100 quality scores, gating AI buzzwords, chatbot tells, decorative emojis, em dashes, and unfilled placeholders with `--strict-quality`.

### Milestone 3: Staged Draft Adapter, Human-in-the-Loop Review CLI, Authenticated Cloud Control Plane [COMPLETED]
- [x] **Spec #06: WorkOS-Style Org Discovery & Cloud Control Plane**: Added Layer 0 `OrgCloudProbe` for enterprise `services.json`, embedded review queue Web UI, and authenticated OAuth connectors (GitHub, GitLab, Jira, Linear).
- [x] **Spec #06.1: Control Plane Hardening & Post-M2 Remediation**: Bound forge client with `httpx.PostBytes` SSRF protection, hardened draft IDs against directory traversal, and decoupled Jira and Linear protocols.
- [x] **Spec #08: Control Plane Security, Audit Logger & Webhooks**: Implemented constant-time Bearer token authentication with SHA-256 pre-hashing, CSRF origin verification, append-only JSONL audit logging (`audit.log`), and HMAC-SHA256 signed webhook dispatching (`X-Bugrouter-Signature`).
- [x] **Spec #09 & #09.1: Production Readiness & Scrubber Precision**: Refined secret scrubber thresholds (>= 6 chars, preserving booleans and nil), added `--timeout` context bounds, `--body-file` stdin markdown parsing, and end-to-end integration tests.

### Milestone 4: Native Session Handoff (`bugrouter park`), WorkOS-Style Services Catalog, Zero-Dependency Telemetry [COMPLETED]
- [x] **Spec #11: Zero-Hijacking `park_bug` MCP Handoff & WorkOS Services Catalog**:
  - Implemented `<5ms` zero-network-call `ParkedStore` (`ParkedBug`, `HandoffPayload`) with 8-character hex IDs and atomic `0600` persistence in `$XDG_DATA_HOME/bugrouter/parked/<id>.json`.
  - Added `park_bug` as first tool in `internal/mcp/server.go`, emitting `notifications/resources/list_changed` before returning tool response, and serving `bugrouter://parked/<id>` and `triage_parked_bug` prompts.
  - Built WorkOS-style catalog API (`GET/POST/DELETE /api/v1/services`) and 1-click preset connection tiles in Cloud UI.
  - Added `bugrouter park` CLI subcommand and `--from-parked <id>` draft hydration.
- [x] **Spec #14: Zero-Dependency Hardware & OS Telemetry**:
  - Implemented `telemetry.Collect` gathering OS, kernel, CPU, GPU models, driver versions, display servers, and desktop environments across Linux, macOS, and Windows with type-safe scrubbing.
  - Added `bugrouter telemetry [--json]` subcommand and attached telemetry to `## Environment` sections in bug drafts.

### Milestone 5: Deterministic Reproduction Verifier (`bugrouter verify`), Workspace Stack Radar (`bugrouter stack`) [COMPLETED]
- [x] **Spec #12: Bounded Reproduction Validator**:
  - Built `internal/verifier/verifier.go` (`Verify`, `VerifyOptions`, `VerificationProof`), executing reproduction shell commands under bounded timeouts (default 15s) and 256 KiB output buffers, capturing/scrubbing output, matching exit codes, and generating deterministic SHA-256 proof digests.
  - Integrated `VerificationProof` into drafts with `## Verified Reproduction` section and +10 quality bonus.
  - Added `bugrouter verify` / `bugrouter agent verify` CLI subcommands and `verify_reproduction` MCP tool.
- [x] **Spec #13 & #13.1: Workspace Tech Stack Scanner & Downstream Bug Radar**:
  - Implemented `internal/resolver/stack.go` scanning workspace dependencies across `services.json`, `go.mod`, `package.json`, `Cargo.toml`, and `pyproject.toml` with concurrent resolution.
  - Implemented `internal/dedup/radar.go` querying canonical upstream trackers (GitHub, GitLab, Bugzilla, Gitea) for active open bugs affecting local dependency versions.
  - Added `bugrouter stack` CLI subcommand, `/api/v1/stack` REST endpoint, "Connected Tech Stack & Downstream Radar" Web UI tab, and `scan_workspace_stack` MCP tool.

### Milestone 6: Native OS Crash Log Ingestion (`bugrouter triage` + WER / coredumpctl / DiagnosticReports) [COMPLETED]
- [x] **Spec #12.A: Zero-Daemon Post-Mortem OS Crash Reader**:
  - Implemented `internal/resolver/crashlog.go` (`ReadLatestCrash`) reading native OS post-mortem journals on demand without background pollers:
    - Linux: `coredumpctl info` and directory scanning `/var/crash`, `/var/lib/systemd/coredump`
    - Windows: Windows Error Reporting (WER) and Event Viewer (Application Crash Event ID 1000) via bounded PowerShell query
    - macOS: `/Library/Logs/DiagnosticReports/` and `~/Library/Logs/DiagnosticReports/` sorted by modification time
  - Added `bugrouter crash-log [--json] [--query <target>]` CLI subcommand and `read_system_crash_log` MCP tool.
- [x] **Spec #11.B: Crash Log Auto-Attribution**:
  - Implemented `ExtractTargetsFromLog` in `internal/resolver/trace.go`, parsing Go, Node.js, Python, Rust, and native segfault traces to identify culprit symbols and suspect packages.
  - Added `bugrouter triage` / `bugrouter agent triage` CLI subcommands and `triage_crash_log` MCP tool.

### Milestone 7: Maintainer Empathy & Opt-Out Guard (`companion_only` mode, `CONTRIBUTING.md` checklist parsing) [COMPLETED]
- [x] **Spec #12: Maintainer Empathy & Opt-Out Guard**:
  - Added `MaintainerPolicy` struct (`AIOptOut`, `OptOutReason`, `ChecklistRules`) to `TemplateSchema`.
  - Implemented `ParseMaintainerPolicy` in `internal/introspector/parser.go`, scanning case-insensitively for upstream maintainer opt-out phrases (`"no ai"`, `"no llm"`, `"do not submit ai"`, `"no automated issue"`, `"ai-generated issues"`, `"ban ai"`, `"no bot"`) and extracting up to 5 prerequisite checklist rules.
  - Fetched `CONTRIBUTING.md` and `.github/CONTRIBUTING.md` in `introspectGitHub` and `introspectGitea`.
  - Switched `adapter.BuildDraft` into **Companion Mode** when maintainers opt out (`draft.Status = "companion_only"`), omitting the `*Staged via bugrouter/...*` footer.
  - Hardened automated API submission refusal in `ForgeClient.Submit`, `Server.handleApproveDraft`, and `mcp.approve_draft`.
- [x] **Spec #12: Self-Hosting Dogfooding & Cross-Dependency Evidence Dossiers**:
  - Added intrinsic `<1ms` offline self-resolution in `DirectProbe.Resolve` for `"bugrouter"` and `"self"`.
  - Added top-level panic recovery with auto-parking breadcrumb (`recoverAndParkSelfBug`) in `main()`.
  - Added `RelatedDependency` and `RelatedIssues` to `DraftInput` and `StagedDraft`, compiling correlated upstream tickets under `## Correlated Evidence (<dep>)`.

### Milestone 8: Upstream Patch Status Checker (`bugrouter patch check`), Cloud UI Companion Mode & Full 15 MCP Tools Integration [COMPLETED]
- [x] **Upstream Patch Status Checker Engine (`internal/adapter/patch_check.go`)**:
  - Implemented `CheckPatchUpstreamStatus` querying upstream tracker issue states across GitHub (`GET /repos/...`), GitLab (`GET /api/v4/projects/.../issues/...`), Gitea (`GET /api/v1/repos/.../issues/...`), and Bugzilla (`GET /rest/bug/...`), returning `PatchStatusResult` with `UpstreamState` and `CanRevert: true` when closed.
  - Bounded concurrency with a 5-worker semaphore and per-request timeouts.
- [x] **CLI Subcommand (`cmd/bugrouter/main.go`)**:
  - Extended `bugrouter patch` to support `bugrouter patch check [--json] [--timeout <dur>]`, displaying each tracked patch, its upstream issue URL, state, and clear `[READY TO REVERT]` status.
- [x] **Cloud Control Plane & Companion Mode UI (`internal/cloud/server.go`)**:
  - Wired `introspector` into `handleCreateDraft` so drafts created via Web UI respect maintainer opt-outs and trigger `companion_only` status.
  - Added `POST /api/v1/patches/check` and `GET /api/v1/patches?check_upstream=1` endpoints.
  - Added "Check Upstream Status" button and green `Ready to Revert` badges to the Active Dependency Patches banner in `indexHTML`.
  - Added `.status-companion` styling, disabled `Approve` button for `companion_only` drafts, rendered Maintainer Empathy banner with `opt_out_reason`, checklist rules, and manual submission link, and rendered `Correlated Evidence`.
- [x] **Full 15 MCP Tools Integration (`internal/mcp/server.go`)**:
  - Added `check_dependency_patches` as the 15th MCP tool.
  - Verified exact tool count of 15 tools with comprehensive test suite.
- [x] **Milestone 9: GitHub Actions Matrix, CI/CD Pipeline & Automated CalVer Release [COMPLETED]**:
  - **Multi-OS CI Matrix (`.github/workflows/ci.yml`)**: Strategy matrix across `ubuntu-latest`, `macos-latest`, `windows-latest` with `go-version: ['1.22.x']`, enforcing supply-chain zero external dependency validation, code formatting on Linux/macOS, `go vet`, `go test -race -v`, and static binary compilation.
  - **Reproducible CalVer Release Automation (`.github/workflows/release.yml`)**: Cross-compilation pipeline triggered on CalVer tags (`20[0-9][0-9].[0-1][0-9].*`) producing stripped static binaries (`CGO_ENABLED=0`, `-trimpath`, `-ldflags="-s -w"`) for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, and `windows/amd64`, generating `SHA256SUMS`, and publishing releases via `softprops/action-gh-release@v2`.
  - **Turnkey Composite GitHub Action (`action.yml`)**: Root composite action enabling any repository to audit tracked dependency patches (`mode: patch-check`, with `fail-on-revertable: true`) or triage crash logs (`mode: triage`), generating rich Markdown summaries in `$GITHUB_STEP_SUMMARY`.
  - **Makefile Release Dry-Run (`Makefile`)**: Added `make release-dry-run` to cross-compile all 5 platform binaries to `dist/` with `SHA256SUMS` and updated `clean` to purge `bin/ dist/`.

---

## 3. Future & Planned Milestones

*(All core milestones through Milestone 9 completed)*
