# ARCHITECTURE_STATE.md — bugrouter System Architecture & Handoff

Current CalVer: **2026.10.0**  
Status: **Milestones 1–10 Completed** (Core Resolver, Upstream Introspector, Cloud Control Plane, Native MCP Handoff, Stack Radar & Reproduction Verifier, Native OS Crash Reader, Maintainer Empathy & Opt-Out Guard, Upstream Patch Status Checker, GitHub Actions Matrix & Release Automation, and Workspace Patch Scanner & Release Finalization)

---

## 1. System Overview

`bugrouter` is an autonomous, zero-dependency Go CLI and Model Context Protocol (MCP) server that resolves arbitrary software artifacts (local dependencies, OS packages, ecosystem libraries, and SaaS domains) to their canonical upstream bug trackers, scrubs sensitive credentials at the type level, introspects upstream issue templates, identifies upstream duplicate issues, verifies reproductions, checks upstream patch statuses, and stages structured bug tickets for Human-in-the-Loop review.

---

## 2. Package Map

| Package | Path | Purpose & Responsibilities |
| :--- | :--- | :--- |
| `main` | `cmd/bugrouter/main.go` | Entrypoint providing `version`, `resolve`, `introspect`, `dedup`, `draft` (with `--from-parked <id>` and `--related-dep <pkg>`), `scrub`, `telemetry`, `triage` / `agent triage`, `verify` / `agent verify`, `stack`, `park` (with `--related-dep <pkg>`), `patch` (`list`, `add`, `scan`, `check`, `rm`), `crash-log`, `report` (guided interactive wizard), `serve`, and `mcp` subcommands with disk caching, bounded execution (`--timeout`), `--body-file` with stdin support, autonomous crash triage, bounded self-verification, `--verify-cmd` draft attachment, local hardware telemetry, zero-daemon post-mortem OS crash reader, workspace dependency inventory & downstream bug radar, top-level panic recovery auto-parking (`recoverAndParkSelfBug`), graceful shutdown, duplicate detection warnings, and flag orchestration. |
| `version` | `internal/version/version.go` | CalVer version constant (`2026.10.0`) and canonical `User-Agent` generator. |
| `httpx` | `internal/httpx/client.go` | Bounded HTTP client enforcing 2 MiB body caps, timeouts, rate limiting (`429`/`503` retry handling), and SSRF/DNS-rebinding protection against private/loopback/link-local addresses with automatic credential stripping on cross-host redirects. |
| `cache` | `internal/cache/disk.go` | Zero-dependency local TTL disk cache backed by `$XDG_CACHE_HOME/bugrouter/targets` with SHA-256 key hashing and atomic file replacement. |
| `resolver` | `internal/resolver/` | 6-layer waterfall resolution engine: `OrgCloudProbe` (enterprise catalog/monorepo ownership), `DirectProbe` (with intrinsic offline `<1ms` self-target resolution for `bugrouter` and `self`), `WorkspaceProbe` (`node_modules`, `go.mod`, `Cargo.toml`/`Cargo.lock`, `pyproject.toml`), `OSPackageProbe` (Debian `dpkg`/`apt`, Fedora/RHEL `rpm`, Arch `pacman`, Linux `flatpak`, `snap`, Windows `winget`), `RegistryProbe` (`npm`, `PyPI`, `Crates.io`), and `WebDomainProbe` (`.well-known/bug-report`, RFC 9116 `security.txt`). Strict hostname classification for GitHub, GitLab, Codeberg, Gitea/Forgejo (`projects.blender.org`, `gitea.com`, `*.gitea.*`, `*.forgejo.*`), SourceHut, Bugzilla, Debbugs, Jira, and Linear. Deterministic Crash & Stack Trace Attribution Engine (`trace.go`) mapping Go, Python, Node.js, Rust, and native segfault traces to culprit symbols and suspect targets. Zero-Daemon Post-Mortem OS Crash Reader (`crashlog.go`) extracting crash logs and suspect applications from `coredumpctl`, `/var/crash`, Windows Application Error Event ID 1000, WER, and macOS `DiagnosticReports` on demand. Workspace Tech Stack Scanner (`stack.go`) scanning workspace manifests (`services.json`, `go.mod`, `package.json`, `Cargo.toml`, `pyproject.toml`) and resolving dependencies concurrently. Wires optional `TargetCache` into resolution lifecycle. |
| `verifier` | `internal/verifier/` | Bounded reproduction validator (`Verify`, `VerifyOptions`, `VerificationProof`) executing reproduction shell commands under bounded contexts (256 KiB combined output buffer, timeout handling, exit code matching, candidate extraction, secret redaction, and SHA-256 proof digests). |
| `telemetry` | `internal/telemetry/` | Zero-dependency native hardware, operating system, and desktop GUI telemetry collector (`SystemTelemetry`: OS, Arch, KernelVersion, CPUModel, NumCPU, GPUs, GPUModels, DesktopEnv, DesktopEnvironment, DisplayServer, DriverVersion) gathering advanced diagnostics on Linux (`lspci`, `/sys/class/drm`, `/sys/bus/pci/devices`, `/proc/driver/nvidia`, `nvidia-smi`), macOS (`system_profiler SPDisplaysDataType`), and Windows (PowerShell `Get-CimInstance Win32_VideoController` CSV, `wmic`) with type-safe scrubbing and clean Markdown list formatting under `## Environment`. |
| `introspector` | `internal/introspector/` | Discovers and parses upstream issue templates across GitHub (YAML Issue Forms and Markdown), GitLab (Markdown templates), Gitea/Codeberg (`/api/v1/repos/<owner>/<repo>/issue_templates`), and Bugzilla (REST schemas `/rest/product` and `/rest/field/bug`) with enterprise host API base URL derivation and zero external dependencies. Houses Maintainer Empathy & Policy Parser (`parser.go`: `MaintainerPolicy`, `ParseMaintainerPolicy`) scanning for AI/bot opt-out notices and checklist rules across templates and `CONTRIBUTING.md` documents. |
| `dedup` | `internal/dedup/` | Queries upstream trackers (GitHub, GitLab, Bugzilla, Gitea) for existing duplicate bug reports using token overlap scoring, stop word filtering, keyword extraction, and enterprise forge API base URL derivation. Downstream Bug Radar (`radar.go`: `BuildStackRadar`, `StackRadarEntry`, `StackRadarReport`) querying upstream issue trackers for active bugs matching workspace dependencies via `ListActiveIssues` with version prioritization. Supports private repo auth via `GITLAB_TOKEN`, `GL_TOKEN`, `BUGROUTER_GITLAB_TOKEN`, `GITHUB_TOKEN`, `GITEA_TOKEN`. |
| `scrubber` | `internal/scrubber/scrubber.go` | Deterministic secret and PII redactor producing `ScrubbedText`. Strips PEM private keys, Bearer tokens, AWS/GitHub/OpenAI/Stripe/Slack keys, generic config assignments (>= 6 chars, preserving non-secret literals like `true`/`false`/`null`/`nil`), URI credentials, and `/home/*` or `/Users/*` paths. |
| `adapter` | `internal/adapter/` | Sanitizes titles against RFC-822 header injection, maps upstream template schemas to Markdown sections (`### <Label>`), attaches potential upstream duplicate tickets, generates deep-link submission URLs (GitHub issue form query parameters, GitLab `issuable_template`, Gitea/Codeberg `/issues/new?title=...&body=...`, Bugzilla `enter_bug.cgi`), RFC-822 Debbugs emails with pseudo-headers, and atomically stages tickets with `0600` permissions via `DraftStore`. Houses Zero-Latency Parked Bug Store (`parked.go`: `ParkedBug`, `HandoffPayload`, `ParkedStore`) storing breadcrumbs with optional `RelatedDependency` in `$XDG_DATA_HOME/bugrouter/parked` in `<5ms` with zero network calls, 4-way flow preservation options, and atomic `0600` writes. Houses Tracked Dependency Patch Ledger (`patch.go`: `DependencyPatch`, `PatchStore`) tracking local dependency forks in `patches.json` with atomic `0600` persistence. Upstream Patch Status Checker (`patch_check.go`: `CheckPatchUpstreamStatus`, `PatchStatusResult`) querying tracker states across GitHub, GitLab, Gitea, and Bugzilla with 5-worker bounded concurrency. Workspace Patch Scanner (`patch_scan.go`: `ScanWorkspacePatches`, `PatchStore.SyncWorkspace`) scanning `go.mod` (replace directives), `package.json` (`patch:`, `file:`, `link:`, `git+`), `patches/` folder (`*.patch`), Cargo (`[patch]`), and `pyproject.toml`. Implements Maintainer Companion Mode (`companion_only`) with staged footer omission and automated submission refusal. Compiles Cross-Dependency Evidence Dossiers (`## Correlated Evidence (<dep>)`). Integrates `VerificationProof` into drafts with automatic logs fallback and `## Verified Reproduction` section. Integrates `SystemTelemetry` under `## Environment`. Houses Anti-Slop Quality Linter (`linter.go`) evaluating buzzwords, chatbot tells, emojis, em dashes, incomplete placeholders, and awarding +10 bonus for verified reproduction proofs. |
| `cloud` | `internal/cloud/` | Zero-dependency Cloud Control Plane HTTP daemon (`Server`) with embedded single-page Web UI for Human-in-the-Loop review queues (`/api/v1/health`, `/api/v1/drafts`, `/api/v1/drafts/{id}/approve`, `/api/v1/drafts/{id}/discard`, `/api/v1/audit`, `/api/v1/stack`), Parked Bug Breadcrumbs queue (`/api/v1/parked`, `/api/v1/parked/{id}`), WorkOS-Style Active Dependency Patches banner and ledger (`/api/v1/patches`, `/api/v1/patches/check`, `/api/v1/patches/scan`), Connected Dependencies & Downstream Services catalog (`/api/v1/services`), Connected Tech Stack & Downstream Radar panel, audit trail display panel, constant-time Bearer token auth, CSRF/origin guard, append-only JSONL audit logging (`AuditLogger`), SSRF-guarded HMAC webhook dispatcher (`WebhookNotifier`), and authenticated OAuth enterprise forge connectors (`ForgeClient`) with maintainer AI opt-out submission rejection and Companion Mode banner rendering. |
| `mcp` | `internal/mcp/server.go` | Zero-dependency JSON-RPC 2.0 stdio server implementing Model Context Protocol (spec `2024-11-05`), advertising `tools`, `resources` (`listChanged: true`), and `prompts` capabilities. Publishes 17 specialized tools (`park_bug`, `list_parked_bugs`, `record_dependency_patch`, `check_dependency_patches`, `scan_workspace_patches`, `read_system_crash_log`, `resolve_target`, `scrub_text`, `introspect_template`, `search_duplicates`, `draft_bug_report` with `from_parked_id` hydration, `list_staged_drafts`, `approve_draft`, `triage_crash_log`, `verify_reproduction`, `scan_workspace_stack`, `collect_system_telemetry`). Guards `approve_draft` against maintainer opt-outs. Emits `notifications/resources/list_changed` before tool response. Handles `resources/list`, `resources/read` (`bugrouter://parked/<id>`), `prompts/list`, and `prompts/get` (`triage_parked_bug`). Automatically benefits from XDG disk caching. |

---

## 3. Implemented Interfaces & Execution Flow

### Waterfall Resolution Priority

1. **`org-cloud` (`LayerOrgCloud`)**: Evaluates enterprise service catalog and monorepo ownership records configured via `$XDG_CONFIG_HOME/bugrouter/services.json` (or `/etc/bugrouter/services.json`, or `BUGROUTER_SERVICES_FILE`) before any public probes.
2. **`direct-url` (`LayerWebDomain`)**: Matches explicit URLs and repository paths (`github.com/org/repo`, `gitlab.com/...`, `codeberg.org/...`, `sr.ht/...`). Rejects generic domain roots (`https://stripe.com`) so they fall through to web discovery.
3. **`workspace` (`LayerWorkspace`)**: Inspects local `node_modules/<pkg>/package.json` (with strict name validation against directory traversal), parses `go.mod` `require` blocks, parses Rust `Cargo.toml`/`Cargo.lock` dependencies and package manifests, and parses Python `pyproject.toml` (PEP 508 dependencies, Poetry git dependencies, and project URLs).
4. **`os-pkg` (`LayerOSPackage`)**: Resolves system binaries, packages, and desktop GUI applications across Debian/Ubuntu (`which`, `dpkg -S`, `dpkg-query -W`, `apt-cache show`), Fedora/RHEL (`rpm -qf`, `rpm -qi`), Arch Linux (`pacman -Qoq`, `pacman -Qi`), Linux `flatpak` (`flatpak info <query>`), Linux `snap` (`snap info <query>`), and Windows `winget` (`winget show [--id] <query>`), prioritizing upstream source homepages over downstream distro trackers.
5. **`registry` (`LayerRegistry`)**: Queries public package registries (`npm`, `PyPI`, `Crates.io`) concurrently with `sync.WaitGroup`, returning results in deterministic `0 -> 1 -> 2` priority order in $1 \times T$ latency.
6. **`web-domain` (`LayerWebDomain`)**: Probes web hostnames via `/.well-known/bug-report` JSON and falls back to RFC 9116 `/.well-known/security.txt` `Contact:` lines.

### Template Introspection, Duplicate Detection & Ticket Staging Pipeline

```
Raw Input (Agent / User)
       │
       ▼
[resolver.Waterfall] (with TargetCache hit/miss) ──► Target
       │
       ├──────────────────────────────────────────┐
       ▼                                          ▼
[introspector.Introspect]               [dedup.FindDuplicates]
(GitHub / GitLab / Bugzilla)            (Scored Overlap Against Tracker Issues)
       │                                          │
       ▼                                          ▼
TemplateSchema (with Policy)               PotentialDuplicates
       │                                          │
       └────────────────────┬─────────────────────┘
                            │
                            ▼
                     [scrubber.Scrub]
            (Redacts keys, tokens, URIs, paths)
                            │
                            ▼
                   [adapter.BuildDraft]
  (Maps Fields to ### <Label> Headings + Submission URLs + Companion Mode)
                            │
                            ▼
                   [adapter.DraftStore]
    (Atomic write to $XDG_DATA_HOME/bugrouter/drafts/<id>.json, mode 0600)
```

---

## 4. Chronological Milestones Architecture Ledger (Milestones 1–9.1)

### Milestone 1: Core Foundation, Waterfall Resolver, Deterministic Scrubber [COMPLETED]
- Bootstrapped CalVer versioning (`2026.10.0`), bounded `httpx.Client`, and initial `resolver.Target` abstraction.
- Implemented URL normalization, forge classification (GitHub, GitLab, Codeberg, SourceHut), and Debian/Ubuntu package queries (`dpkg`, `apt`).
- Implemented Node.js `node_modules` and Go `go.mod` parsing, concurrent registry probing for npm, PyPI, and Crates.io, and web discovery via RFC 9116 `security.txt` and `/.well-known/bug-report`.
- Built immutable `ScrubbedText` redacting AWS, GitHub, Slack, OpenAI, PEM keys, and URI credentials with atomic draft staging.

### Milestone 2: Upstream Template Introspector, Duplicate Search Engine, Quality Scorer [COMPLETED]
- Built zero-dependency YAML and Markdown issue template parsers, Bugzilla REST schema discovery, and query parameter pre-fill adaptation.
- Added Rust `Cargo.toml`/`Cargo.lock` and Python `pyproject.toml` parsing, Fedora/RHEL `rpm` and Arch `pacman` probes, and token overlap duplicate detection for GitHub, GitLab, and Bugzilla.
- Built Deterministic Anti-Slop Quality Linter in `internal/adapter/linter.go` (`LintDraft`, `QualityReport`), calculating a 0 to 100 quality score and rejecting conversational AI filler, short titles, missing steps, and missing summaries with `--strict-quality`.

### Milestone 3: Staged Draft Adapter, Human-in-the-Loop Review CLI, Authenticated Cloud Control Plane [COMPLETED]
- Added Layer 0 `OrgCloudProbe` for enterprise `services.json`, embedded review queue Web UI, and authenticated OAuth connectors (GitHub, GitLab, Jira, Linear).
- Bound `ForgeClient` with `httpx.PostBytes` enforcing SSRF protection, body caps, and redirect limits.
- Implemented constant-time Bearer token authentication with SHA-256 pre-hashing, CSRF origin verification, append-only JSONL audit logging (`audit.log`), and HMAC-SHA256 signed webhook dispatching (`X-Bugrouter-Signature`).
- Refined secret scrubber thresholds (>= 6 chars, preserving booleans and nil), added `--timeout` context bounds, `--body-file` stdin markdown parsing, and end-to-end integration tests.

### Milestone 4: Native Session Handoff (`bugrouter park`), WorkOS-Style Services Catalog, Zero-Dependency Telemetry [COMPLETED]
- Built `<5ms`, zero-network-call `ParkedStore` in `internal/adapter/parked.go` (`ParkedBug`, `HandoffPayload`) with 8-character hex IDs and atomic `0600` persistence in `$XDG_DATA_HOME/bugrouter/parked/<id>.json`.
- Integrated `park_bug` as tool 1 in `internal/mcp/server.go`, emitting `notifications/resources/list_changed` before returning tool response, and serving `resources/list`, `resources/read` (`bugrouter://parked/<id>`), `prompts/list`, and `prompts/get` (`triage_parked_bug`).
- Built WorkOS-Style Dependency Catalog in `internal/cloud/server.go` (`GET/POST/DELETE /api/v1/services`), preset dependency cards, and custom service modal.
- Created zero-dependency hardware and OS telemetry collector in `internal/telemetry/telemetry.go` (`Collect`, `SystemTelemetry`), probing OS, CPU model, core counts, kernel version, GPUs, desktop environment, and display servers on Linux, macOS, and Windows.

### Milestone 5: Deterministic Reproduction Verifier (`bugrouter verify`), Workspace Stack Radar (`bugrouter stack`) [COMPLETED]
- Built Bounded Reproduction Validator in `internal/verifier/verifier.go` (`Verify`, `VerifyOptions`, `VerificationProof`), executing reproduction shell commands under bounded timeouts (default 15s) and 256 KiB output buffers, capturing/scrubbing output, matching exit codes, extracting candidate targets, and generating deterministic SHA-256 proof digests.
- Implemented Workspace Tech Stack Scanner in `internal/resolver/stack.go` (`ScanWorkspaceManifests`), discovering dependencies across `services.json`, `go.mod`, `package.json`, `Cargo.toml`, and `pyproject.toml`.
- Implemented Downstream Bug Radar in `internal/dedup/radar.go` (`BuildStackRadar`, `StackRadarEntry`, `StackRadarReport`), querying canonical upstream trackers (GitHub, GitLab, Bugzilla) for active open bugs affecting local dependency versions.
- Added `bugrouter stack` CLI subcommand, `GET /api/v1/stack` endpoint, "Connected Tech Stack & Downstream Radar" Web UI tab, and `scan_workspace_stack` MCP tool.

### Milestone 6: Native OS Crash Log Ingestion (`bugrouter triage` + WER / coredumpctl / DiagnosticReports) [COMPLETED]
- Built zero-daemon post-mortem OS crash reader in `internal/resolver/crashlog.go` (`ReadLatestCrash`) extracting failure logs and suspect packages from native OS facilities without background pollers (Linux `coredumpctl` / `/var/crash`, Windows WER / Event 1000, macOS `DiagnosticReports`).
- Built deterministic Crash & Stack Trace Attribution Engine in `internal/resolver/trace.go` (`ExtractTargetsFromLog`, `TraceCandidate`), scanning crash logs and extracting culprit dependencies across Node.js, Go, Python, Rust, and native segfault traces.
- Added `bugrouter crash-log` and `bugrouter triage` CLI subcommands, and `read_system_crash_log` and `triage_crash_log` MCP tools.

### Milestone 7: Maintainer Empathy & Opt-Out Guard (`companion_only` mode, `CONTRIBUTING.md` checklist parsing) [COMPLETED]
- Added `MaintainerPolicy` schema (`AIOptOut`, `OptOutReason`, `ChecklistRules`) to `types.go` and `TemplateSchema`.
- Implemented `ParseMaintainerPolicy` in `internal/introspector/parser.go`, scanning case-insensitively for upstream maintainer opt-out phrases and extracting up to 5 prerequisite checklist rules.
- Added best-effort fetch of `CONTRIBUTING.md` and `.github/CONTRIBUTING.md` in `introspectGitHub` and `introspectGitea`.
- Implemented Companion Mode (`draft.Status = "companion_only"`), omitting the `*Staged via bugrouter/...*` footer and blocking automated API submissions in `ForgeClient.Submit`, `handleApproveDraft`, and `mcp.approve_draft`.
- Added self-hosting offline resolution for `"bugrouter"` and `"self"`, top-level panic recovery auto-parking (`recoverAndParkSelfBug`), and Cross-Dependency Evidence Dossiers (`--related-dep`) rendering `## Correlated Evidence (<dep>)`.

### Milestone 8: Upstream Patch Status Checker (`bugrouter patch check`), Cloud UI Companion Mode & Full 15 MCP Tools Integration [COMPLETED]
- Built Upstream Patch Status Checker in `internal/adapter/patch_check.go` (`CheckPatchUpstreamStatus`, `PatchStatusResult`) querying issue states across GitHub, GitLab, Gitea, and Bugzilla with a 5-worker bounded concurrency semaphore.
- Added `bugrouter patch check [--json] [--timeout <dur>]` CLI subcommand with tabular formatting and `[READY TO REVERT]` status.
- Added `POST /api/v1/patches/check` and `GET /api/v1/patches?check_upstream=1` endpoints, "Check Upstream Status" button, and `Ready to Revert` badges in Cloud UI.
- Wired issue template introspection into Cloud server `handleCreateDraft` so drafts staged in Web UI trigger `companion_only` status for AI opt-out targets.
- Added `.status-companion` styling, disabled `Approve` button for `companion_only` drafts, and rendered prominent Maintainer Empathy banner with checklist rules and manual submission link in review modal.
- Added `check_dependency_patches` as the 15th MCP tool in `internal/mcp/server.go`, completing the full 15 MCP tools suite.

### Milestone 9: GitHub Actions Matrix, CI/CD Pipeline & Automated CalVer Release [COMPLETED]
- Multi-OS Strategy Matrix (`.github/workflows/ci.yml`) across Ubuntu, macOS, and Windows with Go 1.22.x, supply-chain zero-dependency validation, code formatting gate, `go vet`, `go test -race -v`, and static binary compilation.
- Reproducible CalVer Release Automation (`.github/workflows/release.yml`) cross-compiling static binaries for Linux (amd64/arm64), macOS (amd64/arm64), and Windows (amd64) with `SHA256SUMS` and automated GitHub Release publishing.
- Turnkey Composite GitHub Action (`action.yml`) in repository root enabling CI runners to execute `patch-check` (with `fail-on-revertable: true`) and `triage` modes, rendering rich step summaries in `$GITHUB_STEP_SUMMARY`.
- `Makefile` release dry-run (`make release-dry-run`) compiling all 5 platform targets and generating `SHA256SUMS`.

### Milestone 9.1: Final Release Hardening (`v2026.10.0`), Windows CI Permission Fix, Action Security & Cloud Parked-to-Draft Hydration [COMPLETED]
- Hardened `action.yml` against bash script injection by binding all action inputs directly to `env:` variables.
- Eliminated Windows CI race ignore (`|| true`) and guarded all POSIX `0600` test assertions across the codebase with `if runtime.GOOS != "windows"`.
- Completed the Parked Bug -> Staged Draft full lifecycle in the Cloud Control Plane (`POST /api/v1/drafts` with `parked_id` and `related_dependency`), auto-transitioning parked bugs to `"triaged"` upon draft staging and filtering triaged bugs from `GET /api/v1/parked` unless `?all=1` is requested.
- Extended Cloud UI Guided Report Composer with cross-dependency search and 1-click parked bug promotion.

### Milestone 10: Workspace Patch Scanner (`patch scan`), Root License & Release Finalization (`v2026.10.0`) [COMPLETED]
- Built Workspace Patch Scanner in `internal/adapter/patch_scan.go` (`ScanWorkspacePatches`, `PatchStore.SyncWorkspace`), automatically detecting local overrides, forks, and patches across `go.mod` (`replace` directives), `package.json` (`patch:`, `file:`, `link:`, `git+` dependencies/resolutions), `patches/` directory (`*.patch` diffs), `Cargo.toml` (`[patch.<source>]`), and `pyproject.toml` (`[tool.poetry.dependencies]` paths/git).
- Added `bugrouter patch scan [--dir <path>] [--json]` CLI subcommand with tabular output and deduplication against existing ledger entries.
- Added `POST /api/v1/patches/scan` endpoint in Cloud Control Plane daemon with audit logging (`patch.scanned`) and a "Scan Workspace Manifests" button in the Web UI Active Dependency Patches banner.
- Added `scan_workspace_patches` as the 17th tool in `internal/mcp/server.go`, allowing MCP coding agents to automatically discover and register workspace patches.
- Added `list_parked_bugs` (tool 16) and `from_parked_id` hydration with auto-triage transition in `draft_bug_report`.
- Added root `LICENSE` file under the MIT License, Copyright (c) 2026 Ricardo Veronese Ricci.

