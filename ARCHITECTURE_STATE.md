# ARCHITECTURE_STATE.md — bugrouter System Architecture & Handoff

Current CalVer: **2026.10.0**  
Status: **Milestone 5 Spec #11 Completed** (Native MCP Handoff (`park_bug` + MCP Resources/Prompts + `notifications/resources/list_changed`) & WorkOS-Style Plug-and-Play Dependency Catalog + 12 MCP Tools)

---

## 1. System Overview

`bugrouter` is an autonomous, zero-dependency Go CLI and Model Context Protocol (MCP) server that resolves arbitrary software artifacts (local dependencies, OS packages, ecosystem libraries, and SaaS domains) to their canonical upstream bug trackers, scrubs sensitive credentials at the type level, introspects upstream issue templates, identifies upstream duplicate issues, and stages structured bug tickets for Human-in-the-Loop review.

---

## 2. Package Map

| Package | Path | Purpose & Responsibilities |
| :--- | :--- | :--- |
| `main` | `cmd/bugrouter/main.go` | Entrypoint providing `version`, `resolve`, `draft` (with `--from-parked <id>`), `park`, `agent`, `stack`, `telemetry`, `report`, `serve`, and `mcp` subcommands with disk caching, bounded execution (`--timeout`), `--body-file` with stdin support, autonomous crash triage (`bugrouter agent triage`), bounded self-verification (`bugrouter agent verify`), `--verify-cmd` draft attachment, local hardware telemetry (`bugrouter telemetry`, `bugrouter draft --with-telemetry`), workspace dependency inventory & downstream bug radar (`bugrouter stack`), graceful shutdown, duplicate detection warnings, and flag orchestration. |
| `version` | `internal/version/version.go` | CalVer version constant (`2026.10.0`) and canonical `User-Agent` generator. |
| `httpx` | `internal/httpx/client.go` | Bounded HTTP client enforcing 2 MiB body caps, timeouts, rate limiting (`429`/`503` retry handling), and SSRF/DNS-rebinding protection against private/loopback/link-local addresses. |
| `cache` | `internal/cache/disk.go` | Zero-dependency local TTL disk cache backed by `$XDG_CACHE_HOME/bugrouter/targets` with SHA-256 key hashing and atomic file replacement. |
| `resolver` | `internal/resolver/` | 6-layer waterfall resolution engine: `OrgCloudProbe` (enterprise catalog/monorepo ownership), `DirectProbe`, `WorkspaceProbe` (`node_modules`, `go.mod`, `Cargo.toml`/`Cargo.lock`, `pyproject.toml`), `OSPackageProbe` (Debian `dpkg`/`apt`, Fedora/RHEL `rpm`, Arch `pacman`, Linux `flatpak`, `snap`, Windows `winget`), `RegistryProbe` (`npm`, `PyPI`, `Crates.io`), and `WebDomainProbe` (`.well-known/bug-report`, RFC 9116 `security.txt`). Strict hostname classification for GitHub, GitLab, Codeberg, Gitea/Forgejo (`projects.blender.org`, `gitea.com`, `*.gitea.*`, `*.forgejo.*`), SourceHut, Bugzilla, Debbugs, Jira, and Linear. Deterministic Crash & Stack Trace Attribution Engine (`trace.go`) mapping Go, Python, Node.js, Rust, and native segfault traces to culprit symbols and suspect targets. Workspace Tech Stack Scanner (`stack.go`) scanning workspace manifests (`services.json`, `go.mod`, `package.json`, `Cargo.toml`, `pyproject.toml`) and resolving dependencies concurrently. Wires optional `TargetCache` into resolution lifecycle. |
| `verifier` | `internal/verifier/` | Bounded reproduction validator (`Verify`, `VerifyOptions`, `VerificationProof`) executing reproduction shell commands under bounded contexts (256 KiB combined output buffer, timeout handling, exit code matching, candidate extraction, secret redaction, and SHA-256 proof digests). |
| `telemetry` | `internal/telemetry/` | Zero-dependency native hardware and operating system telemetry collector (`SystemTelemetry`: OS, Arch, KernelVersion, CPUModel, NumCPU, GPUs, DesktopEnv, DisplayServer) gathering diagnostic info on Linux (`/proc/cpuinfo`, `/proc/sys/kernel/osrelease`, `lspci`, `/sys/class/drm`), macOS (`sysctl`, `system_profiler`), and Windows (`PROCESSOR_IDENTIFIER`, `wmic`, PowerShell) with type-safe scrubbing and Markdown list formatting. |
| `introspector` | `internal/introspector/` | Discovers and parses upstream issue templates across GitHub (YAML Issue Forms and Markdown), GitLab (Markdown templates), Gitea/Codeberg (`/api/v1/repos/<owner>/<repo>/issue_templates`), and Bugzilla (REST schemas `/rest/product` and `/rest/field/bug`) with enterprise host API base URL derivation and zero external dependencies. |
| `dedup` | `internal/dedup/` | Queries upstream trackers (GitHub, GitLab, Bugzilla, Gitea) for existing duplicate bug reports using token overlap scoring, stop word filtering, keyword extraction, and enterprise forge API base URL derivation. Downstream Bug Radar (`radar.go`: `BuildStackRadar`, `StackRadarEntry`, `StackRadarReport`) querying upstream issue trackers for active bugs matching workspace dependencies via `ListActiveIssues` with version prioritization. Supports private repo auth via `GITLAB_TOKEN`, `GL_TOKEN`, `BUGROUTER_GITLAB_TOKEN`, `GITHUB_TOKEN`, `GITEA_TOKEN`. |
| `scrubber` | `internal/scrubber/scrubber.go` | Deterministic secret and PII redactor producing `ScrubbedText`. Strips PEM private keys, Bearer tokens, AWS/GitHub/OpenAI/Stripe/Slack keys, generic config assignments (>= 6 chars, preserving non-secret literals like `true`/`false`/`null`/`nil`), URI credentials, and `/home/*` or `/Users/*` paths. |
| `adapter` | `internal/adapter/` | Sanitizes titles against RFC-822 header injection, maps upstream template schemas to Markdown sections (`### <Label>`), attaches potential upstream duplicate tickets, generates deep-link submission URLs (GitHub issue form query parameters, GitLab `issuable_template`, Gitea/Codeberg `/issues/new?title=...&body=...`, Bugzilla `enter_bug.cgi`), RFC-822 Debbugs emails with pseudo-headers, and atomically stages tickets with `0600` permissions via `DraftStore`. Houses Zero-Latency Parked Bug Store (`parked.go`: `ParkedBug`, `HandoffPayload`, `ParkedStore`) storing breadcrumbs in `$XDG_DATA_HOME/bugrouter/parked` in `<5ms` with zero network calls and atomic `0600` writes. Integrates `VerificationProof` into drafts with automatic logs fallback and `## Verified Reproduction` section. Integrates `SystemTelemetry` under `## Environment`. Houses Anti-Slop Quality Linter (`linter.go`) evaluating buzzwords, chatbot tells, emojis, em dashes, incomplete placeholders, and awarding +10 bonus for verified reproduction proofs. |
| `cloud` | `internal/cloud/` | Zero-dependency Cloud Control Plane HTTP daemon (`Server`) with embedded single-page Web UI for Human-in-the-Loop review queues (`/api/v1/health`, `/api/v1/drafts`, `/api/v1/drafts/{id}/approve`, `/api/v1/drafts/{id}/discard`, `/api/v1/audit`, `/api/v1/stack`), WorkOS-Style Connected Dependencies & Downstream Services catalog (`/api/v1/services`), Connected Tech Stack & Downstream Radar panel, audit trail display panel, constant-time Bearer token auth, CSRF/origin guard, append-only JSONL audit logging (`AuditLogger`), SSRF-guarded HMAC webhook dispatcher (`WebhookNotifier`), and authenticated OAuth enterprise forge connectors (`ForgeClient`). |
| `mcp` | `internal/mcp/server.go` | Zero-dependency JSON-RPC 2.0 stdio server implementing Model Context Protocol (spec `2024-11-05`), advertising `tools`, `resources` (`listChanged: true`), and `prompts` capabilities. Publishes `park_bug` as first tool (total: 12 tools). Emits `notifications/resources/list_changed` before tool response. Handled `resources/list`, `resources/read` (`bugrouter://parked/<id>`), `prompts/list`, and `prompts/get` (`triage_parked_bug`). Automatically benefits from XDG disk caching. |

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
TemplateSchema                             PotentialDuplicates
       │                                          │
       └────────────────────┬─────────────────────┘
                            │
                            ▼
                     [scrubber.Scrub]
            (Redacts keys, tokens, URIs, paths)
                            │
                            ▼
                   [adapter.BuildDraft]
  (Maps Fields to ### <Label> Headings + Submission URLs + PotentialDuplicates)
                            │
                            ▼
                   [adapter.DraftStore]
    (Atomic write to $XDG_DATA_HOME/bugrouter/drafts/<id>.json, mode 0600)
```

---

## 4. Milestone Status & Progress

### Spec #05: Upstream Issue Template Introspector (COMPLETED)
- Remediated RFC-822 header injection vulnerability in draft titles.
- Wired `TargetCache` into `resolver.Waterfall` and MCP server.
- Built zero-dependency line-oriented YAML and Markdown parsers, Bugzilla schema parser, and upstream introspector client.
- Implemented semantic field mapping and URL pre-fill query parameter adaptation.
- Exposed `introspect_template` tool via MCP.

### Spec #06: WorkOS-Style Org Discovery & Cloud Control Plane Server (COMPLETED)
- Implemented `LayerOrgCloud` enterprise catalog and monorepo ownership probe as Layer 0 in `resolver.Waterfall`.
- Built zero-dependency Cloud Control Plane HTTP server with embedded single-page Web UI for Human-in-the-Loop review queues.
- Implemented authenticated OAuth issue-filing connectors for GitHub Enterprise, GitLab Self-Managed, Jira REST, and Linear GraphQL.
- Added `serve` subcommand in CLI (`cmd/bugrouter/main.go`).
- Exposed `list_staged_drafts` and `approve_draft` tools via MCP server (total: 6 tools).

### Spec #06.1: Post-Milestone 2 Red-Team Security & Parser Remediation (COMPLETED)
- Bound `ForgeClient` with `httpx.PostBytes` enforcing SSRF protection, body caps, and redirect limits.
- Configured explicit timeouts on Cloud Control Plane `http.Server` and added DOM XSS escaping guard on `submission_url`.
- Hardened draft ID validation against path traversal (`..`, `/`, `\`, special characters) across `DraftStore` and server routes.
- Decoupled `ProtocolJira` and `ProtocolLinear` into distinct tracker protocols across resolver and cloud connectors.
- Automatically normalized incomplete `OrgCloudProbe` service entries using `ClassifyTracker`.
- Resolved YAML parser indentation trap on top-level keys after `body:` and fixed empty Bugzilla schema fallback.

### Spec #07: Upstream Issue Deduplicator & Polyglot Workspace/OS Probes (COMPLETED)
- Extended `WorkspaceProbe` to parse Rust manifests (`Cargo.toml` dependencies, workspace dependencies, `Cargo.lock` git sources, and `[package]` checkouts) and Python manifests (`pyproject.toml` PEP 508 dependencies, Poetry git sources, and `[project.urls]`).
- Extended `OSPackageProbe` to query RPM packages (`rpm -qf`, `rpm -qi`) on Fedora/RHEL and Pacman packages (`pacman -Qoq`, `pacman -Qi`) on Arch Linux, prioritizing upstream homepages over downstream bug trackers.
- Implemented `internal/dedup` issue deduplicator with title search term extraction, English stop word filtering, deterministic token overlap scoring, and search integration for GitHub, GitLab, and Bugzilla.
- Integrated duplicate detection into `adapter.DraftInput` and `adapter.StagedDraft`.
- Added duplicate warning section in Cloud Web UI review modal with escaped links and match percentages.
- Added duplicate warning output to `bugrouter draft` CLI command.
- Exposed `search_duplicates` tool in MCP server and updated MCP tool count to 7.

### Spec #07.1: Red-Team Remediation & Parser Hardening (COMPLETED)
- Replaced `extractInlineTableField` with a scanner/splitter enforcing exact key matching outside quotes across Cargo and Poetry inline tables.
- Added PEP 503/508 package name normalization (`normalizePyPkgName`) stripping extras and normalizing delimiters (`-`, `.`) to `_` in `resolvePyproject` while preserving query as `CanonicalName`.
- Added opening array line parsing when `dependencies = [` has inline entries.
- Added enterprise host API base URL derivation in `internal/dedup` for GitHub Enterprise (`/api/v3`) and GitLab Self-Managed.
- Added `dedup` scope to commit-msg hook and `AGENTS.md` engineering constitution.

### Spec #08: Cloud Control Plane Security, Audit Log & Webhook Dispatcher (COMPLETED)
- Hardened Cloud Control Plane with constant-time Bearer token authentication via `crypto/subtle.ConstantTimeCompare` and SHA-256 pre-hashing on protected API endpoints (`/api/v1/drafts...`, `/api/v1/audit`), keeping `/` and `/api/v1/health` public.
- Implemented CSRF origin validation and custom header guard (`X-Bugrouter-Request: 1` or valid Bearer token) on all `POST /api/v1/...` routes.
- Updated embedded Web UI SPA with Bearer token authentication input and session storage persistence.
- Built append-only JSONL `AuditLogger` writing to `$XDG_STATE_HOME/bugrouter/audit.log` with strict `0600` permissions and 1 MiB bounded reverse-chronological retrieval.
- Implemented SSRF-guarded `WebhookNotifier` delivering HMAC-SHA256 signed audit events (`X-Bugrouter-Signature`) with 3-second bounded timeouts.
- Added `--auth-token`, `--audit-log`, and `--webhook-url` CLI flags to `serve` subcommand.

### Spec #09: v1.0 Readiness, CLI Polish, Scrubber Precision & E2E Golden-Path (COMPLETED)
- Scrubber false-positive hardening in `internal/scrubber`: refined generic secret redaction using `genericSecretRegex.ReplaceAllStringFunc` to require at least 6 characters (excluding quotes) and ignore common non-secret literals (`true`, `false`, `null`, `nil`, `none`, `undefined`, `yes`, `no`), preserving boolean configs, flags, and nil assignments.
- CLI polish and bounded execution in `cmd/bugrouter`: added `--timeout` duration flag (default 15s) with `context.WithTimeout` to `resolve` and `draft` commands, wired `context.Context` through `resolveTarget`, and added graceful `SIGINT`/`SIGTERM` server shutdown (5s timeout) in `serve`.
- File and Stdin input support in `cmd/bugrouter draft`: implemented `--body-file` flag (supporting `-` for stdin, bounded by `io.LimitReader` at 512 KiB) with Markdown heading parser `parseMarkdownBodyFile` extracting `## Summary`, `## Steps to Reproduce` / `## Steps`, and `## Logs` / `## Logs & Output`, falling back to full text summary when no recognized headings exist.
- Cloud Control Plane audit trail in `internal/cloud`: added "Recent Audit Trail" table to embedded SPA `indexHTML` fetching `/api/v1/audit` with headers, rendering timestamps, actions, draft IDs, targets, protocols, and escaped clickable URLs or errors, refreshing on load, refresh button, approval, and discard.
- Introspector enterprise API URL derivation: aligned `internal/introspector` with `dedup` and `cloud.ForgeClient` to derive `/api/v3` for GitHub Enterprise and self-managed GitLab hosts.
- Comprehensive end-to-end golden-path integration tests in `cmd/bugrouter/main_test.go`: verified end-to-end flow from `--body-file` parsing, target resolution, template introspection, duplicate detection, draft generation with scrubber redaction, template field mapping, and draft storage serialization with `0600` permissions.

### Spec #09.1: Post-Milestone 4 Red-Team Remediation (COMPLETED)
- Removed `BUGROUTER_ALLOW_PRIVATE_HOSTS` environment bypass in `internal/httpx/client.go` to ensure SSRF and loopback network protections remain unconditional in production binaries.
- Wired shared `*httpx.Client` parameter into `resolveTarget` in `cmd/bugrouter/main.go`, sharing a single bounded HTTP client instance across resolution, introspection, and duplicate detection in `resolve` and `draft` commands.
- Updated `cmd/bugrouter/main_test.go` to use `httpx.NewTestClient(0)` directly without relying on process-level environment variable overrides.
- Fixed subheading drop bug in `cmd/bugrouter/main.go` (`parseMarkdownBodyFile`): ensured level-3+ subheadings (`### ...`) inside active sections (`## Summary`, `## Logs`) are preserved as regular section content rather than resetting the active section.
- Hardened quoted generic secret redaction in `internal/scrubber/scrubber.go`: separated trailing quotes from captured values before evaluating length thresholds and non-secret literals, preserving trailing quotes in redaction replacements (`CLIENT_SECRET="[REDACTED_SECRET]"`) and preventing false-positive redaction on quoted short values (`token="short"`).

### Spec #10: CLI/README Parity, MCP Audit Trail Integration, Idempotent Approval & Private Repo Auth (COMPLETED)
- Updated `bugrouter version` in `cmd/bugrouter/main.go` to output platform target `(%s/%s)` matching documentation parity with `README.md`.
- Added `--webhook-secret` flag to `bugrouter serve` in `cmd/bugrouter/main.go` with fallback to `BUGROUTER_WEBHOOK_SECRET`, updating usage help and `README.md`.
- Implemented idempotent approval guard in `internal/cloud/server.go` (HTTP 409 Conflict with `{"error": "draft already submitted", "issue_url": ...}`) and `internal/mcp/server.go` (`isError: true` stating `"draft is already submitted"`), preventing duplicate ticket submissions.
- Integrated `AuditLogger` and `WebhookNotifier` into `mcp.Server` in `internal/mcp/server.go`, recording `draft.approved` and `draft.submit_failed` audit events from MCP tool invocations with `RemoteIP: "mcp-stdio"`.
- Extended `httpx.Client` with `GetBytesWithHeaders` in `internal/httpx/client.go` to support custom authorization headers.
- Added environment token authentication in `internal/introspector/introspector.go` and `internal/dedup/dedup.go` for GitHub (`GITHUB_TOKEN`, `GH_TOKEN`, `BUGROUTER_GITHUB_TOKEN`) and GitLab (`GITLAB_TOKEN`, `GL_TOKEN`, `BUGROUTER_GITLAB_TOKEN`), resolving access on private enterprise repositories and lifting unauthenticated rate limits.

### Spec #10.1: Post-Spec #10 Red-Team Credential Boundary Remediation (COMPLETED)
- Remediated cross-protocol credential leak in `internal/dedup/dedup.go` (`findBugzilla`): removed extraneous GitLab token environment lookup loop that was forwarding `PRIVATE-TOKEN` headers to Bugzilla servers.
- Hardened cross-host redirect security in `internal/httpx/client.go`: added automated stripping of sensitive authentication headers (`Authorization` and `PRIVATE-TOKEN`) whenever `CheckRedirect` detects a transition across different hostnames (`!strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname())`).
- Scoped GitHub token forwarding in `internal/introspector/introspector.go`: implemented `shouldSendGitHubAuth` ensuring `gitHubAuthHeader()` is only attached to `best.DownloadURL` if the target hostname matches the configured API base URL, `"github.com"`, or `"raw.githubusercontent.com"`, preventing exfiltration to untrusted external mirrors.

### Spec #11: Master ROADMAP.md, CLI Agentic Mode, Crash Log Auto-Attribution & Anti-Slop Gate (COMPLETED)
- Created `ROADMAP.md` in repository root outlining the Three Core Pillars (CLI Agentic Mode, Tech Stack Radar, Everyday Desktop/PC Experience), completed Milestones 1–4 ledger, active Milestone 5, and upcoming Milestones 6–7.
- Implemented deterministic Crash & Stack Trace Attribution Engine in `internal/resolver/trace.go` (`ExtractTargetsFromLog`, `TraceCandidate`), scanning crash logs and extracting up to 5 unique candidate dependencies across Node.js (`node_modules`), Go modules, Python packages (`site-packages`), Rust crates (`.cargo/registry`), and Unix CLI binary error prefixes with secret redaction in evidence snippets.
- Built Deterministic Anti-Slop Quality Linter in `internal/adapter/linter.go` (`LintDraft`, `QualityReport`), calculating a 0 to 100 quality score, assigning grades (`ready`, `needs_detail`, `low_signal`), and rejecting conversational AI filler (`as an ai`, `delve into`, `certainly!`, etc.), short titles (< 3 words), missing steps (< 15 chars), missing summaries (< 20 chars), and missing diagnostic evidence.
- Wired `QualityReport` into `adapter.StagedDraft` and populated it automatically inside `BuildDraft`. Added `--strict-quality` flag to `bugrouter draft` exiting with code 2 on failure.
- Implemented `bugrouter agent triage` subcommand in `cmd/bugrouter/main.go`, reading crash logs from `--log-file` or stdin, extracting candidates, resolving the primary target, introspecting templates, detecting duplicates, and outputting structured JSON agent envelopes (`AgentTriageResult`).
- Exposed `triage_crash_log` as the 8th tool in `internal/mcp/server.go`, returning candidates, resolved target, template schema, potential duplicates, scrubbed log, and actionable next steps.

### Spec #12: Spec #11 Audit Remediation, Agentic Self-Verification & Proof-of-Reproduction Engine (COMPLETED)
- Remediated Spec #11 audit findings: eliminated ignored error check patterns (`_ = ...`) across CLI and tests; aligned GitLab token header parity in `internal/dedup/dedup.go` (`PRIVATE-TOKEN` from `GITLAB_TOKEN`, `GL_TOKEN`, `BUGROUTER_GITLAB_TOKEN`); added `strict_quality`, `verify_cmd`, and `query` parity to MCP server tools and documentation.
- Built Bounded Reproduction Validator in `internal/verifier/verifier.go` (`Verify`, `VerifyOptions`, `VerificationProof`), executing reproduction shell commands under bounded timeouts (default 15s) and 256 KiB output buffers, capturing/scrubbing output, matching exit codes, extracting candidate targets, and generating deterministic SHA-256 proof digests.
- Integrated `VerificationProof` into `adapter.DraftInput`, `adapter.StagedDraft`, `adapter.BuildDraft`, and `adapter.LintDraft`, automatically using verified crash output for draft logs when logs are empty, rendering the `## Verified Reproduction` section in draft markdown bodies, and awarding a +10 quality bonus in the Anti-Slop Linter.
- Implemented `bugrouter agent verify` CLI subcommand and `--verify-cmd` on `bugrouter draft` in `cmd/bugrouter/main.go`.
- Exposed `verify_reproduction` as the 9th tool in `internal/mcp/server.go`, and updated all unit and integration test suites.

### Spec #13: Workspace Tech Stack Scanner, Downstream Bug Radar, Cloud UI Stack Tab & Roadmap Milestone 8 (COMPLETED)
- Updated `ROADMAP.md` marking Milestone 6 (Spec #13) as Completed, Milestone 7 (Desktop/PC User Mode — Spec #14) as Active, and added Milestone 8: GitHub Actions, CI/CD Matrix & Release Automation (Planned — Post-Stabilization) specifying `.github/workflows/ci.yml`, `.github/workflows/release.yml`, and composite `action.yml`.
- Implemented Workspace Tech Stack Scanner in `internal/resolver/stack.go` (`ScanWorkspaceManifests`, `(w *Waterfall) ScanStack`), discovering all project dependencies across enterprise `services.json`, `go.mod`, `package.json`, `Cargo.toml`, and `pyproject.toml` (with PEP 508 parsing), deduplicating by `Ecosystem:Name`, sorting deterministically, and resolving targets concurrently with 8-worker bounded concurrency.
- Implemented Downstream Bug Radar in `internal/dedup/radar.go` (`BuildStackRadar`, `StackRadarEntry`, `StackRadarReport`), querying canonical upstream trackers (GitHub, GitLab, Bugzilla) with 5-worker bounded concurrency to find active upstream bugs impacting local workspace dependencies.
- Added `bugrouter stack` CLI subcommand in `cmd/bugrouter/main.go` supporting `--dir`, `--check-upstream`, `--json`, `--no-cache`, and `--timeout`.
- Added `GET /api/v1/stack` endpoint and "Connected Tech Stack & Downstream Radar" interactive dashboard tab in `internal/cloud/server.go` (`indexHTML`), wired via `srv.WithStackScanner(wf, finder, ".")` in `main.go`.
- Exposed `scan_workspace_stack` as the 10th tool in `internal/mcp/server.go` with full schema and execution handler.

### Spec #13.1: Security & Radar Precision Remediation (COMPLETED)
- Removed arbitrary `?dir=` parameter override in `internal/cloud/server.go` (`handleStack`), guaranteeing that remote HTTP clients cannot traverse arbitrary host directories and always scan `s.stackDir`. Wrapped `BuildStackRadar` with a 45-second bounded context timeout, and increased server `WriteTimeout` to 60 seconds to support comprehensive multi-forge radar scans without mid-flight connection resets.
- Replaced noisy duplicate search in `internal/dedup/radar.go` with dedicated `ListActiveIssues(ctx, target, version)` in `internal/dedup/dedup.go`, querying canonical open issues across GitHub (`is:issue is:open`), GitLab (`state=opened`), Bugzilla (`bug_status=NEW&bug_status=ASSIGNED&bug_status=REOPENED`), and Gitea (`type=issues&state=open`) without title token-overlap filtering and prioritizing issues matching the local version (`Score: 1.0`).

### Spec #14: Desktop App Resolver, Gitea/Forgejo Support & Hardware Telemetry Collector (COMPLETED)
- Added `ProtocolGitea Protocol = "gitea"` in `internal/resolver/types.go` and extended `ClassifyTracker` and `DirectProbe` to recognize Gitea and Forgejo instances (`projects.blender.org`, `gitea.com`, and hosts containing `gitea.` or `forgejo.`) with canonical issue URLs (`https://<host>/<owner>/<repo>/issues`).
- Integrated pre-filled deep links for `ProtocolGitea` in `internal/adapter/draft.go` (`/issues/new?title=...&body=...`) and REST API duplicate detection and issue introspection.
- Extended `OSPackageProbe` (`internal/resolver/ospkg.go`) with desktop application resolvers for Linux `flatpak` (`flatpak info <query>`), Linux `snap` (`snap info <query>`), and Windows `winget` (`winget show [--id] <query>`) using bounded subprocess execution and pure deterministic output parsers (`parseFlatpakInfo`, `parseSnapInfo`, `parseWingetShow`).
- Created zero-dependency hardware and OS telemetry collector in `internal/telemetry/telemetry.go` (`Collect`, `SystemTelemetry`, `FormatMarkdown`), probing OS, CPU model, core counts, kernel version, GPUs, desktop environment, and display servers on Linux, macOS, and Windows with type-safe credential and path scrubbing.
- Integrated telemetry into `adapter.DraftInput` and `adapter.StagedDraft`, automatically rendering hardware diagnostic lists under the `## Environment` section of generated bug drafts.
- Added `--with-telemetry` flag to `bugrouter draft`, added `bugrouter telemetry [--json]` subcommand, added `bugrouter agent telemetry`, and exposed `collect_system_telemetry` as the 11th tool in `internal/mcp/server.go` while adding `include_telemetry` to `draft_bug_report`.

### Spec #14.1: Red-Team Security & Constitutional Remediation (COMPLETED)
- Remediated blank identifier assignments (`_ = ...`) across `internal/dedup/dedup.go` (`listActiveGitHub`, `listActiveGitLab`, `listActiveBugzilla`, `listActiveGitea`) and `internal/telemetry/telemetry.go`, ensuring 100% adherence to AGENTS.md explicit error handling standards.
- Added Gitea/Codeberg authentication header support to `introspectGitea` in `internal/introspector/introspector.go` (`giteaAuthHeader`) checking `GITEA_TOKEN`, `BUGROUTER_GITEA_TOKEN`, and `CODEBERG_TOKEN`.
- Added Gitea/Codeberg authenticated issue submission connector in `internal/cloud/client.go` (`ForgeClient.getToken`, `ForgeClient.Submit`, `ForgeClient.submitGitea`) and added unit test coverage in `internal/cloud/client_test.go` (`TestForgeClientGitea`).
- Removed unreachable dead conditional branch under `agent telemetry` in `cmd/bugrouter/main.go`.
- Strengthened Anti-Slop Quality Linter in `internal/adapter/linter.go` (`LintDraft`), adding 15-point deduction and slop flag for em dashes (`—`) and decorative emojis, plus 20-point deduction for unfilled placeholders (`<insert`, `[insert`, `todo:`, `fixme:`), with unit tests in `internal/adapter/linter_test.go`.

### Spec #15: Interactive Guided Human Bug Wizard & Web UI Guided Composer (COMPLETED)
- Implemented `bugrouter report` subcommand and `runGuidedReport(ctx, in, out, httpClient, opts)` in `cmd/bugrouter/main.go`, providing a human-friendly interactive CLI wizard that resolves applications, introspects templates, automatically attaches hardware and OS telemetry by default (unless `--no-telemetry`), prompts line-by-line for missing fields via a single `bufio.Scanner`, checks upstream duplicates, runs real-time anti-slop quality linting, and stages the draft with clickable submission deep links.
- Added deterministic unit tests in `cmd/bugrouter/main_test.go` (`TestGuidedReportWizard`) verifying interactive scanning and staging.
- Added Guided Draft Composer API (`POST /api/v1/drafts`) to `internal/cloud/server.go` (`handleCreateDraft`, `CreateDraftRequest`), protected by Bearer auth and CSRF guard, supporting query resolution, hardware telemetry attachment, duplicate checking, draft staging, audit trail recording (`draft.created`), webhook notification, and strict quality enforcement (returning 422 Unprocessable Entity with `QualityReport`).
- Added "New Guided Report" button and interactive composer modal with hardware telemetry and strict quality options to the Cloud Control Plane Web UI (`indexHTML`).
- Added unit tests in `internal/cloud/server_test.go` (`TestServerCreateDraftEndpoint`) verifying 201 Created staging, 422 Unprocessable Entity rejection, draft store persistence, and audit logging.
- Updated `ROADMAP.md` completing Milestone 7 (Spec #15) and activating Milestone 8 (Spec #16: GitHub Actions CI/CD & CalVer Release Pipeline).

### Spec #11: Native MCP Session Handoff (`park_bug` + MCP Resources/Prompts) & WorkOS-Style Dependency Catalog (COMPLETED)
- Implemented `<5ms`, zero-network-call `ParkedStore` in `internal/adapter/parked.go` (`ParkedBug`, `HandoffPayload`, `ParkedStore`) with 8-character hex IDs (`crypto/rand`), secret scrubbing via `scrubber.Scrub`, and atomic `0600` persistence in `$XDG_DATA_HOME/bugrouter/parked/<id>.json`.
- Implemented `HandoffPayload` providing `ResourceURI` (`bugrouter://parked/<id>`), `MCPPromptName` (`triage_parked_bug`), `CLICommand` (`bugrouter draft --from-parked <id>`), and actionable directives for spawning separate triage sessions.
- Integrated `park_bug` as the primary tool in `internal/mcp/server.go` (12 tools total), advertising `resources: { listChanged: true }` and `prompts: {}` capabilities in `initialize`, emitting `notifications/resources/list_changed` before returning tool response, and serving `resources/list`, `resources/read`, `prompts/list`, and `prompts/get`.
- Created WorkOS-Style Dependency Catalog in `internal/cloud/server.go` with `GET /api/v1/services`, `POST /api/v1/services` (atomic write with `0600` permissions), and `DELETE /api/v1/services/{name}`, protected by Bearer auth and CSRF origin guards.
- Updated Web UI `indexHTML` with 1-click preset dependency cards (Stripe, Supabase, Auth0, Prisma, Next.js, Remix, Redis, Postgres, FFmpeg, Blender), custom service registration modal, and 1-click copyable CLI/MCP snippets (`bugrouter park <name> "<issue>"`).
- Added `bugrouter park` subcommand and `--from-parked <id>` flag on `bugrouter draft` in `cmd/bugrouter/main.go`.
- Added `ResolveOrgCloudConfigPath() string` in `internal/resolver/orgcloud.go` for shared service catalog discovery.
