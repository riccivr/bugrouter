# ARCHITECTURE_STATE.md — bugrouter System Architecture & Handoff

Current CalVer: **2026.10.0**  
Status: **Milestone 4 Spec 09.1 Completed** (Post-Spec #09 Red-Team Remediation + v1.0 Release Lock + SSRF Env Bypass Removal + Body File Subheading Preservation + Scrubber Trailing Quote Handling)

---

## 1. System Overview

`bugrouter` is an autonomous, zero-dependency Go CLI and Model Context Protocol (MCP) server that resolves arbitrary software artifacts (local dependencies, OS packages, ecosystem libraries, and SaaS domains) to their canonical upstream bug trackers, scrubs sensitive credentials at the type level, introspects upstream issue templates, identifies upstream duplicate issues, and stages structured bug tickets for Human-in-the-Loop review.

---

## 2. Package Map

| Package | Path | Purpose & Responsibilities |
| :--- | :--- | :--- |
| `main` | `cmd/bugrouter/main.go` | Entrypoint providing `version`, `resolve`, `draft`, `serve`, and `mcp` subcommands with disk caching, bounded execution (`--timeout`), `--body-file` with stdin support, graceful shutdown, duplicate detection warnings, and flag orchestration. |
| `version` | `internal/version/version.go` | CalVer version constant (`2026.10.0`) and canonical `User-Agent` generator. |
| `httpx` | `internal/httpx/client.go` | Bounded HTTP client enforcing 2 MiB body caps, timeouts, rate limiting (`429`/`503` retry handling), and SSRF/DNS-rebinding protection against private/loopback/link-local addresses. |
| `cache` | `internal/cache/disk.go` | Zero-dependency local TTL disk cache backed by `$XDG_CACHE_HOME/bugrouter/targets` with SHA-256 key hashing and atomic file replacement. |
| `resolver` | `internal/resolver/` | 6-layer waterfall resolution engine: `OrgCloudProbe` (enterprise catalog/monorepo ownership), `DirectProbe`, `WorkspaceProbe` (`node_modules`, `go.mod`, `Cargo.toml`/`Cargo.lock`, `pyproject.toml`), `OSPackageProbe` (Debian `dpkg`/`apt`, Fedora/RHEL `rpm`, Arch `pacman`), `RegistryProbe` (`npm`, `PyPI`, `Crates.io`), and `WebDomainProbe` (`.well-known/bug-report`, RFC 9116 `security.txt`). Strict hostname classification for GitHub, GitLab, Codeberg, SourceHut, Bugzilla, Debbugs, Jira, and Linear. Wires optional `TargetCache` into resolution lifecycle. |
| `introspector` | `internal/introspector/` | Discovers and parses upstream issue templates across GitHub (YAML Issue Forms and Markdown), GitLab (Markdown templates), and Bugzilla (REST schemas `/rest/product` and `/rest/field/bug`) with enterprise host API base URL derivation and zero external dependencies. |
| `dedup` | `internal/dedup/` | Queries upstream trackers (GitHub, GitLab, Bugzilla) for existing duplicate bug reports using token overlap scoring, stop word filtering, keyword extraction, and enterprise forge API base URL derivation. |
| `scrubber` | `internal/scrubber/scrubber.go` | Deterministic secret and PII redactor producing `ScrubbedText`. Strips PEM private keys, Bearer tokens, AWS/GitHub/OpenAI/Stripe/Slack keys, generic config assignments (>= 6 chars, preserving non-secret literals like `true`/`false`/`null`/`nil`), URI credentials, and `/home/*` or `/Users/*` paths. |
| `adapter` | `internal/adapter/draft.go` | Sanitizes titles against RFC-822 header injection, maps upstream template schemas to Markdown sections (`### <Label>`), attaches potential upstream duplicate tickets, generates deep-link submission URLs (GitHub issue form query parameters, GitLab `issuable_template`, Bugzilla `enter_bug.cgi`), RFC-822 Debbugs emails with pseudo-headers, and atomically stages tickets with `0600` permissions via `DraftStore`. |
| `cloud` | `internal/cloud/` | Zero-dependency Cloud Control Plane HTTP daemon (`Server`) with embedded single-page Web UI for Human-in-the-Loop review queues (`/api/v1/health`, `/api/v1/drafts`, `/api/v1/drafts/{id}/approve`, `/api/v1/drafts/{id}/discard`, `/api/v1/audit`), audit trail display panel, constant-time Bearer token auth, CSRF/origin guard, append-only JSONL audit logging (`AuditLogger`), SSRF-guarded HMAC webhook dispatcher (`WebhookNotifier`), and authenticated OAuth enterprise forge connectors (`ForgeClient`). |
| `mcp` | `internal/mcp/server.go` | Zero-dependency JSON-RPC 2.0 stdio server implementing Model Context Protocol (spec `2024-11-05`), publishing `resolve_target`, `scrub_text`, `draft_bug_report`, `introspect_template`, `search_duplicates`, `list_staged_drafts`, and `approve_draft` tools (total: 7 tools). Automatically benefits from XDG disk caching. |

---

## 3. Implemented Interfaces & Execution Flow

### Waterfall Resolution Priority

1. **`org-cloud` (`LayerOrgCloud`)**: Evaluates enterprise service catalog and monorepo ownership records configured via `$XDG_CONFIG_HOME/bugrouter/services.json` (or `/etc/bugrouter/services.json`, or `BUGROUTER_SERVICES_FILE`) before any public probes.
2. **`direct-url` (`LayerWebDomain`)**: Matches explicit URLs and repository paths (`github.com/org/repo`, `gitlab.com/...`, `codeberg.org/...`, `sr.ht/...`). Rejects generic domain roots (`https://stripe.com`) so they fall through to web discovery.
3. **`workspace` (`LayerWorkspace`)**: Inspects local `node_modules/<pkg>/package.json` (with strict name validation against directory traversal), parses `go.mod` `require` blocks, parses Rust `Cargo.toml`/`Cargo.lock` dependencies and package manifests, and parses Python `pyproject.toml` (PEP 508 dependencies, Poetry git dependencies, and project URLs).
4. **`os-pkg` (`LayerOSPackage`)**: Resolves system binaries and packages across Debian/Ubuntu (`which`, `dpkg -S`, `dpkg-query -W`, `apt-cache show`), Fedora/RHEL (`rpm -qf`, `rpm -qi`), and Arch Linux (`pacman -Qoq`, `pacman -Qi`), prioritizing upstream source homepages over downstream distro trackers.
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
