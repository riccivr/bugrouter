# ARCHITECTURE_STATE.md — bugrouter System Architecture & Handoff

Current CalVer: **2026.10.0**  
Status: **Milestone 2 Spec 06 Completed** (WorkOS-Style Org Discovery + Cloud Control Plane Server + Human-in-the-Loop Web UI + OAuth Enterprise Connectors + MCP Tooling)

---

## 1. System Overview

`bugrouter` is an autonomous, zero-dependency Go CLI and Model Context Protocol (MCP) server that resolves arbitrary software artifacts (local dependencies, OS packages, ecosystem libraries, and SaaS domains) to their canonical upstream bug trackers, scrubs sensitive credentials at the type level, introspects upstream issue templates, and stages structured bug tickets for Human-in-the-Loop review.

---

## 2. Package Map

| Package | Path | Purpose & Responsibilities |
| :--- | :--- | :--- |
| `main` | `cmd/bugrouter/main.go` | Entrypoint providing `version`, `resolve`, `draft`, `serve`, and `mcp` subcommands with disk caching and flag orchestration. |
| `version` | `internal/version/version.go` | CalVer version constant (`2026.10.0`) and canonical `User-Agent` generator. |
| `httpx` | `internal/httpx/client.go` | Bounded HTTP client enforcing 2 MiB body caps, timeouts, rate limiting (`429`/`503` retry handling), and SSRF/DNS-rebinding protection against private/loopback/link-local addresses. |
| `cache` | `internal/cache/disk.go` | Zero-dependency local TTL disk cache backed by `$XDG_CACHE_HOME/bugrouter/targets` with SHA-256 key hashing and atomic file replacement. |
| `resolver` | `internal/resolver/` | 6-layer waterfall resolution engine: `OrgCloudProbe` (enterprise catalog/monorepo ownership), `DirectProbe`, `WorkspaceProbe` (`node_modules`, `go.mod`), `OSPackageProbe` (`dpkg`, `apt`), `RegistryProbe` (`npm`, `PyPI`, `Crates.io`), and `WebDomainProbe` (`.well-known/bug-report`, RFC 9116 `security.txt`). Strict hostname classification for GitHub, GitLab, Codeberg, SourceHut, Bugzilla, Debbugs, Jira, and Linear. Wires optional `TargetCache` into resolution lifecycle. |
| `introspector` | `internal/introspector/` | Discovers and parses upstream issue templates across GitHub (YAML Issue Forms and Markdown), GitLab (Markdown templates), and Bugzilla (REST schemas `/rest/product` and `/rest/field/bug`) with zero external dependencies. |
| `scrubber` | `internal/scrubber/scrubber.go` | Deterministic secret and PII redactor producing `ScrubbedText`. Strips PEM private keys, Bearer tokens, AWS/GitHub/OpenAI/Stripe/Slack keys, generic config assignments, URI credentials, and `/home/*` or `/Users/*` paths. |
| `adapter` | `internal/adapter/draft.go` | Sanitizes titles against RFC-822 header injection, maps upstream template schemas to Markdown sections (`### <Label>`), generates deep-link submission URLs (GitHub issue form query parameters, GitLab `issuable_template`, Bugzilla `enter_bug.cgi`), RFC-822 Debbugs emails with pseudo-headers, and atomically stages tickets with `0600` permissions via `DraftStore`. |
| `cloud` | `internal/cloud/` | Zero-dependency Cloud Control Plane HTTP daemon (`Server`) with embedded single-page Web UI for Human-in-the-Loop review queues (`/api/v1/health`, `/api/v1/drafts`, `/api/v1/drafts/{id}/approve`, `/api/v1/drafts/{id}/discard`), and authenticated OAuth enterprise forge connectors (`ForgeClient` supporting GitHub Enterprise, GitLab Self-Managed, Jira REST, and Linear GraphQL). |
| `mcp` | `internal/mcp/server.go` | Zero-dependency JSON-RPC 2.0 stdio server implementing Model Context Protocol (spec `2024-11-05`), publishing `resolve_target`, `scrub_text`, `draft_bug_report`, `introspect_template`, `list_staged_drafts`, and `approve_draft` tools. Automatically benefits from XDG disk caching. |

---

## 3. Implemented Interfaces & Execution Flow

### Waterfall Resolution Priority

1. **`org-cloud` (`LayerOrgCloud`)**: Evaluates enterprise service catalog and monorepo ownership records configured via `$XDG_CONFIG_HOME/bugrouter/services.json` (or `/etc/bugrouter/services.json`, or `BUGROUTER_SERVICES_FILE`) before any public probes.
2. **`direct-url` (`LayerWebDomain`)**: Matches explicit URLs and repository paths (`github.com/org/repo`, `gitlab.com/...`, `codeberg.org/...`, `sr.ht/...`). Rejects generic domain roots (`https://stripe.com`) so they fall through to web discovery.
3. **`workspace` (`LayerWorkspace`)**: Inspects local `node_modules/<pkg>/package.json` (with strict name validation against directory traversal) and parses `go.mod` `require` blocks (ignoring `replace`, `exclude`, `retract`, and `tool` blocks).
4. **`os-pkg` (`LayerOSPackage`)**: Resolves system binaries and packages via `which`/`exec.LookPath`, `dpkg -S`, `dpkg-query -W`, and `apt-cache show`, with pipe buffer deadlock guards.
5. **`registry` (`LayerRegistry`)**: Queries public package registries (`npm`, `PyPI`, `Crates.io`) concurrently with `sync.WaitGroup`, returning results in deterministic `0 -> 1 -> 2` priority order in $1 \times T$ latency.
6. **`web-domain` (`LayerWebDomain`)**: Probes web hostnames via `/.well-known/bug-report` JSON and falls back to RFC 9116 `/.well-known/security.txt` `Contact:` lines.

### Template Introspection & Ticket Staging Pipeline

```
Raw Input (Agent / User)
       │
       ▼
[resolver.Waterfall] (with TargetCache hit/miss) ──► Target
       │
       ▼
[introspector.Introspect] ──► TemplateSchema (GitHub Form / Markdown / Bugzilla)
       │
       ▼
[scrubber.Scrub] ──► Produces ScrubbedText (Redacts keys, tokens, URIs, user paths)
       │
       ▼
[adapter.BuildDraft] ──► Maps Fields to ### <Label> Headings + Prefixes + Query Params
       │
       ▼
[adapter.DraftStore] ──► Atomic write to $XDG_DATA_HOME/bugrouter/drafts/<id>.json (mode 0600)
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
