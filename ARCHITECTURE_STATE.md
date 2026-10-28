# ARCHITECTURE_STATE.md — bugrouter System Architecture & Handoff

Current CalVer: **2026.10.0**  
Status: **Milestone 1 Completed** (CLI + Waterfall Resolver + Red-Team Hardening + Secret Scrubber + Draft Adapter + Stdio MCP Server)

---

## 1. System Overview

`bugrouter` is an autonomous, zero-dependency Go CLI and Model Context Protocol (MCP) server that resolves arbitrary software artifacts (local dependencies, OS packages, ecosystem libraries, and SaaS domains) to their canonical upstream bug trackers, scrubs sensitive credentials at the type level, and stages structured bug tickets for Human-in-the-Loop review.

---

## 2. Package Map

| Package | Path | Purpose & Responsibilities |
| :--- | :--- | :--- |
| `main` | `cmd/bugrouter/main.go` | Entrypoint providing `version`, `resolve`, `draft`, and `mcp` subcommands with disk caching and flag orchestration. |
| `version` | `internal/version/version.go` | CalVer version constant (`2026.10.0`) and canonical `User-Agent` generator. |
| `httpx` | `internal/httpx/client.go` | Bounded HTTP client enforcing 2 MiB body caps, timeouts, rate limiting (`429`/`503` retry handling), and SSRF/DNS-rebinding protection against private/loopback/link-local addresses. |
| `cache` | `internal/cache/disk.go` | Zero-dependency local TTL disk cache backed by `$XDG_CACHE_HOME/bugrouter/targets` with SHA-256 key hashing and atomic file replacement. |
| `resolver` | `internal/resolver/` | 5-layer waterfall resolution engine: `DirectProbe`, `WorkspaceProbe` (`node_modules`, `go.mod`), `OSPackageProbe` (`dpkg`, `apt`), `RegistryProbe` (`npm`, `PyPI`, `Crates.io`), and `WebDomainProbe` (`.well-known/bug-report`, RFC 9116 `security.txt`). Strict hostname classification for GitHub, GitLab, Codeberg, SourceHut, Bugzilla, and Debbugs. |
| `scrubber` | `internal/scrubber/scrubber.go` | Deterministic secret and PII redactor producing `ScrubbedText`. Strips PEM private keys, Bearer tokens, AWS/GitHub/OpenAI/Stripe/Slack keys, generic config assignments, URI credentials, and `/home/*` or `/Users/*` paths. |
| `adapter` | `internal/adapter/draft.go` | Builds structured bug drafts, generates deep-link submission URLs (GitHub/GitLab/Codeberg) and RFC-822 Debbugs emails with pseudo-headers, and atomically stages tickets with `0600` permissions via `DraftStore`. |
| `mcp` | `internal/mcp/server.go` | Zero-dependency JSON-RPC 2.0 stdio server implementing the Model Context Protocol (spec `2024-11-05`), publishing `resolve_target`, `scrub_text`, and `draft_bug_report` tools. |

---

## 3. Implemented Interfaces & Execution Flow

### Waterfall Resolution Priority

1. **`direct-url` (`LayerWebDomain`)**: Matches explicit URLs and repository paths (`github.com/org/repo`, `gitlab.com/...`, `codeberg.org/...`, `sr.ht/...`). Rejects generic domain roots (`https://stripe.com`) so they fall through to web discovery.
2. **`workspace` (`LayerWorkspace`)**: Inspects local `node_modules/<pkg>/package.json` (with strict name validation against directory traversal) and parses `go.mod` `require` blocks (ignoring `replace`, `exclude`, `retract`, and `tool` blocks).
3. **`os-pkg` (`LayerOSPackage`)**: Resolves system binaries and packages via `which`/`exec.LookPath`, `dpkg -S`, `dpkg-query -W`, and `apt-cache show`, with pipe buffer deadlock guards.
4. **`registry` (`LayerRegistry`)**: Queries public package registries (`npm`, `PyPI`, `Crates.io`) concurrently with `sync.WaitGroup`, returning results in deterministic `0 -> 1 -> 2` priority order in $1 \times T$ latency.
5. **`web-domain` (`LayerWebDomain`)**: Probes web hostnames via `/.well-known/bug-report` JSON and falls back to RFC 9116 `/.well-known/security.txt` `Contact:` lines.

### Secret Redaction & Ticket Staging Pipeline

```
Raw Input (Agent / User)
       │
       ▼
[scrubber.Scrub] ──► Produces ScrubbedText (Redacts keys, tokens, URIs, user paths)
       │
       ▼
[adapter.BuildDraft] ──► Formats MarkdownBody + SubmissionURL / DebbugsEmail
       │
       ▼
[adapter.DraftStore] ──► Atomic write to $XDG_DATA_HOME/bugrouter/drafts/<id>.json (mode 0600)
```

---

## 4. Next Milestone: Milestone 2

### Spec #05: Upstream Issue Template Introspector
- Introspect remote repository issue templates (`.github/ISSUE_TEMPLATE/*.yml`, `.github/ISSUE_TEMPLATE/*.md`, `.gitlab/issue_templates/*.md`).
- Parse structured form fields (dropdowns, checkboxes, textareas) and Bugzilla mandatory component schemas.
- Map `DraftInput` fields directly to target-specific template schemas.

### Spec #06: WorkOS-Style Org Discovery & Cloud Control Plane Server
- Implement `LayerOrgCloud` probe: query private internal enterprise service catalogs and monorepo ownership registries before public waterfalls.
- Stand up the Cloud Control Plane server with Web UI Human-in-the-Loop approval queues.
- Add OAuth Connectors for authenticated, non-interactive issue filing to GitHub Enterprise, GitLab Self-Managed, Jira, and Linear.
