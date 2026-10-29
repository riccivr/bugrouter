# Project Roadmap

This document outlines the architectural milestones and development plan for bugrouter. It tracks completed milestones, the active milestone, and upcoming milestones.

## Milestone Status Summary

| Milestone | Focus | Status |
| :--- | :--- | :--- |
| Milestone 1 | Foundations and Core Waterfall Resolution | Completed |
| Milestone 2 | Upstream Issue Template Introspection and Cloud Control Plane | Completed |
| Milestone 3 | Upstream Deduplication, Polyglot Ecosystems, and Control Plane Security | Completed |
| Milestone 4 | Production Readiness, CLI Polish, Scrubber Precision, and Security Hardening | Completed |
| Milestone 5 | CLI Agentic Mode and Anti-Slop Quality Gate | Active |
| Milestone 6 | Human Tech-Stack Dependency Radar | Planned |
| Milestone 7 | Everyday Linux and Windows Desktop User Experience | Planned |

---

## Milestone 1: Foundations and Core Waterfall Resolution (Completed)

Milestone 1 established the core resolution, scrubbing, draft staging, and agent protocol foundations.

### Implemented Capabilities
- Six-layer resolution waterfall:
  - Direct repository and forge URLs (GitHub, GitLab, Codeberg, SourceHut).
  - Local workspace dependency manifests (`node_modules`, `go.mod`).
  - System package managers on Debian and Ubuntu (`dpkg`, `apt`).
  - Concurrent registry probes for npm, PyPI, and Crates.io.
  - Web domain discovery via `/.well-known/bug-report` and RFC 9116 `security.txt`.
- Type-safe secret and PII scrubber producing immutable `ScrubbedText`, redacting AWS keys, GitHub tokens, Slack tokens, OpenAI keys, PEM private keys, URI credentials, and local home directory paths.
- Local draft staging engine (`DraftStore`) writing JSON records with `0600` permissions to `$XDG_DATA_HOME/bugrouter/drafts`.
- Initial Model Context Protocol (MCP) server running over JSON-RPC 2.0 stdio, publishing `resolve_target`, `scrub_text`, and `draft_bug_report`.
- Bounded HTTP client (`httpx.Client`) enforcing 2 MiB body caps, bounded timeouts, redirect limits, and SSRF protection against private, loopback, and link-local IP addresses.

---

## Milestone 2: Upstream Issue Template Introspection and Cloud Control Plane (Completed)

Milestone 2 introduced automated upstream schema discovery and human-in-the-loop review capabilities.

### Implemented Capabilities
- Upstream template introspector discovering and parsing:
  - GitHub YAML Issue Forms and Markdown issue templates.
  - GitLab Markdown issue templates.
  - Bugzilla REST schemas (`/rest/product` and `/rest/field/bug`).
- Enterprise organization service catalog probe (`LayerOrgCloud`) reading `services.json` to route internal microservices and monorepos to private issue trackers.
- Cloud control plane HTTP daemon (`bugrouter serve`) with an embedded single-page application for reviewing and submitting staged bug reports.
- Authenticated issue submission connectors for GitHub Enterprise, GitLab Self-Managed, Jira REST, and Linear GraphQL.
- Decoupled Jira and Linear protocols, reinforced SSRF guards, and protected draft store paths against traversal attacks.
- Added MCP tools `introspect_template`, `list_staged_drafts`, and `approve_draft`.

---

## Milestone 3: Upstream Deduplication, Polyglot Ecosystems, and Control Plane Security (Completed)

Milestone 3 expanded language ecosystem support, added duplicate issue detection, and hardened server security.

### Implemented Capabilities
- Polyglot workspace probes parsing Rust `Cargo.toml`/`Cargo.lock` dependencies and Python `pyproject.toml` manifests (PEP 508 dependencies, Poetry git sources, and project URLs).
- Cross-distribution package manager probes for Fedora/RHEL (`rpm`) and Arch Linux (`pacman`), prioritizing upstream source homepages over downstream bug trackers.
- Upstream issue deduplication engine (`internal/dedup`) using title keyword extraction, English stop word filtering, and deterministic token overlap scoring against GitHub, GitLab, and Bugzilla issues.
- Control plane security hardening:
  - Constant-time Bearer token authentication via `crypto/subtle.ConstantTimeCompare` with SHA-256 pre-hashing.
  - CSRF origin and custom request header verification.
  - Append-only JSONL audit logger (`audit.log`) with bounded reverse retrieval.
  - SSRF-guarded HMAC-SHA256 signed webhook dispatcher (`X-Bugrouter-Signature`).
- Added MCP tool `search_duplicates`.

---

## Milestone 4: Production Readiness, CLI Polish, Scrubber Precision, and Boundary Hardening (Completed)

Milestone 4 focused on production stability, boundary remediation, and end-to-end integration.

### Implemented Capabilities
- Scrubber false-positive prevention: refined generic secret regex to enforce a minimum length of 6 characters and preserve boolean, nil, and null literals.
- CLI polish:
  - Bounded context timeouts (`--timeout`, default 15s) across `resolve` and `draft` commands.
  - Markdown body file and stdin support (`--body-file`) with automatic level-2 heading extraction.
  - Graceful signal handling (`SIGINT`, `SIGTERM`) with bounded shutdown timeouts.
- Idempotent approval guard returning HTTP 409 Conflict in cloud server and error status in MCP, preventing duplicate ticket submissions.
- MCP audit integration recording `draft.approved` and `draft.submit_failed` events with stdio remote IP markers.
- Enterprise forge authentication scoping: added token authentication for private GitHub and GitLab repositories, restricted GitHub auth headers to trusted domains, and stripped credentials on cross-host redirects.

---

## Milestone 5: CLI Agentic Mode and Anti-Slop Quality Gate (Active)

Milestone 5 brings headless autonomous triage, deterministic crash attribution, and quality filtering to bugrouter.

### Core Objectives
- Deterministic Crash and Stack Trace Attribution Engine (`internal/resolver/trace.go`):
  - Parse crash logs and stack traces across Go panics, Python tracebacks, Node.js errors, Rust panics, and native segfaults.
  - Identify culprit source files, line numbers, failing functions, and candidate upstream dependencies.
  - Rank candidate targets and resolve them against the waterfall engine.
- Anti-Slop Quality Linter (`internal/adapter/linter.go`):
  - Detect AI filler words, puffery, and banned buzzwords.
  - Reject chatbot conversational phrases, em dashes, curly quotes, decorative emojis, and unfilled placeholders.
  - Enforce minimum length and specificity standards on issue titles, summaries, and reproduction steps.
- Headless Agentic CLI (`bugrouter agent`):
  - Autonomous pipeline reading crash logs from files or stdin, attributing failures, resolving canonical trackers, building drafts, and running quality checks.
  - Strict quality flag (`--strict-quality`) blocking draft staging when violations occur.
- MCP Tool `triage_crash_log`:
  - Expose crash log triage and attribution directly to coding agents over MCP.

---

## Milestone 6: Human Tech-Stack Dependency Radar (Planned)

Milestone 6 expands bugrouter from reactive triage to proactive dependency health tracking and visibility.

### Planned Capabilities
- Dependency Radar Scanner:
  - Deep workspace scanning across polyglot manifests to build a complete local dependency graph.
  - Direct mapping of all direct and transitive dependencies to their upstream issue trackers and repository release feeds.
- Upstream Velocity and Health Metrics:
  - Check open issue volume, median resolution time, commit activity, and maintenance status.
  - Flag abandoned, archived, or unmaintained upstream packages before critical failures occur.
- Security and Advisory Correlation:
  - Cross-reference resolved dependencies with public advisory databases without adding external runtime dependencies.
  - Automated draft generation when an installed package has a reported vulnerability or breaking patch.
- Proactive Alerts:
  - CLI subcommand (`bugrouter radar`) providing a terminal summary of tech-stack health and tracker endpoints.

---

## Milestone 7: Everyday Linux and Windows Desktop User Experience (Planned)

Milestone 7 makes bugrouter accessible to desktop developers and everyday users across Linux and Windows environments.

### Planned Capabilities
- Desktop Crash Interceptor:
  - Optional lightweight background watcher monitoring system journals (`systemd-coredump`, Linux `/var/log/syslog`) and Windows Event Logs (`Application Error` events).
  - Desktop notifications prompting user review when a native desktop application crashes.
- One-Click Desktop Triage UI:
  - Local desktop dialog or tray interface displaying crash attribution, scrubbed logs, and canonical upstream bug trackers.
  - One-click button to open pre-filled browser submission URLs or stage tickets in the local review queue.
- Interactive Terminal UI (TUI):
  - Terminal-based interactive dashboard for browsing staged drafts, viewing audit logs, and inspecting dependency health directly inside tmux or terminal windows.
- Native Cross-Platform Distribution:
  - Native packaging (.deb, .rpm, Arch PKGBUILD, Windows MSI/winget manifest) for standard package manager installations.
