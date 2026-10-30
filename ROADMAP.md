# ROADMAP.md — bugrouter Project Roadmap & Vision

This document tracks the long-term architectural trajectory, active implementation focus, and milestone ledger for `bugrouter`. It serves as the authoritative cross-session plan for all Architect and Implementer sessions.

---

## 1. Core Product Philosophy

`bugrouter` is built on four core principles defined by the Principal Architect:

1. **On-Demand Companion (Zero Resident Daemon):**
   `bugrouter` is designed never to run as a bloated, background-polling daemon burning idle CPU and memory. It operates as a zero-overhead companion invoked only at the precise moment a bug or crash occurs—via fast CLI commands, native Model Context Protocol (MCP) tool invocations, or reading zero-idle OS post-mortem crash records (`coredumpctl`, Windows WER Event ID 1000, macOS DiagnosticReports).

2. **Flow Preservation (4-Way Choice):**
   When an AI coding agent spots a bug or anomaly in a 3rd-party dependency while implementing a feature, it must **never** derail or hijack the engineering session. It presents the developer with 4 clear choices:
   - **Choice 1: Ignore & continue** the current task without friction.
   - **Choice 2: Keep parked** in `<5ms` with full contextual breadcrumbs (`park_bug`).
   - **Choice 3: Spawn a separate triage session** using native MCP Resources and Prompts (`bugrouter://parked/<id>`).
   - **Choice 4: Fork/patch locally** and maintain visibility in the dependency patch ledger (`bugrouter patch`).

3. **Dependency Patch Visibility ("Close to the Eyes"):**
   When upstream maintainers are slow to respond and teams fork or patch a dependency (`go.mod` `replace`, npm `overrides`/`patches/`, Cargo `[patch]`, Poetry git branch), temporary forks often become forgotten, permanent technical debt. `bugrouter` tracks every local patch in a high-visibility ledger alongside its canonical upstream issue URL and displays it front-and-center in the Web UI so patches can be promptly reverted when upstream releases a fix.

4. **WorkOS-Style Plug-and-Play Dependency Portal:**
   Companies and development teams do not need speculative, token-wasting "stack discovery". Engineers know the downstream dependencies and internal microservices their systems rely on. The Cloud Control Plane Web UI provides a visual catalog for connecting dependencies (`services.json`) and monitoring all active temporary patches in one unified view.

---

## 2. Completed Milestones Ledger (Milestones 1–4, Specs #01–#10.1)

All milestones and specs below have been fully implemented, verified with race-detector tests, and merged into the core engine:

### Milestone 1: Zero-Dependency Core Resolver & Contract [COMPLETED]
- **Spec #01: Zero-Dependency Core Resolver & Contract [COMPLETED]**
  - Bootstrapped CalVer versioning (`2026.10.0`), bounded `httpx.Client`, and initial `resolver.Target` abstraction.
- **Spec #02: Classification Engine, DirectProbe & OSPackageProbe [COMPLETED]**
  - Added URL normalization, forge classification (GitHub, GitLab, Codeberg, SourceHut), and Debian/Ubuntu package queries (`dpkg`, `apt`).
- **Spec #03: Workspace Probe, Registry Probe & Web Domain Discovery [COMPLETED]**
  - Implemented Node.js `node_modules` and Go `go.mod` parsing, concurrent registry probing for npm, PyPI, and Crates.io, and web discovery via RFC 9116 `security.txt` and `/.well-known/bug-report`.

### Milestone 2: Type-Safe Secret Scrubber, Issue Template Introspector & Staged Drafts [COMPLETED]
- **Spec #04: Type-Safe Secret Scrubber & Draft Engine [COMPLETED]**
  - Implemented immutable `ScrubbedText`, regex redaction for AWS, GitHub, Slack, OpenAI, PEM keys, and URI credentials, and local draft staging in `$XDG_DATA_HOME/bugrouter/drafts` with `0600` permissions.
- **Spec #05: Upstream Issue Template Introspector [COMPLETED]**
  - Built zero-dependency YAML and Markdown issue template parsers, Bugzilla REST schema discovery, and query parameter pre-fill adaptation.
- **Spec #06: WorkOS-Style Org Discovery & Cloud Control Plane [COMPLETED]**
  - Added Layer 0 `OrgCloudProbe` for enterprise `services.json`, embedded review queue Web UI, and authenticated OAuth connectors (GitHub, GitLab, Jira, Linear).
- **Spec #06.1: Control Plane Hardening & Post-M2 Remediation [COMPLETED]**
  - Bound forge client with `httpx.PostBytes` SSRF protection, hardened draft IDs against directory traversal, and decoupled Jira and Linear protocols.

### Milestone 3: Polyglot Manifests, Upstream Deduplication & Linux Package Probes [COMPLETED]
- **Spec #07: Upstream Issue Deduplicator & Polyglot Manifests [COMPLETED]**
  - Added Rust `Cargo.toml`/`Cargo.lock` and Python `pyproject.toml` parsing, Fedora/RHEL `rpm` and Arch `pacman` probes, and token overlap duplicate detection for GitHub, GitLab, and Bugzilla.
- **Spec #07.1: Deduplication Hardening & Python PEP Normalization [COMPLETED]**
  - Fixed TOML inline table scanning, implemented PEP 503/508 package name normalization, and derived enterprise forge API base URLs.

### Milestone 4: Cloud Control Plane Security, Audit Trails, Production Readiness & Credential Boundaries [COMPLETED]
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

### Milestone 5: Zero-Hijacking MCP Handoff, Tracked Patch Ledger & WorkOS Catalog (Active — Spec #11 / #11.1)
Focuses on flow preservation during coding sessions, keeping temporary dependency patches visible to engineers, and providing a WorkOS-style dependency connection portal.

- **Spec #11 & #11.1: Zero-Hijacking `park_bug` MCP Handoff, Tracked Dependency Patch Ledger & WorkOS Catalog [ACTIVE]**
  - **Zero-Latency Parked Bug Store (`internal/adapter/parked.go`)**:
    - `ParkedBug` record with 8-character hex ID (from `crypto/rand`), timestamps, dependency identifier, title, type-safe scrubbed snippets, workaround notes, workspace file locations, and status (`parked` -> `triaged`).
    - `HandoffPayload` containing `ResourceURI` (`bugrouter://parked/<id>`), `MCPPromptName` (`triage_parked_bug`), `CLICommand` (`bugrouter draft --from-parked <id>`), `PatchInstructions`, `UserOptions` (the 4 flow choices), and clear agent directives.
    - `ParkedStore` providing atomic file persistence in `$XDG_DATA_HOME/bugrouter/parked/<id>.json` with `0600` permissions in `<5ms` with zero network I/O.
  - **Tracked Dependency Patch Ledger (`internal/adapter/patch.go`)**:
    - `DependencyPatch` record storing ID, CreatedAt, Dependency, Ecosystem (`go`, `npm`, `cargo`, `python`, `custom`), PatchTarget (fork URL, branch, patch file), ManifestFile, UpstreamIssueURL, Reason, and Status (`active` / `reverted`).
    - `PatchStore` providing atomic persistence in `$XDG_DATA_HOME/bugrouter/patches.json` (or `BUGROUTER_PATCHES_FILE`) with `0600` permissions.
    - Methods `Record`, `List`, and `Remove`.
  - **Native MCP Handoff & Patch Tools (`internal/mcp/server.go`)**:
    - Advertises `tools: {}`, `resources: { listChanged: true }`, and `prompts: {}` capabilities in `initialize`.
    - Exposes `park_bug` as tool 1, emitting `notifications/resources/list_changed` before returning tool response.
    - Exposes `record_dependency_patch` to track local forks directly from MCP agents.
    - Exposes `resources/list` and `resources/read` for `bugrouter://parked/<id>`.
    - Exposes `prompts/list` and `prompts/get` for `triage_parked_bug`.
  - **WorkOS-Style Plug-and-Play Dependency Catalog & Patch Banner (`internal/cloud/server.go`)**:
    - High-visibility "Active Dependency Patches (Temporary Forks)" banner/table at the top of the Web UI with 1-click modal to track local patches.
    - Grid of 1-click preset connection tiles (Stripe, Supabase, Auth0, Prisma, Next.js, Remix, Redis, Postgres, FFmpeg, Blender) and custom dependency registration form.
    - REST API endpoints: `GET/POST/DELETE /api/v1/services` and `GET/POST/DELETE /api/v1/patches`.
  - **CLI Commands (`cmd/bugrouter/main.go`)**:
    - `bugrouter park [--snippet <s>] [--workaround <w>] [--file <f>] [--json] <dependency> <title>` displaying the 4 flow preservation options.
    - `bugrouter patch list [--json]`, `bugrouter patch add --dep <d> --target <fork> [--ecosystem <e>] [--issue <url>] [--manifest <m>] [--reason <r>]`, and `bugrouter patch rm <id-or-dep>`.
    - `bugrouter draft --from-parked <id>` for hydrating parked bugs in spawned triage sessions.

---

### Milestone 6: Zero-Daemon Post-Mortem OS Crash Reader & Desktop Telemetry (Upcoming — Spec #12)
Brings zero-daemon, post-mortem crash inspection to Linux, Windows, and macOS desktop environments without background pollers.

- **Spec #12: Zero-Daemon Post-Mortem OS Crash Reader & Desktop App Telemetry [UPCOMING]**
  - **Post-Mortem OS Crash Readers (`bugrouter crash-log`)**: Zero-daemon inspection reading system crash journals on demand:
    - Linux: `coredumpctl info` and `journalctl -u ...`
    - Windows: Windows Error Reporting (WER) and Event Viewer (Application Crash Event ID 1000)
    - macOS: `/Library/Logs/DiagnosticReports/` and `Console.app` crash logs
  - **Desktop Application & GPU Telemetry**: Diagnostic capture for GUI applications (such as Photoshop, Blender, DaVinci Resolve) collecting GPU models, display servers (Wayland, X11, DWM), and drivers with zero background daemon overhead.

---

### Milestone 7: Upstream Patch Status Checker & Anti-Slop Quality Linter (Upcoming — Spec #13)
Equips teams to retire temporary forks as soon as upstream maintains merge fixes, ensuring maintainer-ready reports.

- **Spec #13: Upstream Patch Status Checker & Anti-Slop Quality Linter [UPCOMING]**
  - **Upstream Patch Status Checker (`bugrouter patch check`)**: Probes tracked `UpstreamIssueURL` states across GitHub, GitLab, and Bugzilla to alert engineers when an active dependency fork can be safely reverted.
  - **Deterministic Anti-Slop Quality Linter (`internal/adapter/linter.go`)**: Evaluates draft quality on a 0–100 scale, gating AI conversational filler, decorative emojis, em dashes, and unfilled placeholders (`TODO`, `FIXME`, `<insert>`).
  - **Bounded Reproduction Verifier (`internal/verifier/verifier.go`)**: Executes reproduction scripts in isolated subshells with 256 KiB output caps, timeout handling, secret scrubbing, and SHA-256 proof digests.
