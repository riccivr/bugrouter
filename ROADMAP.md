# ROADMAP.md — bugrouter Project Roadmap & Vision

This document tracks the long-term architectural trajectory, active implementation focus, and milestone ledger for `bugrouter`. It serves as the authoritative cross-session plan for all Architect and Implementer sessions.

---

## 1. Core Product Philosophy

`bugrouter` is built on two fundamental product truths and an unwavering quality standard:

1. **Zero-Hijacking Agentic Workflow (Native Host Handoff):**
   When an AI coding agent spots a bug in a 3rd-party dependency while working on an engineer's feature, it must **never** hijack the current session to resolve trackers, fetch templates, search duplicates, or draft tickets. Instead, it calls `park_bug`—which writes a local breadcrumb in `<5ms` with zero network calls, emits a native MCP resource notification (`notifications/resources/list_changed`), and exposes an MCP Resource (`bugrouter://parked/<id>`) along with an MCP Prompt (`triage_parked_bug`) and `handoff_prompt`. This allows Claude Desktop, Claude Code, Antigravity, or ChatGPT to natively offer a non-intrusive "Spawn new session to file this bug" action while immediately resuming the engineer's primary task.

2. **WorkOS-Style Plug-and-Play Dependency Catalog:**
   Companies and development teams do not need speculative, token-wasting "stack discovery". Engineers already know the downstream dependencies and internal microservices their systems rely on. The Cloud Control Plane Web UI provides a visual, WorkOS-style catalog where engineers click to enable, configure, or toggle dependencies (persisted to `services.json`), with copyable 1-click CLI and MCP commands for parking bugs directly against them.

3. **High-Signal, Zero-Slop Tickets (For Agents & Desktop Users Alike):**
   Whether triggered from a spawned agent session or by an everyday Linux/Windows PC user reporting a desktop application issue (such as a GPU rendering crash in Blender), tickets are strictly scrubbed of secrets, stripped of AI conversational filler and emojis, and formatted with maintainer-grade reproduction steps and verified telemetry.

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

### Milestone 5: Native Session Handoff & WorkOS-Style Dependency Catalog (Active — Spec #11)
Focuses on the non-intrusive, zero-hijacking agentic workflow and visual downstream service configuration.

- **Spec #11: Native MCP Session Handoff (`park_bug` + MCP Resources/Prompts) & WorkOS-Style Web UI [ACTIVE]**
  - **Zero-Latency Parked Bug Store (`internal/adapter/parked.go`)**:
    - `ParkedBug` record with 8-character hex ID (from `crypto/rand`), timestamps, dependency identifier, title, type-safe scrubbed snippets, workaround notes, workspace file locations, and lifecycle status (`parked` -> `triaged`).
    - `HandoffPayload` containing `ResourceURI` (`bugrouter://parked/<id>`), `MCPPromptName` (`triage_parked_bug`), `CLICommand` (`bugrouter draft --from-parked <id>`), and spawn directives.
    - `ParkedStore` providing atomic file persistence in `$XDG_DATA_HOME/bugrouter/parked/<id>.json` with `0600` permissions in `<5ms` with zero network I/O.
  - **Native MCP Handoff Primitives (`internal/mcp/server.go`)**:
    - Advertises `tools: {}`, `resources: { listChanged: true }`, and `prompts: {}` capabilities in `initialize`.
    - Exposes `park_bug` as the primary tool in `tools/list` for in-coding agents.
    - Emits JSON-RPC `notifications/resources/list_changed` notification to stdio immediately prior to writing the `tools/call` response.
    - Exposes `resources/list` and `resources/read` returning `bugrouter://parked/<id>`.
    - Exposes `prompts/list` and `prompts/get` for `triage_parked_bug` providing copy-ready prompts for spawned sessions.
  - **WorkOS-Style Plug-and-Play Dependency Catalog (`internal/cloud/server.go`)**:
    - Embedded Web UI featuring visual "Connected Dependencies & Downstream Services" dashboard.
    - 1-Click preset connection tiles (Stripe, Supabase, Auth0, Prisma, Next.js, Remix, Redis, Postgres, FFmpeg, Blender) and custom dependency registration modal.
    - REST API endpoints: `GET /api/v1/services`, `POST /api/v1/services` (auto-classifying targets and atomically saving `0600`), and `DELETE /api/v1/services/{name}`.
    - Copyable 1-click `bugrouter park <name> "<issue>"` snippets for connected services.
  - **CLI Commands (`cmd/bugrouter/main.go`)**:
    - `bugrouter park <dependency> <title> [--snippet <s>] [--workaround <w>] [--file <f>] [--json]`.
    - `bugrouter draft --from-parked <id>` for hydrating parked bugs in spawned triage sessions.

---

### Milestone 6: Spawned Triage Session Hydrator & Deterministic Anti-Slop Quality Linter (Upcoming — Spec #12)
Equips spawned triage sessions to produce maintainer-ready, verified bug tickets with zero AI conversational fluff.

- **Spec #12: Spawned Triage Session Hydrator & Deterministic Anti-Slop Quality Linter [UPCOMING]**
  - **Spawned Session Hydrator (`bugrouter triage <parked-id>`)**: Reads the parked breadcrumb, re-verifies the workspace context, resolves the canonical upstream tracker, introspects templates, and searches for existing duplicates.
  - **Deterministic Anti-Slop Quality Linter (`internal/adapter/linter.go`)**: Evaluates draft quality on a 0–100 scale, penalizing AI conversational filler, decorative emojis, em dashes, typographic quotes, and unfilled placeholders (`TODO`, `FIXME`, `<insert>`). Enforces `--strict-quality` gates.
  - **Bounded Reproduction Verifier (`internal/verifier/verifier.go`)**: Executes reproduction scripts in isolated subshells with output buffering (256 KiB), timeout controls, secret scrubbing, and SHA-256 proof digests.

---

### Milestone 7: Desktop/PC User Mode & Hardware Telemetry (Upcoming — Spec #13)
Brings zero-dependency bug routing to desktop operating systems and everyday GUI applications.

- **Spec #13: Desktop App Resolver, Gitea/Forgejo Support & Hardware Telemetry Collector [UPCOMING]**
  - **Desktop Package Probes**: Pure deterministic parsers for Windows `winget` and Linux `flatpak` / `snap`.
  - **Community Forges & Trackers**: Gitea/Forgejo support (such as `projects.blender.org`, `gitea.com`, and self-hosted instances) with issue template introspection, REST API search, and pre-filled deep links.
  - **Hardware and OS Telemetry Collector (`internal/telemetry`)**: Native, zero-dependency extraction of GPU models, CPU architecture, core counts, OS kernel, desktop environments, and display servers with type-safe scrubbing.
  - **Interactive Human Bug Wizard (`bugrouter report`)**: Terminal wizard guiding everyday users through structured bug reporting with real-time anti-slop scoring and automatic hardware diagnostics attachment.
