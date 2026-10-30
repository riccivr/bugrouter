# bugrouter

**Universal Bug Triage & Upstream Router for Autonomous Coding Agents**

Current Version: **2026.10.0** (CalVer)  
License: **MIT**  
Dependencies: **Standard Library Only (Zero Third-Party Dependencies)**

---

## 1. Core Product Principles

`bugrouter` is built on four constitutional principles designed to balance developer productivity, agent autonomy, and open-source maintainer empathy:

1. **Zero External Dependencies & Modern C99-Spirit Go**:
   Implemented exclusively with the Go standard library (`net/http`, `os/exec`, `crypto/subtle`, `encoding/json`). Zero `node_modules`, zero third-party Go modules, zero supply-chain attack surface. Bounded memory execution (`io.LimitReader`), strict per-request timeouts, and type-level security guarantees.

2. **Maintainer Empathy & AI Opt-Out Guard (Zero Maintainer Harassment)**:
   Open-source maintainers must never be inundated with unverified or automated AI-generated bug spam. `bugrouter` automatically scans upstream issue templates and `CONTRIBUTING.md` policies for AI/LLM opt-out rules. If an upstream repository restricts AI submissions, `bugrouter` **blocks automated API submission 100% of the time**, switches into **Companion Mode** (`companion_only`), strips automated branding footers, surfaces maintainer checklist rules, and provides pre-filled deep links for human engineers to review and file respectful, human-authored reports manually.

3. **Anti-Context-Hijacking via `<5ms` Native Session Handoff (`park_bug`)**:
   When an AI coding agent discovers a bug or anomaly in a 3rd-party library while implementing a feature, derailing into ticket filing destroys its in-context reasoning. `bugrouter park` / `park_bug` records the issue locally in `<5ms` with zero network I/O, emitting native Model Context Protocol (MCP) resource notifications (`notifications/resources/list_changed`), MCP Resources (`bugrouter://parked/<id>`), and MCP Prompts (`triage_parked_bug`) so the user can spin up a dedicated triage agent without hijacking the primary workflow.

4. **Dependency Patch Ledger with Automated Upstream Status Checks (`patch check`)**:
   When upstream maintainers take time to fix bugs, development teams frequently fork or vendor-patch dependencies (`go.mod` `replace`, npm `overrides`/`patches/`, Cargo `[patch]`). These temporary forks often become permanent technical debt. `bugrouter` tracks every temporary patch alongside its upstream issue URL in a high-visibility ledger and provides automated upstream status checks (`bugrouter patch check`) to notify engineers the instant an upstream bug is closed and the fork is **[READY TO REVERT]**.

---

## 2. Overview & System Architecture

When an agent or developer encounters a bug, crash, or failing dependency, `bugrouter`:

1. **Resolves** the artifact or error to its canonical upstream tracker via a 6-layer waterfall engine (`org-cloud` -> `direct-url` -> `workspace` -> `os-pkg` -> `registry` -> `web-domain`).
2. **Scrubs** sensitive API keys, private keys, database credentials, authorization tokens, and personal home paths at the type level (`scrubber.ScrubbedText`).
3. **Introspects** upstream issue templates (GitHub YAML Issue Forms, GitLab Markdown templates, Gitea/Codeberg schemas, Bugzilla products) and parses maintainer policies (`CONTRIBUTING.md`).
4. **Detects Duplicates** against existing upstream issues via token-overlap scoring to prevent ticket flooding.
5. **Verifies Reproductions** via deterministic, isolated command execution producing SHA-256 proof digests.
6. **Compiles Evidence Dossiers** with hardware/OS telemetry (`## Environment`) and cross-dependency interaction prior art (`## Correlated Evidence`).
7. **Stages Structured Drafts** locally in `$XDG_DATA_HOME/bugrouter/drafts` with strict permissions (`0600`) and generates deep-link pre-fill URLs or authenticated API submissions.
8. **Hardens Control Plane Operations** through an embedded Web UI with constant-time Bearer token authentication, CSRF origin verification, append-only JSONL audit logs, and SSRF-guarded HMAC webhook notifications.

---

## 3. Build & Installation

### Requirements
- **Go**: 1.22 or later
- **OS**: Linux, macOS, or Windows (WSL2 recommended on Windows)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/riccivr/bugrouter.git
cd bugrouter

# Build the CLI binary
make build
# Binary is produced at ./bin/bugrouter

# Run full test suite with race detector
make test
```

---

## 4. CLI Subcommand Reference

The `bugrouter` CLI provides dedicated commands for every phase of the bug routing lifecycle:

### `bugrouter version`
Displays the CalVer version, commit, and platform target:
```bash
bugrouter version
# Output: bugrouter 2026.10.0 (linux/amd64)
```

### `bugrouter resolve <target>`
Resolves any package name, binary name, repository, or domain to its canonical tracker via the 6-layer waterfall:
```bash
# Resolve a Python package
bugrouter resolve requests

# Resolve a local OS binary with JSON output
bugrouter resolve curl --json

# Self-hosting resolution (<1ms, offline)
bugrouter resolve bugrouter

# Resolve with custom timeout and disable disk cache
bugrouter resolve nginx --timeout 5s --no-cache
```

### `bugrouter introspect <target>`
Discovers and displays upstream issue templates, YAML forms, and maintainer empathy policies:
```bash
bugrouter introspect https://github.com/expressjs/express
bugrouter introspect requests --json
```

### `bugrouter dedup <target> <title>`
Queries upstream trackers (GitHub, GitLab, Bugzilla, Gitea) for existing duplicate bug reports:
```bash
bugrouter dedup express "Null pointer dereference on startup"
bugrouter dedup requests "SSL connection timeout" --json
```

### `bugrouter draft <target>`
Stages a structured bug ticket with automatic secret redaction, template mapping, duplicate detection, and quality scoring:
```bash
# Draft using CLI flags with cross-dependency evidence
bugrouter draft react-dom \
  --title "Hydration mismatch caused by third-party DOM mutation" \
  --summary "Browser extension injects data attributes before hydration completes" \
  --steps "1. Install extension\n2. Reload page" \
  --related-dep "https://github.com/grammarly/extension"

# Draft from a Markdown body file (or stdin via -) with strict quality enforcement
cat error.log | bugrouter draft payment-service --body-file - --strict-quality

# Draft with automated reproduction verification command
bugrouter draft my-app \
  --title "Buffer overflow in request parser" \
  --summary "Request parser aborts with non-zero exit code on large payload" \
  --steps "1. Send 10MB chunked POST payload\n2. Observe panic" \
  --verify-cmd "./test/repro.sh"

# Hydrate draft from a previously parked bug
bugrouter draft --from-parked <parked-id>
```

### `bugrouter scrub`
Deterministically scrubs secrets, tokens, connection strings, and username home paths from raw text:
```bash
echo "DATABASE_URL=postgres://user:pass@localhost:5432/db" | bugrouter scrub
bugrouter scrub --input "Authorization: Bearer ghp_1234567890abcdef in /home/alice"
```

### `bugrouter telemetry`
Collects zero-dependency operating system, GPU, driver, and desktop environment diagnostics:
```bash
# Formatted Markdown output
bugrouter telemetry

# Raw JSON output
bugrouter telemetry --json
```

### `bugrouter triage` / `bugrouter agent triage`
Parses raw crash logs or stack traces (Go, Node.js, Python, Rust, native binaries), attributes suspect packages, introspects templates, and searches duplicates:
```bash
# Triage a crash log file
bugrouter triage --log-file ./panic.log

# Triage piped crash log from stdin
npm test 2>&1 | bugrouter triage --log-file -

# Triage with explicit query override
bugrouter triage --log-file ./trace.log --query "requests"
```

### `bugrouter verify` / `bugrouter agent verify`
Executes a bounded reproduction command under isolated contexts with 256 KiB output caps, timeout handling, exit code matching, candidate extraction, and cryptographic proof digests:
```bash
# Run reproduction verification command
bugrouter verify --cmd "npm test"

# Verify command with specific expected exit code and custom timeout
bugrouter verify --cmd "pytest tests/test_crash.py" --expect-exit 1 --timeout 30s
```

### `bugrouter stack`
Scans workspace manifests (`services.json`, `go.mod`, `package.json`, `Cargo.toml`, `pyproject.toml`), catalogs dependencies, and optionally queries upstream trackers for open bugs matching installed versions:
```bash
# Scan workspace dependencies
bugrouter stack

# Scan specific directory and output JSON
bugrouter stack --dir ./frontend --json

# Scan workspace and query upstream trackers for active bugs matching dependencies
bugrouter stack --check-upstream
```

### `bugrouter park <dependency> <title>`
Instantly parks a 3rd-party dependency bug in `<5ms` without network calls or context hijacking, displaying the 4 flow preservation choices:
```bash
# Park a dependency bug encountered mid-task (<5ms, zero network calls)
bugrouter park sharp "v0.33.0 fails with SIGSEGV on musl alpine" \
  --snippet "Segmentation fault at 0x00007f9c in libvips" \
  --workaround "Downgraded to sharp@0.32.6" \
  --file "src/image.ts" \
  --related-dep "libvips"

# Park and output machine-readable JSON handoff payload
bugrouter park stripe "Webhook signature verification panic on malformed payload" --json
```

### `bugrouter patch <list|add|check|rm>`
Manages the tracked dependency patch ledger so temporary local forks and vendor patches stay visible and are promptly reverted when fixed upstream:
```bash
# List all tracked dependency patches in ledger
bugrouter patch list

# Track a new local fork or patch
bugrouter patch add \
  --dep sharp \
  --target patches/sharp+0.33.0.patch \
  --ecosystem npm \
  --manifest package.json \
  --issue https://github.com/lovell/sharp/issues/1234 \
  --reason "Fix musl SIGSEGV in libvips"

# Check upstream issue status across GitHub, GitLab, Gitea, and Bugzilla
bugrouter patch check
# Output:
# Dependency | Ecosystem | Patch Target                | Upstream State | Status
# sharp      | npm       | patches/sharp+0.33.0.patch  | closed         | [READY TO REVERT]

# Remove a patch once upstream fixes the issue
bugrouter patch rm sharp
```

### `bugrouter crash-log`
Reads the latest native OS post-mortem crash record (`coredumpctl`, `/var/crash`, Windows WER/Event 1000, macOS `DiagnosticReports`) on demand with zero resident daemon overhead:
```bash
bugrouter crash-log
bugrouter crash-log --json --query "my-native-bin"
```

### `bugrouter report <target>`
Launches an interactive guided CLI wizard prompting step-by-step with real-time Anti-Slop quality evaluation, automatic hardware telemetry attachment, and pre-filled submission links:
```bash
bugrouter report blender
bugrouter report https://github.com/myorg/myapp --title "Memory leak in connection pool"
```

### `bugrouter serve`
Starts the embedded review queue Web UI and Cloud Control Plane daemon:
```bash
# Start local review server
bugrouter serve --addr :8080

# Start with Bearer authentication, audit logging, and webhook dispatch
bugrouter serve \
  --addr :8080 \
  --auth-token "secret-token" \
  --audit-log /var/log/bugrouter/audit.log \
  --webhook-url https://hooks.slack.com/services/... \
  --webhook-secret "hmac-signing-secret"
```

### `bugrouter mcp`
Starts the zero-dependency JSON-RPC 2.0 stdio Model Context Protocol (MCP) server.

---

## 5. Model Context Protocol (MCP) Integration

`bugrouter` runs as a native stdio Model Context Protocol (MCP) server (spec `2024-11-05`) for Claude Desktop, Cline, Cursor, Antigravity, and autonomous AI agents.

### Client Configuration

Add `bugrouter` to your MCP client configuration (e.g., `claude_desktop_config.json` or `cursor.json`):

```json
{
  "mcpServers": {
    "bugrouter": {
      "command": "bugrouter",
      "args": ["mcp"]
    }
  }
}
```

### MCP Capabilities, Resources & Prompts
- **Resources**: Exposes parked bug records as `bugrouter://parked/<id>` (`application/json`), allowing host models to inspect context.
- **Prompts**: Provides `triage_parked_bug` with argument `id`, supplying ready-to-execute prompt templates for spawned triage sessions.
- **Notifications**: Emits `notifications/resources/list_changed` to the host client immediately before returning `park_bug` responses.

### Complete 15 MCP Tools Reference

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `park_bug` | `dependency` (string, req), `title` (string, req), `error_snippet` (string, opt), `workaround_note` (string, opt), `workspace_file` (string, opt), `related_dependency` (string, opt) | PREFERRED DURING CODING: Instantly parks a 3rd-party dependency bug in <5ms with zero network calls and returns a native session-handoff payload so you can alert the user to spawn a separate bug-reporting session without derailing your current task. Emits `notifications/resources/list_changed`. |
| `record_dependency_patch` | `dependency` (string, req), `patch_target` (string, req), `reason` (string, req), `ecosystem` (string, opt), `manifest_file` (string, opt), `upstream_issue_url` (string, opt) | Records a temporary local fork or patch for a 3rd-party dependency in the patch ledger so it stays visible to engineers and can be reverted when upstream fixes the issue. |
| `check_dependency_patches` | *(none)* | Checks upstream issue/PR tracking status for all recorded temporary dependency patches across GitHub, GitLab, Gitea, and Bugzilla, highlighting issues ready to be reverted. |
| `read_system_crash_log` | `query` (string, opt), `title` (string, opt) | Reads the latest native OS post-mortem crash record (Linux coredumpctl/var-crash, Windows WER/Event 1000, macOS DiagnosticReports), extracts suspect binary and trace candidates, scrubs PII, and returns structured triage context. |
| `resolve_target` | `query` (string, req) | Resolves a software artifact or dependency query to its canonical bug tracker via the 6-layer waterfall engine. |
| `scrub_text` | `text` (string, req) | Deterministically scrubs secrets, tokens, connection strings, and PII home paths from text. |
| `introspect_template` | `query` (string, req) | Discovers and parses upstream bug tracker issue templates or schemas for a target, detecting maintainer AI opt-out policies and checklist rules. |
| `search_duplicates` | `query` (string, req), `title` (string, req) | Searches upstream issue tracker (GitHub, GitLab, Bugzilla, Gitea) for existing duplicate bug reports using token overlap scoring. |
| `draft_bug_report` | `query` (string, req), `title` (string, req), `summary` (string, opt), `steps_to_reproduce` (string, opt), `logs` (string, opt), `strict_quality` (bool, opt), `verify_cmd` (string, opt), `include_telemetry` (bool, opt), `related_dependency` (string, opt) | Resolves target, scrubs credentials, introspects templates, checks duplicates, stages draft to disk, compiles cross-dependency evidence, enforces maintainer policies, and returns structured ticket. |
| `list_staged_drafts` | `status` (string, opt) | Lists all staged bug drafts pending review or approval (`pending_review`, `companion_only`, `submitted`, `discarded`). |
| `approve_draft` | `id` (string, req) | Approves and submits a staged draft to its upstream tracker via authenticated OAuth connectors (refuses automated submission if maintainer has opted out of AI/bot reports). |
| `triage_crash_log` | `log` (string, req), `title` (string, opt), `query` (string, opt) | Analyzes raw crash logs or stack traces, deterministically attributes failures to upstream dependencies, introspects templates, checks duplicates, and returns structured agent triage envelopes. |
| `verify_reproduction` | `command` (string, req), `timeout_seconds` (integer, opt), `expect_exit` (integer, opt) | Executes a bounded reproduction command, captures and scrubs stdout/stderr, extracts faulting package candidates, and returns a deterministic VerificationProof with SHA-256 digest. |
| `scan_workspace_stack` | `dir` (string, opt), `check_upstream` (bool, opt) | Scans workspace dependency manifests (`go.mod`, `package.json`, `Cargo.toml`, `pyproject.toml`, `services.json`), resolves upstream trackers, and optionally queries upstream issues for active bugs. |
| `collect_system_telemetry` | *(none)* | Collects zero-dependency local operating system and hardware diagnostics (CPU, GPU models, driver versions, kernel, desktop environment, display server). |

---

## 6. Cloud Control Plane & Review Queue

The embedded Cloud Control Plane (`bugrouter serve`) provides a single-pane-of-glass operations console:

1. **Active Dependency Patches (Temporary Forks) Banner**:
   Displays active local patches, manifests, fork branches, and upstream issue links. Features a **"Check Upstream Status"** button that queries upstream trackers and marks closed upstream bugs with a prominent green `Ready to Revert` badge.
2. **WorkOS-Style Plug-and-Play Services Catalog**:
   One-click connection cards for common ecosystem dependencies (Stripe, Supabase, Auth0, Prisma, Next.js, Remix, Redis, Postgres, FFmpeg, Blender) plus a custom registration form backed by `services.json`.
3. **Human-in-the-Loop Review Queue**:
   Staged drafts pending approval with live status tags (`pending_review`, `submitted`, `discarded`, `companion_only`). For `companion_only` drafts, the `Approve` button is automatically disabled to protect upstream maintainers, and an explicit **Maintainer Empathy** banner guides engineers to file manually.
4. **Guided Report Composer**:
   "New Guided Report" modal allowing human engineers to compose reports with automated hardware telemetry attachment and strict Anti-Slop quality validation.
5. **Connected Tech Stack & Downstream Radar**:
   Live inventory of workspace dependencies with upstream open issue alerts.
6. **Append-Only Audit Trail**:
   Structured log of all triage, dispatch, patch, and service operations.

---

## 7. Enterprise Service Catalog (`services.json`)

Internal private services and monorepo packages can be routed directly to internal issue trackers using an enterprise service catalog file.

### Lookup Order
1. Path in `BUGROUTER_SERVICES_FILE` environment variable
2. `$XDG_CONFIG_HOME/bugrouter/services.json` (defaults to `~/.config/bugrouter/services.json`)
3. `/etc/bugrouter/services.json`

### File Format & Schema

```json
{
  "services": [
    {
      "name": "checkout-worker",
      "aliases": ["checkout", "billing-worker"],
      "repository_url": "https://github.example.corp/fintech/checkout-worker",
      "tracker": {
        "protocol": "github",
        "url": "https://github.example.corp/fintech/checkout-worker/issues"
      }
    },
    {
      "name": "auth-service",
      "repository_url": "https://gitlab.example.corp/security/auth-service",
      "tracker": {
        "protocol": "jira",
        "url": "https://jira.example.corp/browse/AUTH"
      }
    },
    {
      "name": "telemetry-pipeline",
      "repository_url": "https://git.kernel.org/pub/scm/linux/telemetry.git",
      "tracker": {
        "protocol": "debbugs",
        "email": "submit@bugs.example.corp"
      }
    }
  ]
}
```

---

## 8. Security Architecture & Boundary Guarantees

- **Supply Chain Hardening**: Strict zero-dependency standard library design. No `node_modules`, no external Go modules.
- **SSRF & DNS Rebinding Protection**: All outbound HTTP traffic passes through `httpx.Client`. Private IPv4/IPv6 address blocks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1`, `fc00::/7`, `fe80::/10`) are strictly blocked at dial time. Outbound request bodies are capped at 2 MiB, and redirect chains are limited to 5 hops with automatic credential stripping on cross-host redirects.
- **Type-Level PII Scrubber**: Sensitive data is sanitized before leaving agent boundaries. `scrubber.ScrubbedText` ensures raw secrets cannot be accidentally serialized or leaked into ticket drafts.
- **Safe Path Operations**: Draft identifiers are strictly validated against `^[a-zA-Z0-9_-]+$` to prevent directory traversal. Draft and patch files are stored with permissions `0600`.
- **Constant-Time Authentication**: Control plane Bearer tokens are pre-hashed with SHA-256 and compared using `crypto/subtle.ConstantTimeCompare` to eliminate timing side channels.
- **CSRF Mutation Guard**: All state-modifying requests (`POST /api/v1/...`) enforce strict origin matching against the request `Host` header and require either an `Authorization: Bearer` header or `X-Bugrouter-Request: 1`.
- **Audit Logging & Webhooks**: Append-only JSONL audit logs guarantee an immutable record of all draft triage actions. Webhook notifications are signed via HMAC-SHA256 (`X-Bugrouter-Signature`) and executed with bounded timeouts.

---

## 9. CI/CD & GitHub Actions Integration

`bugrouter` provides a turnkey composite GitHub Action (`action.yml`) enabling automated upstream patch status auditing and crash log triage directly within GitHub Actions pipelines.

### 9.1 Gating PRs on Upstream Patch Status (`mode: patch-check`)

When teams maintain temporary forks or local patches (`patches.json`), this workflow continuously audits upstream issue states. If an upstream bug is closed or merged, the action alerts the team and optionally fails CI so temporary forks are prompt and safely reverted to canonical releases.

```yaml
name: Dependency Patch Audit

on:
  pull_request:
  schedule:
    - cron: '0 8 * * 1' # Run weekly every Monday

jobs:
  audit-patches:
    name: Check Upstream Patch Status
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Audit dependency patches
        uses: riccivr/bugrouter@2026.10.0
        with:
          mode: 'patch-check'
          fail-on-revertable: 'true'
          patches-file: 'patches.json'
```

### 9.2 Automated Crash Log Triage in CI (`mode: triage`)

Capture panics, crash logs, or segfaults from test runners and automatically triage them to suspect upstream packages, query issue templates, and identify potential duplicates.

```yaml
name: Test & Autonomous Crash Triage

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run test suite with crash capture
        run: |
          go test -v ./... > test-run.log 2>&1 || true

      - name: Triage crash logs
        uses: riccivr/bugrouter@2026.10.0
        if: failure()
        with:
          mode: 'triage'
          log-file: 'test-run.log'
```

### 9.3 Action Parameters

| Input | Mode | Default | Description |
| :--- | :--- | :--- | :--- |
| `mode` | Both | `patch-check` | Operational mode: `patch-check` (audit tracked forks) or `triage` (crash log attribution). |
| `fail-on-revertable` | `patch-check` | `true` | Exit with non-zero status if any tracked patch can be reverted (upstream issue closed). |
| `patches-file` | `patch-check` | `""` | Optional path to `patches.json` (sets `BUGROUTER_PATCHES_FILE`). |
| `log-file` | `triage` | `""` | Path to raw crash log or test failure output file. |
| `query` | `triage` | `""` | Optional target package or binary query override. |

| Output | Description |
| :--- | :--- |
| `result-json` | Machine-parseable JSON array of patch statuses or `AgentTriageResult` envelope. |
| `revertable-count` | Number of tracked patches that have been resolved upstream and are ready to revert. |

