# bugrouter

**Universal Bug Triage & Upstream Router for Autonomous Coding Agents**

Current Version: **2026.10.0** (CalVer)  
License: **MIT**  
Dependencies: **Standard Library Only (Zero Third-Party Dependencies)**

---

## 1. Overview

`bugrouter` is an autonomous, zero-dependency Go CLI daemon and Model Context Protocol (MCP) server that connects AI coding agents and development workflows directly to the correct upstream issue trackers. When an agent or developer encounters a bug, crash, or failing dependency, `bugrouter`:

1. **Resolves** the artifact or error to its canonical upstream tracker via a 6-layer waterfall engine.
2. **Scrubs** sensitive API keys, private keys, database credentials, authorization tokens, and personal home paths at the type level.
3. **Introspects** upstream issue templates (GitHub Issue Forms, GitLab Markdown templates, Bugzilla schemas).
4. **Detects Duplicates** against existing upstream issues via token-overlap scoring to prevent ticket flooding.
5. **Stages Structured Drafts** locally in `$XDG_DATA_HOME/bugrouter/drafts` with strict permissions (`0600`) and generates deep-link pre-fill URLs or authenticated API submissions.
6. **Hardens Control Plane Operations** through an embedded Web UI with constant-time Bearer token authentication, CSRF origin verification, append-only JSONL audit logs, and SSRF-guarded HMAC webhook notifications.

---

## 2. Key Features

- **Zero External Dependencies**: Pure Go 1.22+ standard library implementation. No transitive dependency bloat or supply chain exposure.
- **6-Layer Resolution Waterfall**:
  1. `org-cloud`: Enterprise service catalog and monorepo ownership records (`services.json`).
  2. `direct-url`: Exact GitHub, GitLab, Codeberg, and SourceHut repository URLs and paths.
  3. `workspace`: Local dependency manifests (`node_modules`, `go.mod`, `Cargo.toml`/`Cargo.lock`, `pyproject.toml`).
  4. `os-pkg`: Operating system package managers (Debian/Ubuntu `dpkg`/`apt`, Fedora/RHEL `rpm`, Arch `pacman`).
  5. `registry`: Concurrent queries across ecosystem registries (`npm`, `PyPI`, `Crates.io`).
  6. `web-domain`: RFC 9116 `security.txt` and `.well-known/bug-report` discovery.
- **Type-Safe Scrubber**: Produces immutable `scrubber.ScrubbedText`. Redacts AWS keys, GitHub PATs, Slack/Stripe/OpenAI tokens, PEM private keys, URI credentials, and local home directory paths (`/home/*`, `/Users/*`). Preserves short configuration literals (`true`, `false`, `null`, `nil`).
- **Upstream Issue Template Introspection**: Discovers and maps GitHub YAML Issue Forms (`body` textareas/inputs), GitLab markdown templates (`issuable_template`), and Bugzilla product schemas.
- **Upstream Duplicate Detection**: Searches GitHub, GitLab, and Bugzilla trackers using title keyword extraction and stop word filtering, calculating scored token overlap.
- **Human-in-the-Loop Review Queue**: Embedded Web UI and REST API (`/api/v1/drafts`) for manual triage, review, and one-click dispatch via OAuth/PAT connectors.
- **Hardened Cloud Security**: SHA-256 pre-hashed constant-time Bearer auth (`crypto/subtle.ConstantTimeCompare`), CSRF origin guards, append-only audit trail (`audit.log`), and HMAC-SHA256 signed webhooks (`X-Bugrouter-Signature`).
- **Model Context Protocol (MCP)**: Native stdio JSON-RPC 2.0 server (spec `2024-11-05`) exposing 7 specialized agent tools.

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

## 4. CLI Quickstart

The `bugrouter` binary includes subcommands for every stage of the bug routing lifecycle:

### Check Version
```bash
bugrouter version
# Output: bugrouter 2026.10.0 (linux/amd64)
```

### Resolve Upstream Tracker
Resolve any package name, binary name, repository, or domain to its canonical tracker:
```bash
# Resolve a Python package
bugrouter resolve requests

# Resolve a local OS binary with JSON output
bugrouter resolve curl --json

# Resolve with custom timeout and disable disk cache
bugrouter resolve nginx --timeout 5s --no-cache
```

### Draft a Staged Bug Report
Stage a structured bug ticket with automatic secret redaction, template mapping, and duplicate detection:
```bash
# Draft using CLI flags
bugrouter draft requests \
  --title "SSL connection reset during streaming download" \
  --summary "Encountered SSLEOFError when streaming large files" \
  --steps "1. Call requests.get(stream=True)\n2. Read chunks" \
  --logs "SSLEOFError: EOF occurred in violation of protocol"

# Draft using a Markdown body file
bugrouter draft checkout-api --body-file ./bug-details.md

# Draft by piping from stdin
cat error.log | bugrouter draft payment-service --title "Timeout in worker" --body-file -
```

#### Markdown Body File Format
When using `--body-file`, sections with level-2 headings (`##`) are mapped automatically:
```markdown
## Summary
Detailed explanation of what failed.

## Steps to Reproduce
1. Execute step 1
2. Trigger the failure condition

## Logs & Output
Console output or stack trace (secrets will be automatically redacted).
```

### Serve Cloud Control Plane
Start the embedded review queue Web UI and control plane daemon:
```bash
# Start local review server
bugrouter serve --addr :8080

# Start with Bearer authentication, audit logging, and webhook dispatch
bugrouter serve \
  --addr :8080 \
  --auth-token "super-secret-token-123" \
  --audit-log /var/log/bugrouter/audit.log \
  --webhook-url https://hooks.slack.com/services/...
```

Open `http://localhost:8080` in your browser to access the Human-in-the-Loop review dashboard and recent audit trail.

---

## 5. Model Context Protocol (MCP) Integration

`bugrouter` runs as a native stdio Model Context Protocol (MCP) server for Claude Desktop, Cline, Cursor, Antigravity, and other MCP-compliant AI agents.

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

### Available MCP Tools (7 Total)

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `resolve_target` | `query` (string) | Resolves a software artifact or dependency query to its canonical bug tracker. |
| `scrub_text` | `text` (string) | Deterministically redacts secrets, tokens, connection strings, and local username paths. |
| `introspect_template` | `query` (string) | Discovers and parses upstream bug tracker issue templates or schemas for a target. |
| `search_duplicates` | `query` (string), `title` (string) | Searches upstream issue tracker (GitHub, GitLab, Bugzilla) for existing duplicate bug reports. |
| `draft_bug_report` | `query` (string), `title` (string), `summary` (string), `steps_to_reproduce` (string), `logs` (string) | Resolves target, scrubs credentials, introspects template, finds duplicates, stages draft to disk, and returns structured ticket with pre-filled submission URLs. |
| `list_staged_drafts` | `status` (string, optional) | Lists all staged bug drafts pending review or approval (`pending_review`, `submitted`, `discarded`). |
| `approve_draft` | `id` (string) | Approves and submits a staged draft to its upstream tracker via authenticated OAuth connectors. |

---

## 6. Enterprise Service Catalog (`services.json`)

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

## 7. Security Architecture & Boundary Guarantees

- **Supply Chain Hardening**: Strict zero-dependency standard library design. No `node_modules`, no external Go modules.
- **SSRF & DNS Rebinding Protection**: All outbound HTTP traffic passes through `httpx.Client`. Private IPv4/IPv6 address blocks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1`, `fc00::/7`, `fe80::/10`) are strictly blocked at dial time. Outbound request bodies are capped at 2 MiB, and redirect chains are limited to 5 hops.
- **Type-Level PII Scrubber**: Sensitive data is sanitized before leaving agent boundaries. `scrubber.ScrubbedText` ensures raw secrets cannot be accidentally serialized or leaked into ticket drafts.
- **Safe Path Operations**: Draft identifiers are strictly validated against `^[a-zA-Z0-9_-]+$` to prevent directory traversal. Draft files are stored with permissions `0600`.
- **Constant-Time Authentication**: Control plane Bearer tokens are pre-hashed with SHA-256 and compared using `crypto/subtle.ConstantTimeCompare` to eliminate timing side channels.
- **CSRF Mutation Guard**: All state-modifying requests (`POST /api/v1/...`) enforce strict origin matching against the request `Host` header and require either an `Authorization: Bearer` header or `X-Bugrouter-Request: 1`.
- **Audit Logging & Webhooks**: Append-only JSONL audit logs guarantee an immutable record of all draft triage actions. Webhook notifications are signed via HMAC-SHA256 (`X-Bugrouter-Signature`) and executed with bounded timeouts.\n