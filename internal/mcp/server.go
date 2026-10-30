package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/cloud"
	"github.com/riccivr/bugrouter/internal/dedup"
	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/introspector"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/scrubber"
	"github.com/riccivr/bugrouter/internal/telemetry"
	"github.com/riccivr/bugrouter/internal/verifier"
	"github.com/riccivr/bugrouter/internal/version"
)

// ProtocolVersion specifies the supported Model Context Protocol transport version.
const ProtocolVersion = "2024-11-05"

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolCallResult struct {
	Content []toolContent `json:"content"`
	IsError bool          `json:"isError"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// Server exposes bugrouter capabilities via JSON-RPC 2.0 MCP stdio transport.
type Server struct {
	resolver        *resolver.Waterfall
	draftStore      *adapter.DraftStore
	parkedStore     *adapter.ParkedStore
	patchStore      *adapter.PatchStore
	introspector    *introspector.Introspector
	forgeClient     adapter.ForgeSubmitter
	dedupFinder     *dedup.Finder
	auditLogger     *cloud.AuditLogger
	webhookNotifier *cloud.WebhookNotifier
}

// NewServer creates an MCP server backed by the provided waterfall and draft store.
func NewServer(wf *resolver.Waterfall, store *adapter.DraftStore) *Server {
	httpClient := httpx.NewClient(0)
	return &Server{
		resolver:        wf,
		draftStore:      store,
		parkedStore:     adapter.NewParkedStore(""),
		patchStore:      adapter.NewPatchStore(""),
		introspector:    introspector.New(httpClient),
		forgeClient:     cloud.NewForgeClient(httpClient),
		dedupFinder:     dedup.NewFinder(httpClient),
		auditLogger:     cloud.NewAuditLogger(""),
		webhookNotifier: cloud.NewWebhookNotifier(httpClient, "", ""),
	}
}

// WithParkedStore overrides the default parked bug store for testing or custom configuration.
func (s *Server) WithParkedStore(store *adapter.ParkedStore) *Server {
	s.parkedStore = store
	return s
}

// WithPatchStore overrides the default dependency patch store for testing or custom configuration.
func (s *Server) WithPatchStore(store *adapter.PatchStore) *Server {
	s.patchStore = store
	return s
}

// WithAuditLogger configures the audit logger for recording MCP actions.
func (s *Server) WithAuditLogger(logger *cloud.AuditLogger) *Server {
	s.auditLogger = logger
	return s
}

// WithWebhookNotifier configures the webhook notifier for dispatching MCP audit events.
func (s *Server) WithWebhookNotifier(notifier *cloud.WebhookNotifier) *Server {
	s.webhookNotifier = notifier
	return s
}

// WithIntrospector overrides the introspector client for testing or custom caching.
func (s *Server) WithIntrospector(intro *introspector.Introspector) *Server {
	s.introspector = intro
	return s
}

// WithForgeClient overrides the default forge submitter for testing or custom authentication.
func (s *Server) WithForgeClient(f adapter.ForgeSubmitter) *Server {
	s.forgeClient = f
	return s
}

// WithFinder overrides the deduplication finder for testing or custom configuration.
func (s *Server) WithFinder(f *dedup.Finder) *Server {
	s.dedupFinder = f
	return s
}

// Run processes newline-delimited JSON-RPC messages from in and writes responses to out.
func (s *Server) Run(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	const maxLineLength = 4 * 1024 * 1024
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, maxLineLength)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var req jsonrpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			errResp := jsonrpcResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error: &jsonrpcError{
					Code:    -32700,
					Message: "Parse error",
				},
			}
			if writeErr := s.writeResponse(out, errResp); writeErr != nil {
				return writeErr
			}
			continue
		}

		isNotification := len(req.ID) == 0 || string(req.ID) == "null"
		resp := s.handleRequest(ctx, req, out)

		if !isNotification {
			if err := s.writeResponse(out, resp); err != nil {
				return err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read mcp input: %w", err)
	}
	return nil
}

func (s *Server) writeResponse(out io.Writer, resp jsonrpcResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal json-rpc response: %w", err)
	}
	if _, err := out.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write json-rpc response: %w", err)
	}
	return nil
}

func (s *Server) handleRequest(ctx context.Context, req jsonrpcRequest, out io.Writer) jsonrpcResponse {
	resp := jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities": map[string]any{
				"tools":     map[string]any{},
				"resources": map[string]any{"listChanged": true},
				"prompts":   map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "bugrouter",
				"version": version.Version,
			},
		}

	case "notifications/initialized":
		resp.Result = map[string]any{}

	case "ping":
		resp.Result = map[string]any{}

	case "resources/list":
		var resourceList []map[string]any
		if s.parkedStore != nil {
			bugs, err := s.parkedStore.List()
			if err == nil {
				for _, b := range bugs {
					resourceList = append(resourceList, map[string]any{
						"uri":      "bugrouter://parked/" + b.ID,
						"name":     fmt.Sprintf("Parked Bug: %s — %s", b.Dependency, b.Title),
						"mimeType": "application/json",
					})
				}
			}
		}
		if resourceList == nil {
			resourceList = []map[string]any{}
		}
		resp.Result = map[string]any{
			"resources": resourceList,
		}

	case "resources/read":
		var params struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Error = &jsonrpcError{Code: -32602, Message: fmt.Sprintf("invalid params: %v", err)}
			return resp
		}
		const uriPrefix = "bugrouter://parked/"
		if !strings.HasPrefix(params.URI, uriPrefix) {
			resp.Error = &jsonrpcError{Code: -32602, Message: fmt.Sprintf("unsupported resource uri %q", params.URI)}
			return resp
		}
		id := strings.TrimPrefix(params.URI, uriPrefix)
		if s.parkedStore == nil {
			resp.Error = &jsonrpcError{Code: -32000, Message: "parked store not initialized"}
			return resp
		}
		b, err := s.parkedStore.Get(id)
		if err != nil {
			resp.Error = &jsonrpcError{Code: -32000, Message: fmt.Sprintf("resource not found: %v", err)}
			return resp
		}
		data, err := json.Marshal(b)
		if err != nil {
			resp.Error = &jsonrpcError{Code: -32000, Message: fmt.Sprintf("marshal resource: %v", err)}
			return resp
		}
		resp.Result = map[string]any{
			"contents": []map[string]any{
				{
					"uri":      params.URI,
					"mimeType": "application/json",
					"text":     string(data),
				},
			},
		}

	case "prompts/list":
		resp.Result = map[string]any{
			"prompts": []map[string]any{
				{
					"name":        "triage_parked_bug",
					"description": "Triage a previously parked 3rd-party dependency bug into a maintainer-ready bug report",
					"arguments": []map[string]any{
						{
							"name":        "id",
							"description": "Parked bug ID",
							"required":    true,
						},
					},
				},
			},
		}

	case "prompts/get":
		var params struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Error = &jsonrpcError{Code: -32602, Message: fmt.Sprintf("invalid params: %v", err)}
			return resp
		}
		if params.Name != "triage_parked_bug" {
			resp.Error = &jsonrpcError{Code: -32602, Message: fmt.Sprintf("prompt %q not found", params.Name)}
			return resp
		}
		id := params.Arguments["id"]
		if id == "" {
			resp.Error = &jsonrpcError{Code: -32602, Message: "argument 'id' is required"}
			return resp
		}
		if s.parkedStore == nil {
			resp.Error = &jsonrpcError{Code: -32000, Message: "parked store not initialized"}
			return resp
		}
		b, err := s.parkedStore.Get(id)
		if err != nil {
			resp.Error = &jsonrpcError{Code: -32000, Message: fmt.Sprintf("parked bug %s not found: %v", id, err)}
			return resp
		}

		userInstruction := fmt.Sprintf(
			"Please triage the parked bug %s affecting dependency %q.\n\n"+
				"Title: %s\n"+
				"Error Snippet:\n%s\n\n"+
				"Workaround / Notes:\n%s\n\n"+
				"Encountered in: %s\n\n"+
				"Instructions:\n"+
				"Call the draft_bug_report tool for query %q with title %q and logs matching the error snippet to resolve its upstream tracker, introspect templates, and stage a high-signal report.",
			b.ID, b.Dependency, b.Title, b.ErrorSnippet, b.WorkaroundNote, b.WorkspaceFile, b.Dependency, b.Title,
		)

		resp.Result = map[string]any{
			"description": fmt.Sprintf("Triage instructions for parked bug %s (%s)", b.ID, b.Dependency),
			"messages": []map[string]any{
				{
					"role": "user",
					"content": map[string]any{
						"type": "text",
						"text": userInstruction,
					},
				},
			},
		}

	case "tools/list":
		resp.Result = map[string]any{
			"tools": s.toolDefinitions(),
		}

	case "tools/call":
		var params toolCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Result = toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("invalid tools/call params: %v", err)}},
				IsError: true,
			}
			return resp
		}
		resp.Result = s.handleToolCall(ctx, params, out)

	default:
		resp.Error = &jsonrpcError{
			Code:    -32601,
			Message: fmt.Sprintf("method %q not found", req.Method),
		}
	}

	return resp
}

func (s *Server) toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "park_bug",
			"description": "PREFERRED DURING CODING: Instantly parks a 3rd-party dependency bug in <5ms with zero network calls and returns a native session-handoff payload so you can alert the user to spawn a separate bug-reporting session without derailing your current task.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"dependency": map[string]any{
						"type":        "string",
						"description": "3rd-party package, binary, or external service name (e.g. 'sharp', 'stripe-node')",
					},
					"title": map[string]any{
						"type":        "string",
						"description": "1-line concise summary of the observed bug or anomaly",
					},
					"error_snippet": map[string]any{
						"type":        "string",
						"description": "Raw error message, stack trace, or failure logs",
					},
					"workaround_note": map[string]any{
						"type":        "string",
						"description": "How the current coding session bypassed or mitigated the bug",
					},
					"workspace_file": map[string]any{
						"type":        "string",
						"description": "Workspace file path or line number where the bug was encountered",
					},
					"related_dependency": map[string]any{
						"type":        "string",
						"description": "Optional secondary or interacting dependency causing anomaly",
					},
				},
				"required": []string{"dependency", "title"},
			},
		},
		{
			"name":        "record_dependency_patch",
			"description": "Records a temporary local fork or patch for a 3rd-party dependency in the patch ledger so it stays visible to engineers and can be reverted when upstream fixes the issue.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"dependency": map[string]any{
						"type":        "string",
						"description": "3rd-party package, module, or repository name (e.g. 'sharp', 'github.com/org/lib')",
					},
					"patch_target": map[string]any{
						"type":        "string",
						"description": "Fork repository URL, branch, or local patch file (e.g. 'github.com/myorg/lib@fix-branch', 'patches/sharp+0.33.patch')",
					},
					"reason": map[string]any{
						"type":        "string",
						"description": "Reason for forking or patching the dependency",
					},
					"ecosystem": map[string]any{
						"type":        "string",
						"description": "Ecosystem identifier (e.g. 'go', 'npm', 'cargo', 'python', 'custom')",
					},
					"manifest_file": map[string]any{
						"type":        "string",
						"description": "Project manifest file declaring the patch (e.g. 'go.mod', 'package.json', 'Cargo.toml')",
					},
					"upstream_issue_url": map[string]any{
						"type":        "string",
						"description": "URL of the upstream issue or pull request being tracked",
					},
				},
				"required": []string{"dependency", "patch_target", "reason"},
			},
		},
		{
			"name":        "resolve_target",
			"description": "Resolves a software artifact or dependency query to its canonical bug tracker.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "Software package name, binary name, repository URL, or domain",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "scrub_text",
			"description": "Deterministically scrubs secrets, tokens, connection strings, and PII home paths from text.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"text": map[string]any{
						"type":        "string",
						"description": "Raw text, logs, or command output to redact",
					},
				},
				"required": []string{"text"},
			},
		},
		{
			"name":        "introspect_template",
			"description": "Discovers and parses upstream bug tracker issue templates or schemas for a target.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "Software package name, binary name, repository URL, or domain",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "draft_bug_report",
			"description": "Resolves target, scrubs credentials, stages draft to disk, and returns structured ticket with pre-filled submission links.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "Software package name or target query",
					},
					"title": map[string]any{
						"type":        "string",
						"description": "Bug report title",
					},
					"summary": map[string]any{
						"type":        "string",
						"description": "Summary of the issue",
					},
					"steps_to_reproduce": map[string]any{
						"type":        "string",
						"description": "Steps to reproduce",
					},
					"logs": map[string]any{
						"type":        "string",
						"description": "Console logs, terminal output, or stack traces",
					},
					"strict_quality": map[string]any{
						"type":        "boolean",
						"description": "Reject draft if quality score < 70 or AI slop is detected",
					},
					"verify_cmd": map[string]any{
						"type":        "string",
						"description": "Optional shell command to run and attach a verified reproduction proof",
					},
					"include_telemetry": map[string]any{
						"type":        "boolean",
						"description": "Collect and attach local hardware/OS telemetry (default: false)",
					},
					"related_dependency": map[string]any{
						"type":        "string",
						"description": "Optional secondary/related dependency to query for correlated stack evidence",
					},
				},
				"required": []string{"query", "title"},
			},
		},
		{
			"name":        "list_staged_drafts",
			"description": "Lists all staged bug drafts pending review or approval.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"status": map[string]any{
						"type":        "string",
						"description": "Optional filter by draft status (e.g. pending_review, submitted, discarded)",
					},
				},
			},
		},
		{
			"name":        "search_duplicates",
			"description": "Searches upstream issue tracker (GitHub, GitLab, Bugzilla) for existing duplicate bug reports.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "Software package name, binary name, repository URL, or domain",
					},
					"title": map[string]any{
						"type":        "string",
						"description": "Bug report title or problem description to extract search keywords from",
					},
				},
				"required": []string{"query", "title"},
			},
		},
		{
			"name":        "approve_draft",
			"description": "Approves and submits a staged draft to its upstream tracker via authenticated OAuth connectors.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "Unique staged draft ID to approve and submit",
					},
				},
				"required": []string{"id"},
			},
		},
		{
			"name":        "triage_crash_log",
			"description": "Analyzes raw crash logs or stack traces, deterministically extracts suspect targets, introspects templates, checks duplicates, and returns structured agent triage envelopes.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"log": map[string]any{
						"type":        "string",
						"description": "Raw crash log, stack trace, or panic output to analyze",
					},
					"title": map[string]any{
						"type":        "string",
						"description": "Optional bug report title or problem description override",
					},
					"query": map[string]any{
						"type":        "string",
						"description": "Optional target package or repo override",
					},
				},
				"required": []string{"log"},
			},
		},
		{
			"name":        "verify_reproduction",
			"description": "Executes a bounded reproduction command, captures and scrubs stdout/stderr, extracts faulting package candidates, and returns a deterministic VerificationProof.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command": map[string]any{
						"type":        "string",
						"description": "Reproduction shell command string to execute",
					},
					"timeout_seconds": map[string]any{
						"type":        "integer",
						"description": "Execution timeout in seconds (default: 15)",
					},
					"expect_exit": map[string]any{
						"type":        "integer",
						"description": "Optional expected non-zero exit code to confirm reproduction",
					},
				},
				"required": []string{"command"},
			},
		},
		{
			"name":        "scan_workspace_stack",
			"description": "Scans workspace manifests (services.json, go.mod, package.json, Cargo.toml, pyproject.toml), resolves each dependency to its canonical tracker, and optionally checks for downstream open bugs.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"dir": map[string]any{
						"type":        "string",
						"description": "Workspace root directory to scan (default: .)",
					},
					"check_upstream": map[string]any{
						"type":        "boolean",
						"description": "Whether to query upstream trackers for open bugs affecting matching versions (default: false)",
					},
				},
			},
		},
		{
			"name":        "collect_system_telemetry",
			"description": "Collects zero-dependency local operating system and hardware telemetry (CPU, GPU, kernel, desktop environment, display server).",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "read_system_crash_log",
			"description": "Reads the latest native OS post-mortem crash record (Linux coredumpctl/var-crash, Windows WER/Event 1000, macOS DiagnosticReports), extracts suspect binary and trace candidates, scrubs PII, and returns structured triage context.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "Optional target package name, binary name, or repo override",
					},
					"title": map[string]any{
						"type":        "string",
						"description": "Optional bug report title or problem description override for duplicate search",
					},
				},
			},
		},
	}
}

func (s *Server) handleToolCall(ctx context.Context, params toolCallParams, out io.Writer) toolCallResult {
	switch params.Name {
	case "park_bug":
		return s.handleParkBug(ctx, params.Arguments, out)

	case "record_dependency_patch":
		var args struct {
			Dependency       string `json:"dependency"`
			PatchTarget      string `json:"patch_target"`
			Reason           string `json:"reason"`
			Ecosystem        string `json:"ecosystem"`
			ManifestFile     string `json:"manifest_file"`
			UpstreamIssueURL string `json:"upstream_issue_url"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("parse arguments: %v", err)}},
				IsError: true,
			}
		}
		if strings.TrimSpace(args.Dependency) == "" {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: "dependency parameter cannot be empty"}},
				IsError: true,
			}
		}
		if strings.TrimSpace(args.PatchTarget) == "" {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: "patch_target parameter cannot be empty"}},
				IsError: true,
			}
		}
		if strings.TrimSpace(args.Reason) == "" {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: "reason parameter cannot be empty"}},
				IsError: true,
			}
		}

		patch, err := s.patchStore.Record(args.Dependency, args.Ecosystem, args.PatchTarget, args.ManifestFile, args.UpstreamIssueURL, args.Reason)
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("record patch: %v", err)}},
				IsError: true,
			}
		}

		data, err := json.MarshalIndent(patch, "", "  ")
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("marshal patch: %v", err)}},
				IsError: true,
			}
		}

		if s.auditLogger != nil {
			ev := cloud.AuditEvent{
				Timestamp: time.Now().UTC(),
				Action:    "patch.recorded",
				DraftID:   patch.ID,
				Target:    patch.Dependency,
				Protocol:  resolver.Protocol(patch.Ecosystem),
				RemoteIP:  "mcp-stdio",
			}
			if logErr := s.auditLogger.Record(ev); logErr != nil {
				// Non-fatal audit log recording error
			}
		}

		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: string(data)}},
			IsError: false,
		}

	case "resolve_target":
		var args struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("parse arguments: %v", err)}},
				IsError: true,
			}
		}
		if strings.TrimSpace(args.Query) == "" {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: "query parameter cannot be empty"}},
				IsError: true,
			}
		}

		target, err := s.resolver.Resolve(ctx, args.Query)
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: err.Error()}},
				IsError: true,
			}
		}

		data, err := json.MarshalIndent(target, "", "  ")
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("marshal target: %v", err)}},
				IsError: true,
			}
		}
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: string(data)}},
			IsError: false,
		}

	case "scrub_text":
		var args struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("parse arguments: %v", err)}},
				IsError: true,
			}
		}
		scrubbed := scrubber.Scrub(args.Text)
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: string(scrubbed)}},
			IsError: false,
		}

	case "introspect_template":
		var args struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("parse arguments: %v", err)}},
				IsError: true,
			}
		}
		if strings.TrimSpace(args.Query) == "" {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: "query parameter cannot be empty"}},
				IsError: true,
			}
		}

		target, err := s.resolver.Resolve(ctx, args.Query)
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("resolve target %s: %v", args.Query, err)}},
				IsError: true,
			}
		}

		schema, err := s.introspector.Introspect(ctx, *target)
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("introspect template for %s: %v", args.Query, err)}},
				IsError: true,
			}
		}

		data, err := json.MarshalIndent(schema, "", "  ")
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("marshal template schema: %v", err)}},
				IsError: true,
			}
		}
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: string(data)}},
			IsError: false,
		}

	case "draft_bug_report":
		var args struct {
			Query             string `json:"query"`
			Title             string `json:"title"`
			Summary           string `json:"summary"`
			StepsToReproduce  string `json:"steps_to_reproduce"`
			Logs              string `json:"logs"`
			StrictQuality     bool   `json:"strict_quality"`
			VerifyCmd         string `json:"verify_cmd"`
			IncludeTelemetry  bool   `json:"include_telemetry"`
			RelatedDependency string `json:"related_dependency"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("parse arguments: %v", err)}},
				IsError: true,
			}
		}
		if strings.TrimSpace(args.Query) == "" || strings.TrimSpace(args.Title) == "" {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: "query and title parameters are required"}},
				IsError: true,
			}
		}

		var proof *verifier.VerificationProof
		if strings.TrimSpace(args.VerifyCmd) != "" {
			p, err := verifier.Verify(ctx, verifier.VerifyOptions{Command: args.VerifyCmd})
			if err != nil {
				return toolCallResult{
					Content: []toolContent{{Type: "text", Text: fmt.Sprintf("verify reproduction command: %v", err)}},
					IsError: true,
				}
			}
			proof = p
			if strings.TrimSpace(args.Logs) == "" && proof.ScrubbedOutput != "" {
				args.Logs = string(proof.ScrubbedOutput)
			}
		}

		target, err := s.resolver.Resolve(ctx, args.Query)
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("resolve target %s: %v", args.Query, err)}},
				IsError: true,
			}
		}

		schema, err := s.introspector.Introspect(ctx, *target)
		if err != nil {
			schema = nil
		}

		var dups []dedup.ExistingIssue
		if s.dedupFinder != nil {
			if d, err := s.dedupFinder.FindDuplicates(ctx, *target, scrubber.Scrub(args.Title)); err == nil {
				dups = d
			}
		}

		var sysTelemetry *telemetry.SystemTelemetry
		if args.IncludeTelemetry {
			t := telemetry.Collect(ctx)
			sysTelemetry = &t
		}

		var relatedIssues []dedup.ExistingIssue
		if strings.TrimSpace(args.RelatedDependency) != "" {
			relTarget, relErr := s.resolver.Resolve(ctx, strings.TrimSpace(args.RelatedDependency))
			if relErr == nil && relTarget != nil && s.dedupFinder != nil {
				searchQuery := scrubber.Scrub(args.Title + " " + args.Summary)
				if relDups, err := s.dedupFinder.FindDuplicates(ctx, *relTarget, searchQuery); err == nil {
					relatedIssues = relDups
				}
			}
		}

		draft, err := adapter.BuildDraft(adapter.DraftInput{
			Target:            *target,
			Title:             args.Title,
			Summary:           args.Summary,
			StepsToReproduce:  args.StepsToReproduce,
			Logs:              args.Logs,
			Template:          schema,
			Duplicates:        dups,
			Verification:      proof,
			Telemetry:         sysTelemetry,
			RelatedDependency: args.RelatedDependency,
			RelatedIssues:     relatedIssues,
		})
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("build draft: %v", err)}},
				IsError: true,
			}
		}

		if args.StrictQuality && !draft.Quality.Passed {
			qData, err := json.MarshalIndent(draft.Quality, "", "  ")
			if err != nil {
				return toolCallResult{
					Content: []toolContent{{Type: "text", Text: fmt.Sprintf("marshal quality report: %v", err)}},
					IsError: true,
				}
			}
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: string(qData)}},
				IsError: true,
			}
		}

		if _, err := s.draftStore.Save(draft); err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("save draft: %v", err)}},
				IsError: true,
			}
		}

		data, err := json.MarshalIndent(draft, "", "  ")
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("marshal draft: %v", err)}},
				IsError: true,
			}
		}
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: string(data)}},
			IsError: false,
		}

	case "search_duplicates":
		var args struct {
			Query string `json:"query"`
			Title string `json:"title"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("parse arguments: %v", err)}},
				IsError: true,
			}
		}
		if strings.TrimSpace(args.Query) == "" || strings.TrimSpace(args.Title) == "" {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: "query and title parameters are required"}},
				IsError: true,
			}
		}

		target, err := s.resolver.Resolve(ctx, args.Query)
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("resolve target %s: %v", args.Query, err)}},
				IsError: true,
			}
		}

		if s.dedupFinder == nil {
			s.dedupFinder = dedup.NewFinder(httpx.NewClient(0))
		}

		dups, err := s.dedupFinder.FindDuplicates(ctx, *target, scrubber.Scrub(args.Title))
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("find duplicates for %s: %v", args.Query, err)}},
				IsError: true,
			}
		}

		data, err := json.MarshalIndent(dups, "", "  ")
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("marshal duplicates: %v", err)}},
				IsError: true,
			}
		}
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: string(data)}},
			IsError: false,
		}

	case "list_staged_drafts":
		var args struct {
			Status string `json:"status"`
		}
		if len(params.Arguments) > 0 && string(params.Arguments) != "{}" && string(params.Arguments) != "null" {
			if err := json.Unmarshal(params.Arguments, &args); err != nil {
				return toolCallResult{
					Content: []toolContent{{Type: "text", Text: fmt.Sprintf("parse arguments: %v", err)}},
					IsError: true,
				}
			}
		}

		if s.draftStore == nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: "draft store not configured"}},
				IsError: true,
			}
		}

		drafts, err := s.draftStore.List()
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("list drafts: %v", err)}},
				IsError: true,
			}
		}

		if args.Status != "" {
			var filtered []*adapter.StagedDraft
			for _, d := range drafts {
				if strings.EqualFold(d.Status, args.Status) {
					filtered = append(filtered, d)
				}
			}
			drafts = filtered
		}
		if drafts == nil {
			drafts = []*adapter.StagedDraft{}
		}

		data, err := json.MarshalIndent(drafts, "", "  ")
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("marshal drafts: %v", err)}},
				IsError: true,
			}
		}
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: string(data)}},
			IsError: false,
		}

	case "approve_draft":
		var args struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("parse arguments: %v", err)}},
				IsError: true,
			}
		}
		if strings.TrimSpace(args.ID) == "" {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: "id parameter cannot be empty"}},
				IsError: true,
			}
		}

		if s.draftStore == nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: "draft store not configured"}},
				IsError: true,
			}
		}

		draft, err := s.draftStore.Get(args.ID)
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("get draft %s: %v", args.ID, err)}},
				IsError: true,
			}
		}

		if draft.Status == "submitted" {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: "draft is already submitted"}},
				IsError: true,
			}
		}

		if draft.Status == "companion_only" || (draft.Template != nil && draft.Template.Policy != nil && draft.Template.Policy.AIOptOut) {
			reason := "upstream restrictions"
			if draft.Template != nil && draft.Template.Policy != nil && draft.Template.Policy.OptOutReason != "" {
				reason = draft.Template.Policy.OptOutReason
			}
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("maintainer policy opt-out: upstream repository restricts automated/AI submissions (%s); use draft as a local human companion only", reason)}},
				IsError: true,
			}
		}

		var issueURL string
		if s.forgeClient != nil {
			issueURL, err = s.forgeClient.Submit(ctx, draft)
			if err != nil {
				if s.auditLogger != nil {
					failEv := cloud.AuditEvent{
						Timestamp: time.Now().UTC(),
						Action:    "draft.submit_failed",
						DraftID:   args.ID,
						Target:    draft.Target.CanonicalName,
						Protocol:  draft.Target.Tracker.Protocol,
						RemoteIP:  "mcp-stdio",
						Error:     err.Error(),
					}
					if logErr := s.auditLogger.Record(failEv); logErr != nil {
						fmt.Fprintf(os.Stderr, "audit log record error: %v\n", logErr)
					}
					if s.webhookNotifier != nil {
						if notifyErr := s.webhookNotifier.Notify(ctx, failEv); notifyErr != nil {
							fmt.Fprintf(os.Stderr, "webhook notify error: %v\n", notifyErr)
						}
					}
				}
				return toolCallResult{
					Content: []toolContent{{Type: "text", Text: fmt.Sprintf("submit draft %s: %v", args.ID, err)}},
					IsError: true,
				}
			}
		} else if draft.SubmissionURL != "" {
			issueURL = draft.SubmissionURL
		}

		draft.Status = "submitted"
		if issueURL != "" {
			draft.SubmissionURL = issueURL
		}

		if _, err := s.draftStore.Save(draft); err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("save approved draft %s: %v", args.ID, err)}},
				IsError: true,
			}
		}

		if s.auditLogger != nil {
			ev := cloud.AuditEvent{
				Timestamp: time.Now().UTC(),
				Action:    "draft.approved",
				DraftID:   args.ID,
				Target:    draft.Target.CanonicalName,
				Protocol:  draft.Target.Tracker.Protocol,
				IssueURL:  issueURL,
				RemoteIP:  "mcp-stdio",
			}
			if logErr := s.auditLogger.Record(ev); logErr != nil {
				fmt.Fprintf(os.Stderr, "audit log record error: %v\n", logErr)
			}
			if s.webhookNotifier != nil {
				if notifyErr := s.webhookNotifier.Notify(ctx, ev); notifyErr != nil {
					fmt.Fprintf(os.Stderr, "webhook notify error: %v\n", notifyErr)
				}
			}
		}

		resp := map[string]any{
			"status":    "submitted",
			"issue_url": issueURL,
			"draft_id":  draft.ID,
		}
		data, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("marshal response: %v", err)}},
				IsError: true,
			}
		}
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: string(data)}},
			IsError: false,
		}

	case "triage_crash_log":
		var args struct {
			Log   string `json:"log"`
			Title string `json:"title"`
			Query string `json:"query"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("parse arguments: %v", err)}},
				IsError: true,
			}
		}
		if strings.TrimSpace(args.Log) == "" {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: "log parameter cannot be empty"}},
				IsError: true,
			}
		}

		candidates := resolver.ExtractTargetsFromLog(args.Log)
		var resolvedTarget *resolver.Target

		if strings.TrimSpace(args.Query) != "" {
			t, err := s.resolver.Resolve(ctx, strings.TrimSpace(args.Query))
			if err == nil && t != nil {
				resolvedTarget = t
			}
		}

		if resolvedTarget == nil {
			for _, c := range candidates {
				t, err := s.resolver.Resolve(ctx, c.Query)
				if err == nil && t != nil {
					resolvedTarget = t
					break
				}
			}
		}

		var schema *introspector.TemplateSchema
		var dups []dedup.ExistingIssue

		if resolvedTarget != nil {
			tmpl, err := s.introspector.Introspect(ctx, *resolvedTarget)
			if err == nil {
				schema = tmpl
			}

			searchTitle := args.Title
			if searchTitle == "" && len(candidates) > 0 {
				searchTitle = candidates[0].Evidence
			}
			if searchTitle != "" && s.dedupFinder != nil {
				d, err := s.dedupFinder.FindDuplicates(ctx, *resolvedTarget, scrubber.Scrub(searchTitle))
				if err == nil {
					dups = d
				}
			}
		}

		var nextActions []string
		if resolvedTarget != nil {
			nextActions = append(nextActions, fmt.Sprintf("Run 'bugrouter draft --title <title> --steps <steps> %s' to stage a verified bug ticket", resolvedTarget.CanonicalName))
			if len(dups) > 0 {
				nextActions = append(nextActions, "Review potential upstream duplicates before submitting")
			}
			if schema != nil && schema.Name != "" {
				nextActions = append(nextActions, fmt.Sprintf("Fill required fields defined in upstream issue template: %s", schema.Name))
			}
		} else {
			nextActions = append(nextActions, "No candidates could be automatically resolved to an upstream tracker. Specify target manually via '--query <target>'")
		}

		if dups == nil {
			dups = []dedup.ExistingIssue{}
		}
		if candidates == nil {
			candidates = []resolver.TraceCandidate{}
		}

		result := map[string]any{
			"candidates":           candidates,
			"resolved_target":      resolvedTarget,
			"template_schema":      schema,
			"potential_duplicates": dups,
			"scrubbed_log":         scrubber.Scrub(args.Log),
			"next_actions":         nextActions,
		}

		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("marshal triage result: %v", err)}},
				IsError: true,
			}
		}
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: string(data)}},
			IsError: false,
		}

	case "verify_reproduction":
		var args struct {
			Command        string `json:"command"`
			TimeoutSeconds int    `json:"timeout_seconds"`
			ExpectExit     int    `json:"expect_exit"`
		}
		if err := json.Unmarshal(params.Arguments, &args); err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("parse arguments: %v", err)}},
				IsError: true,
			}
		}
		if strings.TrimSpace(args.Command) == "" {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: "command parameter cannot be empty"}},
				IsError: true,
			}
		}

		timeout := 15 * time.Second
		if args.TimeoutSeconds > 0 {
			timeout = time.Duration(args.TimeoutSeconds) * time.Second
		}

		proof, err := verifier.Verify(ctx, verifier.VerifyOptions{
			Command:    args.Command,
			Timeout:    timeout,
			ExpectExit: args.ExpectExit,
		})
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("verify reproduction: %v", err)}},
				IsError: true,
			}
		}

		data, err := json.MarshalIndent(proof, "", "  ")
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("marshal proof: %v", err)}},
				IsError: true,
			}
		}
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: string(data)}},
			IsError: false,
		}

	case "scan_workspace_stack":
		var args struct {
			Dir           string `json:"dir"`
			CheckUpstream bool   `json:"check_upstream"`
		}
		if len(params.Arguments) > 0 && string(params.Arguments) != "{}" && string(params.Arguments) != "null" {
			if err := json.Unmarshal(params.Arguments, &args); err != nil {
				return toolCallResult{
					Content: []toolContent{{Type: "text", Text: fmt.Sprintf("parse arguments: %v", err)}},
					IsError: true,
				}
			}
		}
		dir := args.Dir
		if strings.TrimSpace(dir) == "" {
			dir = "."
		}

		report, err := dedup.BuildStackRadar(ctx, s.resolver, s.dedupFinder, dir, args.CheckUpstream)
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("scan workspace stack: %v", err)}},
				IsError: true,
			}
		}

		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("marshal stack report: %v", err)}},
				IsError: true,
			}
		}
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: string(data)}},
			IsError: false,
		}

	case "collect_system_telemetry":
		t := telemetry.Collect(ctx)
		data, err := json.MarshalIndent(t, "", "  ")
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("marshal telemetry: %v", err)}},
				IsError: true,
			}
		}
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: string(data)}},
			IsError: false,
		}

	case "read_system_crash_log":
		return s.handleReadSystemCrashLog(ctx, params.Arguments)

	default:
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: fmt.Sprintf("unknown tool: %s", params.Name)}},
			IsError: true,
		}
	}
}

func (s *Server) handleParkBug(ctx context.Context, args json.RawMessage, out io.Writer) toolCallResult {
	if s.parkedStore == nil {
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: "parked store is not initialized"}},
			IsError: true,
		}
	}

	var input struct {
		Dependency        string `json:"dependency"`
		Title             string `json:"title"`
		ErrorSnippet      string `json:"error_snippet"`
		WorkaroundNote    string `json:"workaround_note"`
		WorkspaceFile     string `json:"workspace_file"`
		RelatedDependency string `json:"related_dependency"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: fmt.Sprintf("invalid arguments: %v", err)}},
			IsError: true,
		}
	}

	bug, handoff, err := s.parkedStore.Park(input.Dependency, input.Title, input.ErrorSnippet, input.WorkaroundNote, input.WorkspaceFile, input.RelatedDependency)
	if err != nil {
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: fmt.Sprintf("failed to park bug: %v", err)}},
			IsError: true,
		}
	}

	// Emit native MCP notification so host knows resources changed before returning result
	if out != nil {
		notification := map[string]any{
			"jsonrpc": "2.0",
			"method":  "notifications/resources/list_changed",
		}
		if data, err := json.Marshal(notification); err == nil {
			if _, writeErr := out.Write(append(data, '\n')); writeErr != nil {
				// Non-fatal notification emit error
			}
		}
	}

	resultMap := map[string]any{
		"parked_bug": bug,
		"handoff":    handoff,
	}
	data, err := json.MarshalIndent(resultMap, "", "  ")
	if err != nil {
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: fmt.Sprintf("failed to marshal handoff payload: %v", err)}},
			IsError: true,
		}
	}

	return toolCallResult{
		Content: []toolContent{{Type: "text", Text: string(data)}},
	}
}

func (s *Server) handleReadSystemCrashLog(ctx context.Context, args json.RawMessage) toolCallResult {
	var input struct {
		Query string `json:"query"`
		Title string `json:"title"`
	}
	if len(args) > 0 && string(args) != "{}" && string(args) != "null" {
		if err := json.Unmarshal(args, &input); err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("parse arguments: %v", err)}},
				IsError: true,
			}
		}
	}

	rawLog, suspect, err := resolver.ReadLatestCrash(ctx)
	if err != nil {
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: fmt.Sprintf("read system crash log: %v", err)}},
			IsError: true,
		}
	}

	candidates := resolver.ExtractTargetsFromLog(rawLog)
	if suspect != "" {
		found := false
		for _, c := range candidates {
			if strings.EqualFold(c.Query, suspect) {
				found = true
				break
			}
		}
		if !found {
			candidates = append([]resolver.TraceCandidate{{
				Query:    suspect,
				Source:   "os_crash_suspect",
				Evidence: "OS post-mortem crash log suspect binary: " + suspect,
			}}, candidates...)
		}
	}

	var resolvedTarget *resolver.Target
	if strings.TrimSpace(input.Query) != "" {
		t, err := s.resolver.Resolve(ctx, strings.TrimSpace(input.Query))
		if err == nil && t != nil {
			resolvedTarget = t
		}
	}

	if resolvedTarget == nil && suspect != "" {
		t, err := s.resolver.Resolve(ctx, suspect)
		if err == nil && t != nil {
			resolvedTarget = t
		}
	}

	if resolvedTarget == nil {
		for _, c := range candidates {
			t, err := s.resolver.Resolve(ctx, c.Query)
			if err == nil && t != nil {
				resolvedTarget = t
				break
			}
		}
	}

	var schema *introspector.TemplateSchema
	var dups []dedup.ExistingIssue

	if resolvedTarget != nil {
		tmpl, err := s.introspector.Introspect(ctx, *resolvedTarget)
		if err == nil {
			schema = tmpl
		}

		searchTitle := input.Title
		if searchTitle == "" && suspect != "" {
			searchTitle = fmt.Sprintf("crash in %s", suspect)
		} else if searchTitle == "" && len(candidates) > 0 {
			searchTitle = candidates[0].Evidence
		}
		if searchTitle != "" && s.dedupFinder != nil {
			d, err := s.dedupFinder.FindDuplicates(ctx, *resolvedTarget, scrubber.Scrub(searchTitle))
			if err == nil {
				dups = d
			}
		}
	}

	var nextActions []string
	if resolvedTarget != nil {
		nextActions = append(nextActions, fmt.Sprintf("Run 'bugrouter draft --title <title> --steps <steps> %s' to stage a verified bug ticket", resolvedTarget.CanonicalName))
		if len(dups) > 0 {
			nextActions = append(nextActions, "Review potential upstream duplicates before submitting")
		}
		if schema != nil && schema.Name != "" {
			nextActions = append(nextActions, fmt.Sprintf("Fill required fields defined in upstream issue template: %s", schema.Name))
		}
	} else {
		nextActions = append(nextActions, "No candidates could be automatically resolved to an upstream tracker. Specify target manually via '--query <target>'")
	}

	if dups == nil {
		dups = []dedup.ExistingIssue{}
	}
	if candidates == nil {
		candidates = []resolver.TraceCandidate{}
	}

	result := map[string]any{
		"suspect":              suspect,
		"candidates":           candidates,
		"resolved_target":      resolvedTarget,
		"template_schema":      schema,
		"potential_duplicates": dups,
		"scrubbed_log":         scrubber.Scrub(rawLog),
		"next_actions":         nextActions,
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: fmt.Sprintf("marshal triage result: %v", err)}},
			IsError: true,
		}
	}
	return toolCallResult{
		Content: []toolContent{{Type: "text", Text: string(data)}},
		IsError: false,
	}
}
