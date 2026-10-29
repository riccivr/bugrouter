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
		introspector:    introspector.New(httpClient),
		forgeClient:     cloud.NewForgeClient(httpClient),
		dedupFinder:     dedup.NewFinder(httpClient),
		auditLogger:     cloud.NewAuditLogger(""),
		webhookNotifier: cloud.NewWebhookNotifier(httpClient, "", ""),
	}
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
		resp := s.handleRequest(ctx, req)

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

func (s *Server) handleRequest(ctx context.Context, req jsonrpcRequest) jsonrpcResponse {
	resp := jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities": map[string]any{
				"tools": map[string]any{},
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
		resp.Result = s.handleToolCall(ctx, params)

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
			"description": "Analyzes raw crash logs or stack traces, deterministically attributes failures to upstream dependencies, scrubs credentials, checks duplicates, and stages a quality-gated draft.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"log": map[string]any{
						"type":        "string",
						"description": "Raw crash log, stack trace, or panic output to analyze",
					},
					"target": map[string]any{
						"type":        "string",
						"description": "Optional target package name or repository query to override auto-attribution",
					},
					"title": map[string]any{
						"type":        "string",
						"description": "Optional bug report title override",
					},
					"strict_quality": map[string]any{
						"type":        "boolean",
						"description": "If true, enforces strict anti-slop quality gating and rejects drafts with violations",
					},
				},
				"required": []string{"log"},
			},
		},
	}
}

func (s *Server) handleToolCall(ctx context.Context, params toolCallParams) toolCallResult {
	switch params.Name {
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
			Query            string `json:"query"`
			Title            string `json:"title"`
			Summary          string `json:"summary"`
			StepsToReproduce string `json:"steps_to_reproduce"`
			Logs             string `json:"logs"`
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

		draft, err := adapter.BuildDraft(adapter.DraftInput{
			Target:           *target,
			Title:            args.Title,
			Summary:          args.Summary,
			StepsToReproduce: args.StepsToReproduce,
			Logs:             args.Logs,
			Template:         schema,
			Duplicates:       dups,
		})
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("build draft: %v", err)}},
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
			Log           string `json:"log"`
			Target        string `json:"target"`
			Title         string `json:"title"`
			StrictQuality bool   `json:"strict_quality"`
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

		attributor := resolver.NewTraceAttributor(s.resolver)
		var resolvedTarget *resolver.Target
		var rep *resolver.CrashReport

		if strings.TrimSpace(args.Target) != "" {
			var err error
			resolvedTarget, err = s.resolver.Resolve(ctx, args.Target)
			if err != nil {
				return toolCallResult{
					Content: []toolContent{{Type: "text", Text: fmt.Sprintf("resolve target %s: %v", args.Target, err)}},
					IsError: true,
				}
			}
			rep = resolver.ParseCrashTrace(args.Log)
			rep.PrimaryTarget = resolvedTarget.CanonicalName
		} else {
			var err error
			resolvedTarget, rep, err = attributor.AttributeAndResolve(ctx, args.Log)
			if err != nil && resolvedTarget == nil {
				if rep != nil && rep.PrimaryTarget != "" {
					resolvedTarget, err = s.resolver.Resolve(ctx, rep.PrimaryTarget)
				}
				if resolvedTarget == nil {
					return toolCallResult{
						Content: []toolContent{{Type: "text", Text: fmt.Sprintf("attribute and resolve crash: %v", err)}},
						IsError: true,
					}
				}
			}
		}

		title := args.Title
		if strings.TrimSpace(title) == "" {
			title = rep.SuggestedTitle()
		}

		summary := rep.SuggestedSummary()
		steps := rep.SuggestedSteps()
		logs := rep.CleanTrace()

		schema, err := s.introspector.Introspect(ctx, *resolvedTarget)
		if err != nil {
			schema = nil
		}

		var dups []dedup.ExistingIssue
		if s.dedupFinder != nil {
			if d, err := s.dedupFinder.FindDuplicates(ctx, *resolvedTarget, scrubber.Scrub(title)); err == nil {
				dups = d
			}
		}

		draft, err := adapter.BuildDraft(adapter.DraftInput{
			Target:           *resolvedTarget,
			Title:            title,
			Summary:          summary,
			StepsToReproduce: steps,
			Logs:             logs,
			Template:         schema,
			Duplicates:       dups,
		})
		if err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("build draft: %v", err)}},
				IsError: true,
			}
		}

		if args.StrictQuality && draft.Quality != nil && !draft.Quality.Passed {
			violMsg := adapter.FormatViolations(draft.Quality)
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("strict quality gate rejected draft:\n%s", violMsg)}},
				IsError: true,
			}
		}

		if _, err := s.draftStore.Save(draft); err != nil {
			return toolCallResult{
				Content: []toolContent{{Type: "text", Text: fmt.Sprintf("save draft: %v", err)}},
				IsError: true,
			}
		}

		resMap := map[string]any{
			"attribution": rep,
			"target":      resolvedTarget,
			"quality":     draft.Quality,
			"draft":       draft,
		}
		data, err := json.MarshalIndent(resMap, "", "  ")
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

	default:
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: fmt.Sprintf("unknown tool: %s", params.Name)}},
			IsError: true,
		}
	}
}
