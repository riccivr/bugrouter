package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/cloud"
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
	resolver     *resolver.Waterfall
	draftStore   *adapter.DraftStore
	introspector *introspector.Introspector
	forgeClient  adapter.ForgeSubmitter
}

// NewServer creates an MCP server backed by the provided waterfall and draft store.
func NewServer(wf *resolver.Waterfall, store *adapter.DraftStore) *Server {
	httpClient := httpx.NewClient(0)
	return &Server{
		resolver:     wf,
		draftStore:   store,
		introspector: introspector.New(httpClient),
		forgeClient:  cloud.NewForgeClient(httpClient),
	}
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

		draft, err := adapter.BuildDraft(adapter.DraftInput{
			Target:           *target,
			Title:            args.Title,
			Summary:          args.Summary,
			StepsToReproduce: args.StepsToReproduce,
			Logs:             args.Logs,
			Template:         schema,
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

		var issueURL string
		if s.forgeClient != nil {
			issueURL, err = s.forgeClient.Submit(ctx, draft)
			if err != nil {
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

	default:
		return toolCallResult{
			Content: []toolContent{{Type: "text", Text: fmt.Sprintf("unknown tool: %s", params.Name)}},
			IsError: true,
		}
	}
}
