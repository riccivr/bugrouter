package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/cloud"
	"github.com/riccivr/bugrouter/internal/dedup"
	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/introspector"
	"github.com/riccivr/bugrouter/internal/resolver"
)

type mockSubmitter struct {
	submittedURL string
}

func (m *mockSubmitter) Submit(ctx context.Context, draft *adapter.StagedDraft) (string, error) {
	return m.submittedURL, nil
}

func TestMCPServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/expressjs/express/contents/.github/ISSUE_TEMPLATE":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `[{"name": "bug.yml", "download_url": "http://%s/raw/bug.yml", "type": "file"}]`, r.Host)
		case "/raw/bug.yml":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, `
name: Bug Report
body:
  - type: textarea
    id: what-happened
    attributes:
      label: What happened?
`)
		case "/search/issues":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"items": [{"number": 42, "title": "Crash on start with memory error", "html_url": "https://github.com/expressjs/express/issues/42", "state": "open"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	wf := resolver.NewWaterfall(time.Second, resolver.NewDirectProbe())
	intro := introspector.New(httpx.NewTestClient(time.Second)).WithEndpoints(introspector.Endpoints{
		GitHubAPIBaseURL: ts.URL,
	})
	finder := dedup.NewFinder(httpx.NewTestClient(time.Second)).WithEndpoints(dedup.Endpoints{
		GitHubAPIBaseURL: ts.URL,
	})
	mockSub := &mockSubmitter{submittedURL: "https://github.com/expressjs/express/issues/999"}
	server := NewServer(wf, store).WithIntrospector(intro).WithFinder(finder).WithForgeClient(mockSub)

	var in bytes.Buffer
	var out bytes.Buffer

	// 1. initialize
	in.WriteString(`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n")
	// 2. notifications/initialized (notification - should produce no response)
	in.WriteString(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	// 3. ping
	in.WriteString(`{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n")
	// 4. tools/list
	in.WriteString(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}` + "\n")
	// 5. tools/call: scrub_text
	in.WriteString(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"scrub_text","arguments":{"text":"Bearer token123 in /home/alice"}}}` + "\n")
	// 6. tools/call: resolve_target
	in.WriteString(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"resolve_target","arguments":{"query":"https://github.com/expressjs/express"}}}` + "\n")
	// 7. tools/call: introspect_template
	in.WriteString(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"introspect_template","arguments":{"query":"https://github.com/expressjs/express"}}}` + "\n")
	// 8. tools/call: search_duplicates
	in.WriteString(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"search_duplicates","arguments":{"query":"https://github.com/expressjs/express","title":"Crash on start with memory error"}}}` + "\n")
	// 9. tools/call: draft_bug_report
	in.WriteString(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"draft_bug_report","arguments":{"query":"https://github.com/expressjs/express","title":"Crash on start with memory error","summary":"Failed with AKIAIOSFODNN7EXAMPLE","steps_to_reproduce":"Run server","logs":"error stack"}}}` + "\n")
	// 10. tools/call: list_staged_drafts
	in.WriteString(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"list_staged_drafts","arguments":{}}}` + "\n")
	// 11. unknown method
	in.WriteString(`{"jsonrpc":"2.0","id":10,"method":"unknown_cmd"}` + "\n")

	if err := server.Run(context.Background(), &in, &out); err != nil {
		t.Fatalf("Server.Run failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 10 {
		t.Fatalf("expected 10 responses (notification has no response), got %d: %v", len(lines), lines)
	}

	// Response 1: initialize
	var resp1 jsonrpcResponse
	if err := json.Unmarshal([]byte(lines[0]), &resp1); err != nil {
		t.Fatalf("unmarshal resp1: %v", err)
	}
	res1 := resp1.Result.(map[string]any)
	if res1["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion = %v, want %s", res1["protocolVersion"], ProtocolVersion)
	}
	caps := res1["capabilities"].(map[string]any)
	if caps["resources"] == nil || caps["prompts"] == nil {
		t.Errorf("expected resources and prompts in capabilities, got: %v", caps)
	}

	// Response 2: ping
	var resp2 jsonrpcResponse
	if err := json.Unmarshal([]byte(lines[1]), &resp2); err != nil {
		t.Fatalf("unmarshal resp2: %v", err)
	}
	if resp2.Error != nil {
		t.Errorf("ping error: %v", resp2.Error)
	}

	// Response 3: tools/list
	var resp3 jsonrpcResponse
	if err := json.Unmarshal([]byte(lines[2]), &resp3); err != nil {
		t.Fatalf("unmarshal resp3: %v", err)
	}
	res3 := resp3.Result.(map[string]any)
	tools := res3["tools"].([]any)
	if len(tools) != 13 {
		t.Errorf("expected 13 tools, got %d", len(tools))
	}
	if len(tools) > 0 && tools[0].(map[string]any)["name"] != "park_bug" {
		t.Errorf("expected first tool to be park_bug, got %v", tools[0].(map[string]any)["name"])
	}
	if len(tools) > 1 && tools[1].(map[string]any)["name"] != "record_dependency_patch" {
		t.Errorf("expected second tool to be record_dependency_patch, got %v", tools[1].(map[string]any)["name"])
	}

	// Response 4: tools/call scrub_text
	var resp4 jsonrpcResponse
	if err := json.Unmarshal([]byte(lines[3]), &resp4); err != nil {
		t.Fatalf("unmarshal resp4: %v", err)
	}
	res4 := resp4.Result.(map[string]any)
	if res4["isError"] != false {
		t.Errorf("scrub_text isError = true")
	}
	content4 := res4["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(content4, "[REDACTED_TOKEN]") || !strings.Contains(content4, "~") {
		t.Errorf("scrub_text content not redacted: %s", content4)
	}

	// Response 5: tools/call resolve_target
	var resp5 jsonrpcResponse
	if err := json.Unmarshal([]byte(lines[4]), &resp5); err != nil {
		t.Fatalf("unmarshal resp5: %v", err)
	}
	res5 := resp5.Result.(map[string]any)
	if res5["isError"] != false {
		t.Errorf("resolve_target isError = true")
	}
	content5 := res5["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(content5, `"canonical_name": "express"`) {
		t.Errorf("resolve_target missing express: %s", content5)
	}

	// Response 6: tools/call introspect_template
	var resp6 jsonrpcResponse
	if err := json.Unmarshal([]byte(lines[5]), &resp6); err != nil {
		t.Fatalf("unmarshal resp6: %v", err)
	}
	res6 := resp6.Result.(map[string]any)
	if res6["isError"] != false {
		t.Errorf("introspect_template isError = true: %v", res6)
	}
	content6 := res6["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(content6, "github-form") || !strings.Contains(content6, "what-happened") {
		t.Errorf("introspect_template response missing expected schema: %s", content6)
	}

	// Response 7: tools/call search_duplicates
	var respDups jsonrpcResponse
	if err := json.Unmarshal([]byte(lines[6]), &respDups); err != nil {
		t.Fatalf("unmarshal respDups: %v", err)
	}
	resDups := respDups.Result.(map[string]any)
	if resDups["isError"] != false {
		t.Errorf("search_duplicates isError = true: %v", resDups)
	}
	contentDups := resDups["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(contentDups, "Crash on start with memory error") || !strings.Contains(contentDups, "express/issues/42") {
		t.Errorf("search_duplicates response missing duplicate issue: %s", contentDups)
	}

	// Response 8: tools/call draft_bug_report
	var resp7 jsonrpcResponse
	if err := json.Unmarshal([]byte(lines[7]), &resp7); err != nil {
		t.Fatalf("unmarshal resp7: %v", err)
	}
	res7 := resp7.Result.(map[string]any)
	if res7["isError"] != false {
		t.Errorf("draft_bug_report isError = true: %v", res7)
	}
	content7 := res7["content"].([]any)[0].(map[string]any)["text"].(string)
	var staged adapter.StagedDraft
	if err := json.Unmarshal([]byte(content7), &staged); err != nil {
		t.Fatalf("unmarshal staged draft: %v", err)
	}
	if staged.Status != "pending_review" {
		t.Errorf("Status = %q, want pending_review", staged.Status)
	}
	if strings.Contains(string(staged.MarkdownBody), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("staged draft body leaked AWS key")
	}
	if staged.Template == nil || staged.Template.FileName != "bug.yml" {
		t.Errorf("staged draft missing introspected template: %+v", staged.Template)
	}
	if len(staged.PotentialDuplicates) != 1 {
		t.Errorf("staged draft expected 1 potential duplicate, got %d", len(staged.PotentialDuplicates))
	}

	// Response 9: tools/call list_staged_drafts
	var resp8 jsonrpcResponse
	if err := json.Unmarshal([]byte(lines[8]), &resp8); err != nil {
		t.Fatalf("unmarshal resp8: %v", err)
	}
	res8 := resp8.Result.(map[string]any)
	if res8["isError"] != false {
		t.Errorf("list_staged_drafts isError = true: %v", res8)
	}
	content8 := res8["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(content8, staged.ID) {
		t.Errorf("list_staged_drafts missing created draft id: %s", content8)
	}

	// Response 10: unknown method error
	var resp9 jsonrpcResponse
	if err := json.Unmarshal([]byte(lines[9]), &resp9); err != nil {
		t.Fatalf("unmarshal resp9: %v", err)
	}
	if resp9.Error == nil || resp9.Error.Code != -32601 {
		t.Errorf("expected -32601 error for unknown method, got: %+v", resp9.Error)
	}

	// Test approve_draft separately with AuditLogger
	auditLogPath := filepath.Join(tempDir, "audit.log")
	auditLogger := cloud.NewAuditLogger(auditLogPath)

	var inApprove, outApprove bytes.Buffer
	inApprove.WriteString(fmt.Sprintf(`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"approve_draft","arguments":{"id":%q}}}`+"\n", staged.ID))
	serverApprove := NewServer(wf, store).WithForgeClient(mockSub).WithAuditLogger(auditLogger)
	if err := serverApprove.Run(context.Background(), &inApprove, &outApprove); err != nil {
		t.Fatalf("serverApprove.Run failed: %v", err)
	}
	var respApprove jsonrpcResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(outApprove.String())), &respApprove); err != nil {
		t.Fatalf("unmarshal approve response: %v", err)
	}
	if respApprove.Result.(map[string]any)["isError"] != false {
		t.Errorf("approve_draft isError = true")
	}
	contentApprove := respApprove.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(contentApprove, "submitted") || !strings.Contains(contentApprove, mockSub.submittedURL) {
		t.Errorf("approve_draft result missing expected content: %s", contentApprove)
	}

	// Verify audit log entry was recorded by MCP approve_draft
	events, err := auditLogger.ListRecent(10)
	if err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected at least 1 audit event from MCP approve_draft, got 0")
	}
	if events[0].Action != "draft.approved" || events[0].DraftID != staged.ID || events[0].RemoteIP != "mcp-stdio" {
		t.Errorf("unexpected audit event recorded: %+v", events[0])
	}

	// Verify idempotent approval in MCP: approving again returns isError: true stating already submitted
	var inApproveAgain, outApproveAgain bytes.Buffer
	inApproveAgain.WriteString(fmt.Sprintf(`{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"approve_draft","arguments":{"id":%q}}}`+"\n", staged.ID))
	if err := serverApprove.Run(context.Background(), &inApproveAgain, &outApproveAgain); err != nil {
		t.Fatalf("serverApprove.Run again failed: %v", err)
	}
	var respApproveAgain jsonrpcResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(outApproveAgain.String())), &respApproveAgain); err != nil {
		t.Fatalf("unmarshal second approve response: %v", err)
	}
	resApproveAgain := respApproveAgain.Result.(map[string]any)
	if resApproveAgain["isError"] != true {
		t.Errorf("second approve_draft isError = false, want true")
	}
	contentApproveAgain := resApproveAgain["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(contentApproveAgain, "draft is already submitted") {
		t.Errorf("second approve_draft error message = %q, want 'draft is already submitted'", contentApproveAgain)
	}
}

func TestTriageCrashLogTool(t *testing.T) {
	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	wf := resolver.NewWaterfall(0, resolver.NewDirectProbe())
	server := NewServer(wf, store)

	log := `panic: runtime error: slice bounds out of range [:20] with capacity 10

goroutine 1 [running]:
github.com/example/worker.ProcessItems(0xc000088000)
	/go/pkg/mod/github.com/example/worker@v1.2.0/process.go:88 +0x34
`

	var in, out bytes.Buffer
	reqPayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "triage_crash_log",
			"arguments": map[string]any{
				"log": log,
			},
		},
	}
	reqBytes, err := json.Marshal(reqPayload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	in.Write(append(reqBytes, '\n'))

	if err := server.Run(context.Background(), &in, &out); err != nil {
		t.Fatalf("server.Run failed: %v", err)
	}

	var resp jsonrpcResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	resMap := resp.Result.(map[string]any)
	if resMap["isError"] != false {
		t.Fatalf("triage_crash_log isError = true: %v", resMap)
	}

	rawText := resMap["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(rawText, "github.com/example/worker") || !strings.Contains(rawText, "candidates") {
		t.Errorf("triage result missing expected tokens: %s", rawText)
	}
}

func TestVerifyReproductionTool(t *testing.T) {
	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	wf := resolver.NewWaterfall(time.Second, resolver.NewDirectProbe())
	server := NewServer(wf, store)

	var in, out bytes.Buffer
	reqPayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "verify_reproduction",
			"arguments": map[string]any{
				"command": "echo reproduced-output",
			},
		},
	}
	reqBytes, err := json.Marshal(reqPayload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	in.Write(append(reqBytes, '\n'))

	if err := server.Run(context.Background(), &in, &out); err != nil {
		t.Fatalf("server.Run failed: %v", err)
	}

	var resp jsonrpcResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	resMap, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result map, got: %v", resp.Result)
	}
	if resMap["isError"] != false {
		t.Fatalf("verify_reproduction isError = true: %v", resMap)
	}

	rawText := resMap["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(rawText, "reproduced-output") || !strings.Contains(rawText, "proof_digest") {
		t.Errorf("verify result missing expected content: %s", rawText)
	}
}

func TestDraftBugReportStrictQualityRejection(t *testing.T) {
	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	wf := resolver.NewWaterfall(time.Second, resolver.NewDirectProbe())
	server := NewServer(wf, store)

	var in, out bytes.Buffer
	reqPayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "draft_bug_report",
			"arguments": map[string]any{
				"query":          "https://github.com/expressjs/express",
				"title":          "bug",
				"summary":        "As an AI, I noticed that express crashed.",
				"strict_quality": true,
			},
		},
	}
	reqBytes, err := json.Marshal(reqPayload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	in.Write(append(reqBytes, '\n'))

	if err := server.Run(context.Background(), &in, &out); err != nil {
		t.Fatalf("server.Run failed: %v", err)
	}

	var resp jsonrpcResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	resMap, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result map, got: %v", resp.Result)
	}
	if resMap["isError"] != true {
		t.Fatalf("expected isError = true for strict quality failure, got: %v", resMap)
	}

	rawText := resMap["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(rawText, "passed") || !strings.Contains(rawText, "false") {
		t.Errorf("expected quality report in rejection output: %s", rawText)
	}

	// Verify no draft was staged in store
	drafts, err := store.List()
	if err != nil {
		t.Fatalf("list drafts: %v", err)
	}
	if len(drafts) != 0 {
		t.Errorf("expected 0 drafts staged after rejection, got %d", len(drafts))
	}
}

func TestScanWorkspaceStackTool(t *testing.T) {
	tempDir := t.TempDir()
	store := adapter.NewDraftStore(tempDir)
	wf := resolver.NewWaterfall(time.Second, resolver.NewDirectProbe())
	server := NewServer(wf, store)

	pkgJsonContent := `{
		"dependencies": {
			"https://github.com/myorg/component": "1.0.0"
		}
	}`
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(pkgJsonContent), 0600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	var in, out bytes.Buffer
	reqPayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "scan_workspace_stack",
			"arguments": map[string]any{
				"dir": tempDir,
			},
		},
	}
	reqBytes, err := json.Marshal(reqPayload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	in.Write(append(reqBytes, '\n'))

	if err := server.Run(context.Background(), &in, &out); err != nil {
		t.Fatalf("server.Run failed: %v", err)
	}

	var resp jsonrpcResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	resMap, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result map, got: %v", resp.Result)
	}
	if resMap["isError"] != false {
		t.Fatalf("scan_workspace_stack isError = true: %v", resMap)
	}

	rawText := resMap["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(rawText, "component") || !strings.Contains(rawText, "total") {
		t.Errorf("scan_workspace_stack result missing expected tokens: %s", rawText)
	}
}

func TestCollectSystemTelemetryTool(t *testing.T) {
	wf := resolver.NewWaterfall(time.Second, resolver.NewDirectProbe())
	server := NewServer(wf, nil)

	var in, out bytes.Buffer
	reqPayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "collect_system_telemetry",
			"arguments": map[string]any{},
		},
	}
	reqBytes, err := json.Marshal(reqPayload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	in.Write(append(reqBytes, '\n'))

	if err := server.Run(context.Background(), &in, &out); err != nil {
		t.Fatalf("server.Run failed: %v", err)
	}

	var resp jsonrpcResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	resMap, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result map, got: %v", resp.Result)
	}
	if resMap["isError"] != false {
		t.Fatalf("collect_system_telemetry isError = true: %v", resMap)
	}

	rawText := resMap["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(rawText, `"os":`) || !strings.Contains(rawText, `"num_cpu":`) {
		t.Errorf("collect_system_telemetry result missing os or num_cpu: %s", rawText)
	}
}

func TestMCPParkBugHandoffResourcesAndPrompts(t *testing.T) {
	tempDir := t.TempDir()
	parkedStore := adapter.NewParkedStore(tempDir)
	server := NewServer(nil, nil).WithParkedStore(parkedStore)

	var in bytes.Buffer
	var out bytes.Buffer

	// 1. Call park_bug tool
	in.WriteString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"park_bug","arguments":{"dependency":"sharp","title":"libvips null pointer","error_snippet":"panic: nil pointer","workaround_note":"use jimp fallback","workspace_file":"src/img.ts:10"}}}` + "\n")
	// 2. Call resources/list
	in.WriteString(`{"jsonrpc":"2.0","id":2,"method":"resources/list"}` + "\n")
	// 3. Call prompts/list
	in.WriteString(`{"jsonrpc":"2.0","id":3,"method":"prompts/list"}` + "\n")

	if err := server.Run(context.Background(), &in, &out); err != nil {
		t.Fatalf("server.Run failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	// Notice: park_bug emits notifications/resources/list_changed notification line BEFORE response line!
	// So lines should be:
	// line 0: notification {"jsonrpc":"2.0","method":"notifications/resources/list_changed"}
	// line 1: tool call response (id=1)
	// line 2: resources/list response (id=2)
	// line 3: prompts/list response (id=3)
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines (1 notification + 3 responses), got %d: %v", len(lines), lines)
	}

	// Verify line 0: notification
	var notif map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &notif); err != nil {
		t.Fatalf("unmarshal notification: %v", err)
	}
	if notif["method"] != "notifications/resources/list_changed" {
		t.Errorf("expected notifications/resources/list_changed, got: %v", notif["method"])
	}

	// Verify line 1: park_bug response
	var respPark jsonrpcResponse
	if err := json.Unmarshal([]byte(lines[1]), &respPark); err != nil {
		t.Fatalf("unmarshal respPark: %v", err)
	}
	resPark := respPark.Result.(map[string]any)
	if resPark["isError"] != false {
		t.Fatalf("park_bug isError=true: %v", resPark)
	}
	parkText := resPark["content"].([]any)[0].(map[string]any)["text"].(string)

	var payload struct {
		ParkedBug adapter.ParkedBug      `json:"parked_bug"`
		Handoff   adapter.HandoffPayload `json:"handoff"`
	}
	if err := json.Unmarshal([]byte(parkText), &payload); err != nil {
		t.Fatalf("unmarshal parked text: %v", err)
	}
	if payload.ParkedBug.Dependency != "sharp" {
		t.Errorf("expected dependency sharp, got %q", payload.ParkedBug.Dependency)
	}
	if payload.Handoff.ResourceURI != "bugrouter://parked/"+payload.ParkedBug.ID {
		t.Errorf("expected resource URI bugrouter://parked/%s, got %q", payload.ParkedBug.ID, payload.Handoff.ResourceURI)
	}

	// Verify line 2: resources/list response
	var respResList jsonrpcResponse
	if err := json.Unmarshal([]byte(lines[2]), &respResList); err != nil {
		t.Fatalf("unmarshal respResList: %v", err)
	}
	resListMap := respResList.Result.(map[string]any)
	resArr := resListMap["resources"].([]any)
	if len(resArr) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resArr))
	}
	firstRes := resArr[0].(map[string]any)
	if firstRes["uri"] != "bugrouter://parked/"+payload.ParkedBug.ID {
		t.Errorf("resource uri = %v, want bugrouter://parked/%s", firstRes["uri"], payload.ParkedBug.ID)
	}

	// Verify line 3: prompts/list response
	var respPromptList jsonrpcResponse
	if err := json.Unmarshal([]byte(lines[3]), &respPromptList); err != nil {
		t.Fatalf("unmarshal respPromptList: %v", err)
	}
	promptListMap := respPromptList.Result.(map[string]any)
	promptArr := promptListMap["prompts"].([]any)
	if len(promptArr) != 1 {
		t.Fatalf("expected 1 prompt, got %d", len(promptArr))
	}
	firstPrompt := promptArr[0].(map[string]any)
	if firstPrompt["name"] != "triage_parked_bug" {
		t.Errorf("prompt name = %v, want triage_parked_bug", firstPrompt["name"])
	}

	// Now test resources/read and prompts/get
	var in2 bytes.Buffer
	var out2 bytes.Buffer

	in2.WriteString(fmt.Sprintf(`{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"bugrouter://parked/%s"}}`+"\n", payload.ParkedBug.ID))
	in2.WriteString(fmt.Sprintf(`{"jsonrpc":"2.0","id":5,"method":"prompts/get","params":{"name":"triage_parked_bug","arguments":{"id":"%s"}}}`+"\n", payload.ParkedBug.ID))

	if err := server.Run(context.Background(), &in2, &out2); err != nil {
		t.Fatalf("server.Run 2 failed: %v", err)
	}

	lines2 := strings.Split(strings.TrimSpace(out2.String()), "\n")
	if len(lines2) != 2 {
		t.Fatalf("expected 2 responses, got %d: %v", len(lines2), lines2)
	}

	// Verify resources/read
	var respResRead jsonrpcResponse
	if err := json.Unmarshal([]byte(lines2[0]), &respResRead); err != nil {
		t.Fatalf("unmarshal respResRead: %v", err)
	}
	resReadMap := respResRead.Result.(map[string]any)
	contents := resReadMap["contents"].([]any)
	if len(contents) != 1 {
		t.Fatalf("expected 1 content, got %d", len(contents))
	}
	contentItem := contents[0].(map[string]any)
	if contentItem["uri"] != "bugrouter://parked/"+payload.ParkedBug.ID {
		t.Errorf("content uri = %v, want bugrouter://parked/%s", contentItem["uri"], payload.ParkedBug.ID)
	}
	if !strings.Contains(contentItem["text"].(string), "libvips null pointer") {
		t.Errorf("content text missing bug title: %v", contentItem["text"])
	}

	// Verify prompts/get
	var respPromptGet jsonrpcResponse
	if err := json.Unmarshal([]byte(lines2[1]), &respPromptGet); err != nil {
		t.Fatalf("unmarshal respPromptGet: %v", err)
	}
	promptGetMap := respPromptGet.Result.(map[string]any)
	messages := promptGetMap["messages"].([]any)
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
	msgItem := messages[0].(map[string]any)
	msgContent := msgItem["content"].(map[string]any)
	promptText := msgContent["text"].(string)
	if !strings.Contains(promptText, "draft_bug_report") || !strings.Contains(promptText, "sharp") {
		t.Errorf("prompts/get text missing draft_bug_report or sharp: %s", promptText)
	}
}

func TestMCPRecordDependencyPatch(t *testing.T) {
	tempDir := t.TempDir()
	patchFile := filepath.Join(tempDir, "patches.json")
	patchStore := adapter.NewPatchStore(patchFile)

	server := NewServer(nil, nil).WithPatchStore(patchStore)

	var in bytes.Buffer
	var out bytes.Buffer

	callMsg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"record_dependency_patch","arguments":{"dependency":"sharp","patch_target":"patches/sharp+0.33.0.patch","reason":"Fix musl SIGSEGV","ecosystem":"npm","manifest_file":"package.json","upstream_issue_url":"https://github.com/lovell/sharp/issues/1234"}}}` + "\n"
	in.WriteString(callMsg)

	if err := server.Run(context.Background(), &in, &out); err != nil {
		t.Fatalf("server.Run failed: %v", err)
	}

	var resp jsonrpcResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response failed: %v", err)
	}

	resultMap := resp.Result.(map[string]any)
	if resultMap["isError"] != false {
		t.Fatalf("expected isError=false, got %+v", resultMap)
	}

	contentArr := resultMap["content"].([]any)
	if len(contentArr) != 1 {
		t.Fatalf("expected 1 content, got %d", len(contentArr))
	}
	text := contentArr[0].(map[string]any)["text"].(string)

	var recorded adapter.DependencyPatch
	if err := json.Unmarshal([]byte(text), &recorded); err != nil {
		t.Fatalf("unmarshal recorded patch failed: %v", err)
	}

	if recorded.Dependency != "sharp" {
		t.Errorf("expected dependency sharp, got %q", recorded.Dependency)
	}
	if recorded.PatchTarget != "patches/sharp+0.33.0.patch" {
		t.Errorf("expected patch target patches/sharp+0.33.0.patch, got %q", recorded.PatchTarget)
	}
	if recorded.Ecosystem != "npm" {
		t.Errorf("expected ecosystem npm, got %q", recorded.Ecosystem)
	}

	// Verify store state
	patches, err := patchStore.List()
	if err != nil {
		t.Fatalf("patchStore.List failed: %v", err)
	}
	if len(patches) != 1 || patches[0].ID != recorded.ID {
		t.Errorf("expected 1 patch in store, got %+v", patches)
	}
}
