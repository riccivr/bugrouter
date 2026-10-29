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
	if len(tools) != 11 {
		t.Errorf("expected 11 tools, got %d", len(tools))
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
