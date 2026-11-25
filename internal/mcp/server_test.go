package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luminariadev/raksa-netguard/internal/baseline"
)

type stubCollector struct {
	listeners []baseline.Listener
}

func (s stubCollector) Collect(context.Context) ([]baseline.Listener, error) {
	return s.listeners, nil
}

func TestServer_SessionAndAllTools(t *testing.T) {
	srv := NewServer("0.3.0", stubCollector{
		listeners: []baseline.Listener{
			{Protocol: "tcp", BindAddr: "0.0.0.0", Port: 443, PID: "100", ProcessName: "nginx", State: "LISTENING"},
			{Protocol: "tcp", BindAddr: "0.0.0.0", Port: 23, PID: "200", ProcessName: "telnetd", State: "LISTENING"},
		},
	})

	policyYAML := "version: \"1.0\"\nallowed_ports:\n  - port: 443\n    protocol: tcp\n    allowed_binds: [\"0.0.0.0\"]\n    allow_public: true\nforbidden_ports:\n  - port: 23\n    protocol: tcp\n    reason: \"Telnet prohibited\"\n"
	inlineLog := strings.Join([]string{
		`{"timestamp":"2026-11-25T15:00:01Z","src_ip":"198.51.100.42","dst_ip":"192.0.2.10","dst_port":21,"proto":"TCP","action":"BLOCK"}`,
		`{"timestamp":"2026-11-25T15:00:02Z","src_ip":"198.51.100.42","dst_ip":"192.0.2.10","dst_port":22,"proto":"TCP","action":"BLOCK"}`,
		`{"timestamp":"2026-11-25T15:00:03Z","src_ip":"198.51.100.42","dst_ip":"192.0.2.10","dst_port":80,"proto":"TCP","action":"BLOCK"}`,
		`{"timestamp":"2026-11-25T15:00:04Z","src_ip":"198.51.100.42","dst_ip":"192.0.2.10","dst_port":443,"proto":"TCP","action":"BLOCK"}`,
	}, "\n")

	reqs := []any{
		map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2024-11-05"}},
		map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"},
		map[string]any{"jsonrpc": "2.0", "id": 2, "method": "ping"},
		map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
		map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{"name": "netguard_list_rules"}},
		map[string]any{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": map[string]any{"name": "netguard_check_policy", "arguments": map[string]any{"policy_path": filepath.Join("..", "..", "configs", "baseline.example.yaml")}}},
		map[string]any{"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": map[string]any{"name": "netguard_audit_host", "arguments": map[string]any{"policy_yaml": policyYAML}}},
		map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{"name": "netguard_generate_baseline", "arguments": map[string]any{"host_role": "edge-gw"}}},
		map[string]any{"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": map[string]any{"name": "netguard_analyze_logs", "arguments": map[string]any{"log_content": inlineLog, "vertical_threshold": 4}}},
		map[string]any{"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": map[string]any{"name": "nonexistent_tool"}},
		map[string]any{"jsonrpc": "2.0", "id": 10, "method": "unknown/method"},
	}

	var inBuf bytes.Buffer
	for _, r := range reqs {
		b, _ := json.Marshal(r)
		inBuf.Write(b)
		inBuf.WriteByte('\n')
	}
	inBuf.WriteString("{not valid json\n")

	var outBuf bytes.Buffer
	if err := srv.Serve(context.Background(), &inBuf, &outBuf); err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
	// 12 input lines minus 1 notification = 11 responses
	if len(lines) != 11 {
		t.Fatalf("expected 11 JSON-RPC responses, got %d:\n%s", len(lines), outBuf.String())
	}

	byID := make(map[string]rpcResponse, len(lines))
	for _, line := range lines {
		var resp rpcResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("invalid response JSON %q: %v", line, err)
		}
		byID[string(resp.ID)] = resp
	}

	// 1. initialize
	initRaw, _ := json.Marshal(byID["1"].Result)
	if !strings.Contains(string(initRaw), `"raksa-netguard"`) || !strings.Contains(string(initRaw), `"2024-11-05"`) {
		t.Fatalf("unexpected initialize response: %s", initRaw)
	}

	// 3. tools/list has all 5 tools
	listRaw, _ := json.Marshal(byID["3"].Result)
	for _, tool := range []string{"netguard_list_rules", "netguard_check_policy", "netguard_audit_host", "netguard_generate_baseline", "netguard_analyze_logs"} {
		if !strings.Contains(string(listRaw), tool) {
			t.Fatalf("tools/list missing %s: %s", tool, listRaw)
		}
	}

	// 4. list_rules
	if !strings.Contains(extractToolText(t, byID["4"]), "NET-104") {
		t.Fatalf("expected NET-104 in netguard_list_rules output")
	}

	// 5. check_policy clean
	if !strings.Contains(extractToolText(t, byID["5"]), `"total": 0`) {
		t.Fatalf("expected 0 findings on clean policy, got: %s", extractToolText(t, byID["5"]))
	}

	// 6. audit_host detects forbidden port 23
	auditText := extractToolText(t, byID["6"])
	if !strings.Contains(auditText, "NET-001") || !strings.Contains(auditText, "telnetd") {
		t.Fatalf("expected NET-001 with telnetd in audit_host output: %s", auditText)
	}

	// 7. generate_baseline produces edge-gw YAML
	genText := extractToolText(t, byID["7"])
	if !strings.Contains(genText, "edge-gw") || !strings.Contains(genText, "policy_yaml") {
		t.Fatalf("unexpected generate_baseline output: %s", genText)
	}

	// 8. analyze_logs detects NET-101
	anaText := extractToolText(t, byID["8"])
	if !strings.Contains(anaText, "NET-101") {
		t.Fatalf("expected NET-101 in analyze_logs output: %s", anaText)
	}

	// 9. unknown tool returns isError=true result
	resBytes, _ := json.Marshal(byID["9"].Result)
	if !strings.Contains(string(resBytes), `"isError":true`) {
		t.Fatalf("expected isError=true for unknown tool, got %s", resBytes)
	}

	// 10. unknown method returns JSON-RPC -32601
	if byID["10"].Error == nil || byID["10"].Error.Code != -32601 {
		t.Fatalf("expected -32601 for unknown method, got %+v", byID["10"])
	}

	// Parse error returns -32700 with id null
	if byID["null"].Error == nil || byID["null"].Error.Code != -32700 {
		t.Fatalf("expected -32700 parse error, got %+v", byID["null"])
	}
}

func extractToolText(t *testing.T, resp rpcResponse) string {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("unexpected rpc error: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	var tr toolResult
	if err := json.Unmarshal(raw, &tr); err != nil {
		t.Fatalf("decode toolResult: %v", err)
	}
	if tr.IsError || len(tr.Content) == 0 {
		t.Fatalf("expected non-error tool content, got %+v", tr)
	}
	return tr.Content[0].Text
}
