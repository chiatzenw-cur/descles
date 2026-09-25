package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractToolEvidenceOpenAI(t *testing.T) {
	body := map[string]any{
		"model": "deepseek-chat",
		"messages": []any{
			map[string]any{"role": "user", "content": "read the config"},
			map[string]any{"role": "assistant", "content": "",
				"tool_calls": []any{map[string]any{
					"id": "call_1", "type": "function",
					"function": map[string]any{"name": "read_file", "arguments": `{"file_path":"/etc/app.conf"}`},
				}},
			},
			map[string]any{"role": "tool", "tool_call_id": "call_1", "content": "server.port=8080\ndebug=true"},
		},
	}
	b, _ := json.Marshal(body)
	ev := extractToolEvidence(b)
	if len(ev) != 1 {
		t.Fatalf("want 1 evidence, got %d", len(ev))
	}
	e := ev[0]
	if e.Tool != "read_file" || e.Resource != "file:///etc/app.conf" {
		t.Errorf("bad tool/resource: %+v", e)
	}
	if e.Op != "read" {
		t.Errorf("op = %s, want read", e.Op)
	}
	if e.Status != "result_reported" || e.ContentLen == 0 || e.ContentHash == "" {
		t.Errorf("evidence incomplete: %+v", e)
	}
	if !strings.Contains(e.Preview, "server.port") {
		t.Errorf("preview should show result text: %q", e.Preview)
	}
}

func TestExtractToolEvidenceOpenAIWebAndWrite(t *testing.T) {
	body := map[string]any{
		"model": "gpt-4o",
		"messages": []any{
			map[string]any{"role": "user", "content": "check the docs"},
			map[string]any{"role": "assistant", "content": "",
				"tool_calls": []any{
					map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "web_fetch", "arguments": `{"url":"https://docs.stripe.com/api"}`}},
					map[string]any{"id": "c2", "type": "function", "function": map[string]any{"name": "create_issue", "arguments": `{"repo":"acme/backend"}`}},
				}},
			map[string]any{"role": "tool", "tool_call_id": "c1", "content": "API reference page body..."},
			map[string]any{"role": "tool", "tool_call_id": "c2", "content": "issue created #42"},
		},
	}
	b, _ := json.Marshal(body)
	ev := extractToolEvidence(b)
	if len(ev) != 2 {
		t.Fatalf("want 2, got %d", len(ev))
	}
	if ev[0].Resource != "https://docs.stripe.com/api" || ev[0].Op != "read" {
		t.Errorf("web evidence: %+v", ev[0])
	}
	if ev[1].Resource != "github:acme/backend" || ev[1].Op != "write" {
		t.Errorf("issue evidence: %+v", ev[1])
	}
}

func TestExtractToolEvidenceAnthropic(t *testing.T) {
	body := map[string]any{
		"model": "claude-sonnet",
		"messages": []any{
			map[string]any{"role": "user", "content": "look at src/main.go"},
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "tool_use", "id": "toolu_1", "name": "Read", "input": map[string]any{"file_path": "src/main.go"}},
			}},
			map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": "toolu_1", "content": "package main\nfunc main() {}"},
			}},
		},
	}
	b, _ := json.Marshal(body)
	ev := extractToolEvidenceAnthropic(b)
	if len(ev) != 1 {
		t.Fatalf("want 1, got %d", len(ev))
	}
	if ev[0].Tool != "Read" || ev[0].Resource != "file://src/main.go" || ev[0].Op != "read" {
		t.Errorf("evidence: %+v", ev[0])
	}
	if ev[0].ContentHash == "" || ev[0].ContentLen == 0 {
		t.Errorf("fingerprint missing: %+v", ev[0])
	}
}

func TestEvidencePreviewFollowsPayloadLogging(t *testing.T) {
	sample := func() []ToolEvidence {
		return []ToolEvidence{{Tool: "read_file", Resource: "file://app/.env", ContentLen: 9, ContentHash: "abc", Preview: "SECRET=hunter2"}}
	}
	off := &Handler{}
	if ev := off.evidence(sample()); ev[0].Preview != "" || ev[0].ContentHash != "abc" {
		t.Fatalf("payload logging off must drop result text but keep the fingerprint: %+v", ev[0])
	}
	on := &Handler{}
	on.Cfg.LogPayloads = true
	if ev := on.evidence(sample()); ev[0].Preview == "" {
		t.Fatal("payload logging on keeps the preview")
	}
}
