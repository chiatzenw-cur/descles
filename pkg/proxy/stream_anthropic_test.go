package proxy_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/config"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/proxy"
	"github.com/chiatzenw-cur/descles/pkg/storage"
	"log/slog"
)

func anthropicEvent(evt, payload string) string {
	var b strings.Builder
	if evt != "" {
		b.WriteString("event: " + evt + "\n")
	}
	b.WriteString("data: " + payload + "\n\n")
	return b.String()
}

func msgStart(model string, in int) string {
	p, _ := json.Marshal(map[string]any{
		"type": "message_start",
		"message": map[string]any{"id": "msg_1", "model": model,
			"usage": map[string]any{"input_tokens": in, "output_tokens": 0}},
	})
	return anthropicEvent("message_start", string(p))
}

func contentBlockStart(idx int, block map[string]any) string {
	p, _ := json.Marshal(map[string]any{"type": "content_block_start", "index": idx, "content_block": block})
	return anthropicEvent("content_block_start", string(p))
}

func toolStart(idx int, id, name string) string {
	return contentBlockStart(idx, map[string]any{"type": "tool_use", "id": id, "name": name, "input": map[string]any{}})
}

func textStart(idx int, text string) string {
	return contentBlockStart(idx, map[string]any{"type": "text", "text": text})
}

func toolJSONDelta(idx int, partial string) string {
	p, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": idx,
		"delta": map[string]any{"type": "input_json_delta", "partial_json": partial}})
	return anthropicEvent("content_block_delta", string(p))
}

func blockStop(idx int) string {
	p, _ := json.Marshal(map[string]any{"type": "content_block_stop", "index": idx})
	return anthropicEvent("content_block_stop", string(p))
}

func msgDelta(stopReason string, out int) string {
	p, _ := json.Marshal(map[string]any{"type": "message_delta",
		"delta": map[string]any{"stop_reason": stopReason, "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": out}})
	return anthropicEvent("message_delta", string(p))
}

func anthropicStream(body string, pol *policy.Holder) (string, int) {
	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", DenyEnforce: true, AnthropicBaseURL: "", AnthropicAPIKey: ""}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, body)
	}))
	defer up.Close()
	reg := provider.NewRegistry(nil)
	h := proxy.New(cfg, reg, pol, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// These fixtures model an Anthropic-wire BYOK upstream, so declare it: an
	// undeclared slot whose URL carries no /anthropic path is treated as the
	// OpenAI wire and translated.
	h.OrgSlotConfig = func(string, string) (string, map[string]string, string, bool) {
		return "anthropic", nil, "", true
	}
	h.ApprovalSuspender = func(agentID, tool string, args map[string]any) (string, error) {
		return "appr-9", nil
	}
	// Point upstream at the fake server via per-request header (Anthropic handler honors it).
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4","stream":true,"max_tokens":1024,"messages":[{"role":"user","content":"x"}]}`))
	req.Header.Set("x-api-key", "dsk_test_x")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("X-Descles-Provider-Base-URL", up.URL)
	req.Header.Set("X-Descles-Provider-Key", "sk-ant-test")
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	return rr.Body.String(), rr.Code
}

func TestAnthropicStreamingFullBlock(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny","kubectl.delete":"require_approval"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	sse := msgStart("claude-sonnet-4", 10) +
		toolStart(0, "toolu_bad", "shell.rm") + toolJSONDelta(0, `{"path":"/etc"}`) + blockStop(0) +
		toolStart(1, "toolu_susp", "kubectl.delete") + toolJSONDelta(1, `{"pod":"prod"}`) + blockStop(1) +
		msgDelta("tool_use", 5)

	out, code := anthropicStream(sse, policy.NewHolder(pol))
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	if strings.Contains(out, "toolu_bad") || strings.Contains(out, "toolu_susp") {
		t.Errorf("blocked tool ids leaked:\n%s", out)
	}
	if strings.Contains(out, `"type":"tool_use"`) {
		t.Errorf("tool_use blocks must not reach client:\n%s", out)
	}
	if !strings.Contains(out, "[blocked by Descles policy: shell.rm]") {
		t.Errorf("missing deny note:\n%s", out)
	}
	if !strings.Contains(out, "[pending human approval: kubectl.delete (approval appr-9)]") {
		t.Errorf("missing approval note:\n%s", out)
	}
	if !strings.Contains(out, `"stop_reason":"end_turn"`) {
		t.Errorf("stop_reason must be end_turn when all tools blocked:\n%s", out)
	}
	if strings.Contains(out, `"stop_reason":"tool_use"`) {
		t.Errorf("original tool_use stop_reason leaked:\n%s", out)
	}
}

func TestAnthropicStreamingPartialAllowCompactsIndex(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	sse := msgStart("claude-sonnet-4", 10) +
		toolStart(0, "toolu_bad", "shell.rm") + toolJSONDelta(0, `{}`) + blockStop(0) +
		toolStart(1, "toolu_ok", "get_weather") + toolJSONDelta(1, `{"city":"Toronto"}`) + blockStop(1) +
		msgDelta("tool_use", 5)

	out, _ := anthropicStream(sse, policy.NewHolder(pol))
	if strings.Contains(out, "toolu_bad") {
		t.Errorf("denied tool leaked:\n%s", out)
	}
	if !strings.Contains(out, "toolu_ok") {
		t.Errorf("allowed tool missing:\n%s", out)
	}
	// Allowed block must be renumbered to index 0 (after the denied block).
	if !strings.Contains(out, `"index":0,"type":"content_block_start"`) &&
		!strings.Contains(out, `"type":"content_block_start","index":0`) {
		t.Errorf("allowed tool block not compacted to index 0:\n%s", out)
	}
	if !strings.Contains(out, `"stop_reason":"tool_use"`) {
		t.Errorf("stop_reason should stay tool_use when a tool survives:\n%s", out)
	}
}

func TestAnthropicStreamingTextThenBlockedTool(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	sse := msgStart("claude-sonnet-4", 10) +
		textStart(0, "") +
		anthropicEvent("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me check."}}`) +
		blockStop(0) +
		toolStart(1, "toolu_bad", "shell.rm") + toolJSONDelta(1, `{}`) + blockStop(1) +
		msgDelta("tool_use", 5)

	out, _ := anthropicStream(sse, policy.NewHolder(pol))
	if !strings.Contains(out, "Let me check.") {
		t.Errorf("text should stream through:\n%s", out)
	}
	if strings.Contains(out, "toolu_bad") {
		t.Errorf("denied tool block leaked:\n%s", out)
	}
	_ = fmt.Sprint() // keep fmt import if unused later
}
