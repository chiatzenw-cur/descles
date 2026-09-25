package proxy_test

import (
	"encoding/json"
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

func chunk(id, model string, toolCalls []map[string]any, finish *string) string {
	delta := map[string]any{}
	if toolCalls != nil {
		delta["tool_calls"] = toolCalls
	}
	m := map[string]any{
		"id": id, "object": "chat.completion.chunk", "model": model, "created": 1,
		"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
	}
	b, _ := json.Marshal(m)
	return "data: " + string(b) + "\n\n"
}

func tc(index int, id, name, args string) map[string]any {
	return map[string]any{
		"index": index, "id": id, "type": "function",
		"function": map[string]any{"name": name, "arguments": args},
	}
}

// relayFilter runs the streaming policy filter over an upstream SSE body.
func relayFilter(t *testing.T, body string, pol *policy.Holder) (string, *proxy.Handler) {
	t.Helper()
	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", DenyEnforce: true}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(up.Close)
	reg := provider.NewRegistry([]provider.Config{{Name: "deepseek", BaseURL: up.URL, Models: []string{"*"}}})
	h := proxy.New(cfg, reg, pol, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.ApprovalSuspender = func(agentID, tool string, args map[string]any) (string, error) {
		return "appr-123", nil
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"deepseek-chat","stream":true,"messages":[{"role":"user","content":"x"}]}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	return rr.Body.String(), h
}

func TestStreamingToolDenyAndSuspend(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny","kubectl.delete":"require_approval"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	sse := chunk("c1", "deepseek-chat", nil, nil) +
		chunk("c2", "deepseek-chat", []map[string]any{tc(0, "call_1", "shell.rm", `{"path":"/etc"}`)}, nil) +
		chunk("c3", "deepseek-chat", []map[string]any{tc(1, "call_2", "kubectl.delete", `{"pod":"prod"}`)}, nil) +
		chunk("c4", "deepseek-chat", nil, strPtr("tool_calls")) +
		"data: [DONE]\n\n"

	out, _ := relayFilter(t, sse, policy.NewHolder(pol))
	if strings.Contains(out, "call_1") || strings.Contains(out, "call_2") {
		t.Errorf("blocked tool calls must not reach the client:\n%s", out)
	}
	if !strings.Contains(out, "[blocked by Descles policy: shell.rm]") {
		t.Errorf("missing deny note:\n%s", out)
	}
	if !strings.Contains(out, "[pending human approval: kubectl.delete (approval appr-123)]") {
		t.Errorf("missing approval note:\n%s", out)
	}
	if !strings.Contains(out, `"finish_reason":"stop"`) {
		t.Errorf("finish_reason should be stop when all tools blocked:\n%s", out)
	}
}

func TestStreamingToolAllowPassthroughCompactsIndexes(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	sse := chunk("c1", "deepseek-chat", []map[string]any{
		tc(0, "call_bad", "shell.rm", `{}`),
		tc(1, "call_ok", "get_weather", `{"city":"Toronto"}`),
	}, nil) +
		chunk("c2", "deepseek-chat", nil, strPtr("tool_calls")) +
		"data: [DONE]\n\n"

	out, _ := relayFilter(t, sse, policy.NewHolder(pol))
	if strings.Contains(out, "call_bad") {
		t.Errorf("denied call leaked:\n%s", out)
	}
	if !strings.Contains(out, "call_ok") {
		t.Errorf("allowed call missing:\n%s", out)
	}
	// The allowed call must be renumbered to index 0 so clients see a compact
	// contiguous tool_calls array.
	if !strings.Contains(out, `"index":0,"id":"call_ok"`) && !strings.Contains(out, `"id":"call_ok","index":0`) {
		t.Errorf("allowed call index not compacted:\n%s", out)
	}
	if !strings.Contains(out, `"finish_reason":"tool_calls"`) {
		t.Errorf("finish_reason should stay tool_calls when some tools allowed:\n%s", out)
	}
}

func TestResumedCallFlowsThrough(t *testing.T) {
	// Policy requires approval for get_weather. With NO resumer the call is
	// parked; with a resumer that says "approved" it must flow through as a
	// real tool call (no note, no suspension).
	pol, err := policy.FromJSON(`{"defaults":{"require_approval":["get_weather"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	body := "data: " + `{"id":"x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_ok","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Toronto\"}"}}]},"finish_reason":null}]}` + "\n\n" +
		"data: " + `{"id":"x","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n" +
		"data: [DONE]\n\n"

	out, _ := relayFilter(t, body, policy.NewHolder(pol))
	if !strings.Contains(out, "pending human approval") {
		t.Errorf("no resumer: call should be parked with a note:\n%s", out)
	}

	// Now wire a resumer that grants the call — must pass through untouched.
	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", DenyEnforce: true}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(up.Close)
	reg := provider.NewRegistry([]provider.Config{{Name: "deepseek", BaseURL: up.URL, Models: []string{"*"}}})
	h := proxy.New(cfg, reg, policy.NewHolder(pol), store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.ApprovalResumer = func(agentID, tool string, args map[string]any) bool {
		return tool == "get_weather" && args["city"] == "Toronto"
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"deepseek-chat","stream":true,"messages":[{"role":"user","content":"x"}]}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	out2 := rr.Body.String()
	if !strings.Contains(out2, "call_ok") {
		t.Errorf("resumed call should flow through as a real tool call:\n%s", out2)
	}
	if strings.Contains(out2, "pending human approval") {
		t.Errorf("resumed call must not be parked again:\n%s", out2)
	}
	if !strings.Contains(out2, `"finish_reason":"tool_calls"`) {
		t.Errorf("finish_reason should stay tool_calls when the resumed call survives:\n%s", out2)
	}
}

func TestBlockingApprovalAllowsStreamingCallInSameTurn(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"require_approval":["get_weather"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	body := "data: " + `{"id":"x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_ok","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Toronto\"}"}}]},"finish_reason":null}]}` + "\n\n" +
		"data: " + `{"id":"x","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n" +
		"data: [DONE]\n\n"

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", DenyEnforce: true}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(up.Close)
	reg := provider.NewRegistry([]provider.Config{{Name: "deepseek", BaseURL: up.URL, Models: []string{"*"}}})
	h := proxy.New(cfg, reg, policy.NewHolder(pol), store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.ApprovalSuspender = func(agentID, tool string, args map[string]any) (string, error) {
		return "appr-blocking", nil
	}
	blocked := false
	h.ApprovalBlocker = func(approvalID, agentID, tool string, args map[string]any) policy.Decision {
		blocked = true
		if approvalID != "appr-blocking" || tool != "get_weather" || args["city"] != "Toronto" {
			t.Fatalf("blocking gate received wrong approval binding: id=%q tool=%q args=%v", approvalID, tool, args)
		}
		return policy.Allow
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"deepseek-chat","stream":true,"messages":[{"role":"user","content":"weather"}]}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	out := rr.Body.String()
	if !blocked {
		t.Fatal("streaming call never entered the blocking approval gate")
	}
	if !strings.Contains(out, "call_ok") || !strings.Contains(out, `"finish_reason":"tool_calls"`) {
		t.Fatalf("approved streaming call did not survive in the original turn:\n%s", out)
	}
	if strings.Contains(out, "pending human approval") || strings.Contains(out, "denied by human approval") {
		t.Fatalf("approved same-turn stream leaked an approval note into agent context:\n%s", out)
	}
}

func TestStreamingTextIsNotBuffered(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	sse := chunk("c1", "deepseek-chat", nil, nil)
	_ = sse
	// Plain text chunks must pass through unchanged (no tool segment).
	body := "data: " + `{"id":"x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hello "},"finish_reason":null}]}` + "\n\n" +
		"data: " + `{"id":"x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"world"},"finish_reason":"stop"}]}` + "\n\n" +
		"data: [DONE]\n\n"
	out, _ := relayFilter(t, body, policy.NewHolder(pol))
	if !strings.Contains(out, `"content":"Hello "`) || !strings.Contains(out, `"content":"world"`) {
		t.Errorf("text chunks should pass through untouched:\n%s", out)
	}
}

func strPtr(s string) *string { return &s }
