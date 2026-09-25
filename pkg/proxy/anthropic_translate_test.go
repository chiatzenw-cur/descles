package proxy_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/config"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/pricing"
	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/proxy"
	"github.com/chiatzenw-cur/descles/pkg/storage"
)

// newTranslatedFixture wires a handler whose single tenant slot is OpenAI-wire,
// with a model alias map, and returns it with the upstream call recorder.
func newTranslatedFixture(t *testing.T, upstream *httptest.Server, wire string) *proxy.Handler {
	t.Helper()
	cfg := config.Config{Storage: "memory", LogLevel: "error", GatewayDomain: "gw.descles.com",
		UpstreamTimeout: 5 * time.Second}
	h := proxy.New(cfg, provider.NewRegistry(nil), policy.NewHolder(policy.AllowAll()),
		storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.KeyResolver = func(key string) (string, string, string, bool) {
		return "org1", "", "agent1", key == "dsk_test_translate"
	}
	h.OrgUpstream = func(orgID, providerName string) (string, string, bool) {
		if orgID == "org1" {
			return upstream.URL, "sk-upstream", true
		}
		return "", "", false
	}
	h.OrgSlotConfig = func(orgID, slot string) (string, map[string]string, string, bool) {
		return wire, map[string]string{"claude-*": "deepseek-chat"}, "", true
	}
	return h
}

func translatedRequest(t *testing.T, h *proxy.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Host = "anthropic.gw.descles.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Authorization", "Bearer dsk_test_translate")
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	return rr
}

// A Claude Code client asks for a Claude alias; the slot is OpenAI-wire, so the
// request must reach the upstream as chat/completions carrying the mapped model,
// and the answer must come back in the Anthropic envelope with a tool_use block.
func TestAnthropicPlaneTranslatesToOpenAIWire(t *testing.T) {
	var gotPath, gotAuth, gotModel string
	var gotHasTools bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		buf, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(buf, &req)
		gotModel, _ = req["model"].(string)
		_, gotHasTools = req["tools"]
		if _, leaked := req["thinking"]; leaked {
			t.Errorf("Anthropic-only field leaked upstream: %s", buf)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"chatcmpl-1","model":"deepseek-chat","choices":[{"index":0,"finish_reason":"tool_calls",
		  "message":{"content":"checking","tool_calls":[{"id":"call_1","type":"function","function":{"name":"Bash","arguments":"{\"command\":\"ls\"}"}}]}}],
		  "usage":{"prompt_tokens":30,"completion_tokens":5}}`)
	}))
	defer upstream.Close()

	h := newTranslatedFixture(t, upstream, "openai")
	rr := translatedRequest(t, h, `{"model":"claude-opus-5","max_tokens":64,
	  "tools":[{"name":"Bash","description":"run","input_schema":{"type":"object"}}],
	  "messages":[{"role":"user","content":"list files"}]}`)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if gotPath != "/v1/chat/completions" {
		t.Fatalf("upstream path = %q, want the OpenAI wire", gotPath)
	}
	if gotAuth != "Bearer sk-upstream" {
		t.Fatalf("upstream credential = %q", gotAuth)
	}
	if gotModel != "deepseek-chat" {
		t.Fatalf("upstream model = %q, want the alias-mapped name", gotModel)
	}
	if !gotHasTools {
		t.Fatalf("tools were dropped in translation")
	}

	var out struct {
		ID         string `json:"id"`
		Model      string `json:"model"`
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		Usage struct {
			Input  int `json:"input_tokens"`
			Output int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not an Anthropic message: %v (%s)", err, rr.Body.String())
	}
	if !strings.HasPrefix(out.ID, "msg_") {
		t.Fatalf("id = %q, want an Anthropic-shaped id", out.ID)
	}
	if out.Model != "claude-opus-5" {
		t.Fatalf("model = %q, want the alias the client asked for echoed back", out.Model)
	}
	if out.StopReason != "tool_use" {
		t.Fatalf("stop_reason = %q", out.StopReason)
	}
	var tool *struct {
		Type  string          `json:"type"`
		Text  string          `json:"text"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	}
	for i := range out.Content {
		if out.Content[i].Type == "tool_use" {
			tool = &out.Content[i]
		}
	}
	if tool == nil || !strings.HasPrefix(tool.ID, "toolu_") || tool.Name != "Bash" || string(tool.Input) != `{"command":"ls"}` {
		t.Fatalf("tool_use block wrong: %+v", out.Content)
	}
	if out.Usage.Input != 30 || out.Usage.Output != 5 {
		t.Fatalf("usage not carried across: %+v", out.Usage)
	}

	// Cost must be priced on the model that served the call, not on the alias
	// the client asked for: pricing the alias charges Claude rates for a
	// DeepSeek answer (the fixture maps claude-* -> deepseek-chat).
	spans, err := h.Store.ListRecent(context.Background(), 3)
	if err != nil {
		t.Fatalf("list spans: %v", err)
	}
	var cost float64
	for _, s := range spans {
		if v, ok := s.Attributes["cost_usd"].(float64); ok && v > 0 {
			cost = v
		}
	}
	want := pricing.Estimate("deepseek-chat", 30, 5, 0)
	if cost == 0 {
		t.Fatalf("no cost recorded: %v", spans)
	}
	if cost > want*1.0001 || cost < want*0.9999 {
		t.Fatalf("cost = %v, want %v (priced on the upstream model)", cost, want)
	}
	if aliasPrice := pricing.Estimate("claude-opus-5", 30, 5, 0); cost == aliasPrice {
		t.Fatalf("cost matches the ALIAS price (%v) — priced on what the client asked for", aliasPrice)
	}
}

func TestAnthropicPlanePassesThroughWhenSlotIsAnthropicWire(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Header.Get("x-api-key") != "sk-upstream" {
			t.Errorf("x-api-key = %q", r.Header.Get("x-api-key"))
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg-1","type":"message","role":"assistant","model":"claude-opus-5","content":[{"type":"text","text":"native"}],"usage":{"input_tokens":3,"output_tokens":2}}`)
	}))
	defer upstream.Close()

	h := newTranslatedFixture(t, upstream, "anthropic")
	rr := translatedRequest(t, h, `{"model":"claude-opus-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if gotPath != "/v1/messages" {
		t.Fatalf("upstream path = %q, want byte-for-byte passthrough", gotPath)
	}
	if !strings.Contains(rr.Body.String(), "native") {
		t.Fatalf("body altered: %s", rr.Body.String())
	}
}

// The streamed answer must be an Anthropic event sequence, including a tool_use
// block rebuilt from fragmented OpenAI tool-call deltas.
func TestAnthropicPlaneStreamsTranslatedEvents(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		write := func(s string) {
			_, _ = io.WriteString(w, s)
			if flusher != nil {
				flusher.Flush()
			}
		}
		write("data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel\"},\"finish_reason\":null}]}\n\n")
		write("data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":null}]}\n\n")
		write("data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_9\",\"function\":{\"name\":\"Bash\",\"arguments\":\"{\\\"command\\\":\"}}]},\"finish_reason\":null}]}\n\n")
		write("data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"ls\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n")
		write("data: {\"id\":\"c1\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":4}}\n\n")
		write("data: [DONE]\n\n")
	}))
	defer upstream.Close()

	h := newTranslatedFixture(t, upstream, "openai")
	rr := translatedRequest(t, h, `{"model":"claude-opus-5","max_tokens":64,"stream":true,
	  "messages":[{"role":"user","content":"run ls"}]}`)
	body := rr.Body.String()

	for _, want := range []string{
		"event: message_start",
		"event: content_block_start",
		"event: content_block_delta",
		"event: content_block_stop",
		`"type":"text_delta"`,
		`"text":"Hel"`,
		`"type":"tool_use"`,
		`"name":"Bash"`,
		`"type":"input_json_delta"`,
		`"partial_json":"{\"command\":\"ls\"}"`,
		`"stop_reason":"tool_use"`,
		"event: message_stop",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stream missing %s\n--- got ---\n%s", want, body)
		}
	}
	if strings.Count(body, "event: message_start") != 1 || strings.Count(body, "event: message_stop") != 1 {
		t.Fatalf("stream envelope repeated:\n%s", body)
	}
	if strings.Contains(body, `"role":"assistant","model":"deepseek-chat"`) {
		t.Fatalf("upstream model name leaked to the client:\n%s", body)
	}
	if !strings.Contains(body, `"model":"claude-opus-5"`) {
		t.Fatalf("client alias not echoed:\n%s", body)
	}
}

// An upstream failure must reach the client in the Anthropic error envelope,
// carrying the upstream's status.
func TestAnthropicPlaneTranslatesUpstreamError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"error":{"message":"rate limited by upstream","type":"rate_limit_error"}}`)
	}))
	defer upstream.Close()

	h := newTranslatedFixture(t, upstream, "openai")
	rr := translatedRequest(t, h, `{"model":"claude-opus-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, rr.Body.String())
	}
	if out.Type != "error" || out.Error.Type != "rate_limit_error" || out.Error.Message != "rate limited by upstream" {
		t.Fatalf("error not translated: %+v", out)
	}
}

func TestOpenAIChatURLNormalizesStoredOrigin(t *testing.T) {
	cases := map[string]string{
		"https://api.deepseek.com":     "https://api.deepseek.com/v1/chat/completions",
		"https://api.deepseek.com/":    "https://api.deepseek.com/v1/chat/completions",
		"https://api.openai.com/v1":    "https://api.openai.com/v1/chat/completions",
		"https://gw.internal/v1/proxy": "https://gw.internal/v1/proxy/chat/completions",
		"http://127.0.0.1:8000/v1/":    "http://127.0.0.1:8000/v1/chat/completions",
	}
	for in, want := range cases {
		got := proxy.ExportOpenAIChatURL(in)
		if got != want {
			t.Fatalf("openAIChatURL(%q) = %q, want %q", in, got, want)
		}
	}
}
