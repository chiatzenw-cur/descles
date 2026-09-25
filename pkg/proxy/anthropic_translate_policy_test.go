package proxy_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math"
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
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// The governance claim on the translated path: a tool the org denies must not
// come back executable, on the non-streaming and the streaming route alike.
// Without this, translation would be a hole straight through the policy gate.
func TestTranslatedPathNonStreamEnforcesDeny(t *testing.T) {
	upstream := openAIToolUpstream(t)
	defer upstream.Close()

	pol, err := policy.FromJSON(`{"defaults":{"tools":{"Bash":"deny"}}}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	h := translatedFixture(t, upstream, pol)
	rr := translatedRequest(t, h, translatedToolBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"name":"Bash"`) {
		t.Fatalf("denied tool came back executable: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "blocked by Descles policy") {
		t.Fatalf("denied tool left no note for the model: %s", rr.Body.String())
	}
}

func TestTranslatedPathStreamEnforcesDeny(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		write := func(s string) {
			_, _ = io.WriteString(w, s)
			if flusher != nil {
				flusher.Flush()
			}
		}
		write("data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_5\",\"function\":{\"name\":\"Bash\",\"arguments\":\"{\\\"command\\\":\\\"rm -rf /\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n")
		write("data: {\"id\":\"c1\",\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":3}}\n\n")
		write("data: [DONE]\n\n")
	}))
	defer upstream.Close()

	pol, err := policy.FromJSON(`{"defaults":{"tools":{"Bash":"deny"}}}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	h := translatedFixture(t, upstream, pol)
	rr := translatedRequest(t, h, `{"model":"claude-opus-5","max_tokens":64,"stream":true,
	  "tools":[{"name":"Bash","description":"run","input_schema":{"type":"object"}}],
	  "messages":[{"role":"user","content":"clean up"}]}`)

	body := rr.Body.String()
	if !strings.Contains(body, "event: message_stop") {
		t.Fatalf("stream did not complete: %s", body)
	}
	if strings.Contains(body, `"name":"Bash"`) {
		t.Fatalf("denied tool reached the client as executable:\n%s", body)
	}
	if !strings.Contains(body, "blocked by Descles policy") {
		t.Fatalf("denied tool left no note in the stream:\n%s", body)
	}
	assertEveryFrameNamed(t, body)
}

// Translated streams must be accounted with the upstream's real token counts.
// A translated upstream reports prompt tokens only in its final chunk, so a
// policy-enforcing relay that reads input tokens from message_start alone
// recorded input_tokens=0 for every such call and under-reported cost.
func TestTranslatedStreamAccountingUsesRealUsage(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		write := func(s string) {
			_, _ = io.WriteString(w, s)
			if flusher != nil {
				flusher.Flush()
			}
		}
		// DeepSeek's shape: usage rides on the final content chunk.
		write("data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"OK\"},\"finish_reason\":null}]}\n\n")
		write("data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":123,\"completion_tokens\":7,\"total_tokens\":130}}\n\n")
		write("data: [DONE]\n\n")
	}))
	defer upstream.Close()

	// Policy with any tool rule so the enforcing relay (not the plain one) runs.
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"Bash":"deny"}}}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	h := translatedFixture(t, upstream, pol)
	rr := translatedRequest(t, h, `{"model":"claude-opus-5","max_tokens":32,"stream":true,
	  "messages":[{"role":"user","content":"say OK"}]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	spans, err := h.Store.ListRecent(context.Background(), 5)
	if err != nil {
		t.Fatalf("list spans: %v", err)
	}
	if len(spans) == 0 {
		t.Fatalf("no span stored for the translated stream")
	}
	span := spans[0]
	in, _ := span.Attributes[tracing.AttrInputToks].(int)
	out, _ := span.Attributes[tracing.AttrOutputToks].(int)
	cost, _ := span.Attributes[tracing.AttrCostUSD].(float64)
	if in != 123 || out != 7 {
		t.Fatalf("span usage = %d/%d, want 123/7 (attrs=%v)", in, out, span.Attributes)
	}
	if cost <= 0 {
		t.Fatalf("cost not computed: %v", cost)
	}
	if span.Attributes[tracing.AttrModel] != "claude-opus-5" {
		t.Fatalf("span model = %v", span.Attributes[tracing.AttrModel])
	}
	// The stream relay prices the call: it must use the model that served it,
	// not the alias the client asked for. The fixture maps claude-* ->
	// deepseek-chat, so an alias-priced span would charge the default rate
	// (~3.4x here) and the cost assertion below is what catches that.
	wantCost := pricing.Estimate("deepseek-chat", 123, 7, 0)
	aliasCost := pricing.Estimate("claude-opus-5", 123, 7, 0)
	if wantCost == aliasCost {
		t.Fatalf("fixture prices are indistinguishable (%v) — pick another model", wantCost)
	}
	if math.Abs(cost-wantCost) > wantCost*0.0001 {
		t.Fatalf("stream cost = %v, want %v (upstream-model price); alias price would be %v; attrs=%v",
			cost, wantCost, aliasCost, span.Attributes)
	}
	// The pricing-name resolution itself must prefer the serving model.
	probe := &tracing.Span{Attributes: map[string]any{"upstream_model": "deepseek-chat"}}
	if got := proxy.ExportPriceModelFor(probe, "claude-opus-5"); got != "deepseek-chat" {
		t.Fatalf("ExportPriceModelFor = %q, want the upstream model", got)
	}
}

// The non-streaming translated path prices the same way.
func TestTranslatedNonStreamCostUsesUpstreamModel(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c9","model":"deepseek-chat","choices":[{"index":0,"finish_reason":"stop",
		  "message":{"content":"ok"}}],"usage":{"prompt_tokens":400,"completion_tokens":0}}`)
	}))
	defer upstream.Close()

	pol, err := policy.FromJSON(`{}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	h := translatedFixture(t, upstream, pol)
	rr := translatedRequest(t, h, `{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	spans, err := h.Store.ListRecent(context.Background(), 3)
	if err != nil || len(spans) == 0 {
		t.Fatalf("no span: %v", err)
	}
	cost, _ := spans[0].Attributes[tracing.AttrCostUSD].(float64)
	want := pricing.Estimate("deepseek-chat", 400, 0, 0)
	if math.Abs(cost-want) > want*0.0001 {
		t.Fatalf("cost = %v, want %v (upstream-model price)", cost, want)
	}
}

// assertEveryFrameNamed enforces the SSE invariant the relay's synthesized and
// index-rewritten frames must satisfy: a frame with no `event:` line defaults to
// type "message", so an Anthropic client drops the block start and then chokes on
// deltas for a block it never opened ("tool call could not be parsed").
func assertEveryFrameNamed(t *testing.T, stream string) {
	t.Helper()
	for _, frame := range strings.Split(stream, "\n\n") {
		frame = strings.TrimSpace(frame)
		if frame == "" {
			continue
		}
		if !strings.HasPrefix(frame, "event: ") {
			t.Fatalf("SSE frame without an event name:\n%s\n--- full stream ---\n%s", frame, stream)
		}
		data := ""
		for _, line := range strings.Split(frame, "\n") {
			if strings.HasPrefix(line, "data: ") {
				data = strings.TrimPrefix(line, "data: ")
			}
		}
		var payload struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			t.Fatalf("frame data is not JSON: %s", frame)
		}
		if !strings.HasSuffix(strings.TrimSpace(frame), "event: "+payload.Type) &&
			!strings.HasPrefix(frame, "event: "+payload.Type) {
			t.Fatalf("event name does not match payload type (%s):\n%s", payload.Type, frame)
		}
	}
}

// The same invariant on the native Anthropic path, where the relay synthesizes
// the deny note.
func TestNativeAnthropicDenyNoteFramesAreNamed(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"Bash":"deny"}}}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	sse := msgStart("claude-sonnet-4", 10) +
		toolStart(0, "toolu_1", "Bash") +
		toolJSONDelta(0, `{"command":"rm -rf /"}`) +
		blockStop(0) +
		msgDelta("tool_use", 5)
	out, code := anthropicStream(sse, policy.NewHolder(pol))
	if code != 200 {
		t.Fatalf("status=%d", code)
	}
	if !strings.Contains(out, "blocked by Descles policy") {
		t.Fatalf("deny note missing:\n%s", out)
	}
	assertEveryFrameNamed(t, out)
}

const translatedToolBody = `{"model":"claude-opus-5","max_tokens":64,
  "tools":[{"name":"Bash","description":"run","input_schema":{"type":"object"}}],
  "messages":[{"role":"user","content":"clean up"}]}`

func openAIToolUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"chatcmpl-9","model":"deepseek-chat","choices":[{"index":0,"finish_reason":"tool_calls",
		  "message":{"content":"","tool_calls":[{"id":"call_5","type":"function","function":{"name":"Bash","arguments":"{\"command\":\"rm -rf /\"}"}}]}}],
		  "usage":{"prompt_tokens":9,"completion_tokens":3}}`)
	}))
}

func translatedFixture(t *testing.T, upstream *httptest.Server, pol *policy.Policy) *proxy.Handler {
	t.Helper()
	cfg := config.Config{Storage: "memory", LogLevel: "error", DenyEnforce: true,
		GatewayDomain: "gw.descles.com", UpstreamTimeout: 5 * time.Second}
	h := proxy.New(cfg, provider.NewRegistry(nil), policy.NewHolder(pol),
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
		return "openai", map[string]string{"claude-*": "deepseek-chat"}, "", true
	}
	return h
}
