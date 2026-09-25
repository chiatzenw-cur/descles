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
	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/proxy"
	"github.com/chiatzenw-cur/descles/pkg/storage"
)

// The lowest-friction onboarding: point ANTHROPIC_BASE_URL at Descles, keep the
// SDK untouched, and Descles swaps the client key for the real provider key.
func TestAnthropicMessagesDropIn(t *testing.T) {
	var gotKey, gotVersion, gotPath string
	anthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"model":"claude-3-5-sonnet","stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":20}}`)
	}))
	defer anthropic.Close()

	store := storage.NewMemory()
	cfg := config.Config{Addr: ":0", AnthropicBaseURL: anthropic.URL, AnthropicAPIKey: "sk-upstream", Storage: "memory", LogLevel: "error"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := provider.NewRegistry([]provider.Config{{BaseURL: anthropic.URL, APIKey: "sk-upstream"}})
	h := proxy.New(cfg, reg, policy.NewHolder(policy.AllowAll()), store, logger)

	for _, path := range []string{"/anthropic/v1/messages", "/v1/messages"} {
		rr := serve(h.Routes(), http.MethodPost, path,
			`{"model":"claude-3-5-sonnet","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}`,
			map[string]string{"x-api-key": "descles_xxx", "anthropic-version": "2023-06-01"})
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"msg_1"`) {
			t.Fatalf("route %s: status %d: %s", path, rr.Code, rr.Body.String())
		}
	}
	if gotPath != "/v1/messages" {
		t.Fatalf("upstream path %q", gotPath)
	}
	if gotKey != "sk-upstream" {
		t.Fatalf("client key leaked upstream: got %q", gotKey)
	}
	if gotVersion != "2023-06-01" {
		t.Fatalf("anthropic-version not passed through: %q", gotVersion)
	}
	spans, _ := store.ListRecent(context.Background(), 10)
	if len(spans) == 0 || spans[0].Attributes["provider"] != "anthropic" {
		t.Fatalf("expected an anthropic llm.call span, got %+v", spans)
	}
}

func TestAnthropicMessagesRequiresKey(t *testing.T) {
	store := storage.NewMemory()
	cfg := config.Config{Addr: ":0", AnthropicBaseURL: "http://127.0.0.1:1", AnthropicAPIKey: "sk-upstream", Storage: "memory", LogLevel: "error"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := proxy.New(cfg, provider.NewRegistry(nil), policy.NewHolder(policy.AllowAll()), store, logger)

	rr := serve(h.Routes(), http.MethodPost, "/anthropic/v1/messages",
		`{"model":"claude-3-5-sonnet","max_tokens":1,"messages":[]}`, nil)
	if rr.Code != 401 || !strings.Contains(rr.Body.String(), "authentication_error") {
		t.Fatalf("expected 401 authentication_error, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestAnthropicRejectsInvalidPayloadBeforeUpstream(t *testing.T) {
	hits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	h := proxy.New(config.Config{AnthropicBaseURL: upstream.URL, AnthropicAPIKey: "sk-upstream", UpstreamTimeout: time.Second}, provider.NewRegistry(nil), policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, body := range []string{`{`, `{"messages":[]}`} {
		rr := serve(h.Routes(), http.MethodPost, "/anthropic/v1/messages", body, map[string]string{"x-api-key": "dsk_client"})
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_request_error") {
			t.Fatalf("body=%q status=%d response=%s", body, rr.Code, rr.Body.String())
		}
	}
	if hits != 0 {
		t.Fatalf("invalid payload reached upstream %d times", hits)
	}
}

// Claude Code pointing ANTHROPIC_BASE_URL at the gateway sends its Descles token
// as Authorization: Bearer (ANTHROPIC_AUTH_TOKEN) and no x-api-key at all. That
// client must be accepted, with the provider credential still injected upstream.
func TestAnthropicBearerOnlyClientAccepted(t *testing.T) {
	var gotKey string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg_bearer","type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"model":"claude-test","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	defer upstream.Close()

	cfg := config.Config{AnthropicBaseURL: upstream.URL, UpstreamTimeout: time.Second}
	h := proxy.New(cfg, provider.NewRegistry(nil), policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.KeyResolver = func(key string) (string, string, string, bool) {
		return "org", "", "agent", key == "dsk_test_bearer"
	}

	rr := serve(h.Routes(), http.MethodPost, "/v1/messages",
		`{"model":"claude-test","max_tokens":10,"messages":[]}`,
		map[string]string{
			"authorization":          "Bearer dsk_test_bearer",
			"X-Descles-Provider-Key": "sk-ant-upstream",
			"anthropic-version":      "2023-06-01",
		})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if gotKey != "sk-ant-upstream" {
		t.Fatalf("upstream x-api-key=%q", gotKey)
	}
}

// A request with no client credential at all is still rejected before any
// upstream work happens.
func TestAnthropicRejectsCredentiallessRequest(t *testing.T) {
	h := proxy.New(config.Config{UpstreamTimeout: time.Second}, provider.NewRegistry(nil), policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.KeyResolver = func(key string) (string, string, string, bool) { return "org", "", "agent", key == "dsk_test_bearer" }

	rr := serve(h.Routes(), http.MethodPost, "/v1/messages",
		`{"model":"claude-test","max_tokens":10,"messages":[]}`,
		map[string]string{"anthropic-version": "2023-06-01"})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// A client that sets ANTHROPIC_BASE_URL to the gateway hits the canonical
// /v1/messages alias and authenticates with x-api-key alone (the Anthropic SDK
// default). That route must resolve the x-api-key as the Descles client key —
// the legacy /anthropic/v1/ namespace was the only one covered before.
func TestAnthropicCanonicalRouteAcceptsXAPIKeyOnly(t *testing.T) {
	var gotPath, gotKey string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg_canonical","type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"model":"claude-test","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	defer upstream.Close()

	cfg := config.Config{AnthropicBaseURL: upstream.URL, UpstreamTimeout: time.Second}
	h := proxy.New(cfg, provider.NewRegistry(nil), policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.KeyResolver = func(key string) (string, string, string, bool) {
		return "org", "", "agent", key == "dsk_test_canonical"
	}

	rr := serve(h.Routes(), http.MethodPost, "/v1/messages",
		`{"model":"claude-test","max_tokens":10,"messages":[]}`,
		map[string]string{
			"x-api-key":              "dsk_test_canonical",
			"X-Descles-Provider-Key": "sk-ant-upstream",
			"anthropic-version":      "2023-06-01",
		})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "msg_canonical") {
		t.Fatalf("body=%s", rr.Body.String())
	}
	if gotPath != "/v1/messages" {
		t.Fatalf("upstream path=%q", gotPath)
	}
	// The client key is swapped for the provider credential, never forwarded.
	if gotKey != "sk-ant-upstream" {
		t.Fatalf("upstream x-api-key=%q", gotKey)
	}
}

// The OpenAI plane must NOT treat x-api-key as a Descles token: an OpenAI-shaped
// request carries its credential in Authorization only.
func TestOpenAIPlaneIgnoresXAPIKey(t *testing.T) {
	h := proxy.New(config.Config{UpstreamTimeout: time.Second}, provider.NewRegistry(nil), policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.KeyResolver = func(key string) (string, string, string, bool) {
		return "org", "", "agent", key == "dsk_test_canonical"
	}

	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-4o-mini","messages":[]}`,
		map[string]string{"x-api-key": "dsk_test_canonical"})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAnthropicNativeDesclesKeyAndPerRequestBYOK(t *testing.T) {
	var gotKey, gotVersion, gotBeta string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		gotBeta = r.Header.Get("anthropic-beta")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg_byok","type":"message","role":"assistant","content":[],"model":"claude-test","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	defer upstream.Close()

	cfg := config.Config{AnthropicBaseURL: upstream.URL, UpstreamTimeout: time.Second}
	h := proxy.New(cfg, provider.NewRegistry(nil), policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.KeyResolver = func(key string) (string, string, string, bool) {
		return "org", "", "agent", key == "dsk_test_native"
	}
	h.KeyPolicy = func(string) (int64, bool, bool) { return 4096, true, true }
	h.QuotaGate = func(string) (int64, bool, bool) { return 999, true, true }

	rr := serve(h.Routes(), http.MethodPost, "/anthropic/v1/messages",
		`{"model":"claude-test","max_tokens":10,"messages":[]}`,
		map[string]string{
			"x-api-key":              "dsk_test_native",
			"X-Descles-Provider-Key": "sk-ant-customer",
			"anthropic-version":      "2023-06-01",
			"anthropic-beta":         "prompt-caching-2024-07-31",
		})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if gotKey != "sk-ant-customer" || gotVersion != "2023-06-01" || gotBeta != "prompt-caching-2024-07-31" {
		t.Fatalf("upstream headers key=%q version=%q beta=%q", gotKey, gotVersion, gotBeta)
	}
}

func TestAnthropicDenyRewrite(t *testing.T) {
	anthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg_2","type":"message","role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"shell.rm","input":{"path":"/tmp/x"}},{"type":"tool_use","id":"toolu_2","name":"shell.ls","input":{}}],"model":"claude-3-5-sonnet","usage":{"input_tokens":10,"output_tokens":20}}`)
	}))
	defer anthropic.Close()

	store := storage.NewMemory()
	cfg := config.Config{Addr: ":0", AnthropicBaseURL: anthropic.URL, AnthropicAPIKey: "sk-upstream", Storage: "memory", LogLevel: "error", DenyEnforce: true}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := provider.NewRegistry([]provider.Config{{BaseURL: anthropic.URL, APIKey: "sk-upstream"}})
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny"}}}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	h := proxy.New(cfg, reg, policy.NewHolder(pol), store, logger)

	rr := serve(h.Routes(), http.MethodPost, "/anthropic/v1/messages",
		`{"model":"claude-3-5-sonnet","max_tokens":1024,"messages":[{"role":"user","content":"delete"}]}`,
		map[string]string{"x-api-key": "descles_xxx", "anthropic-version": "2023-06-01"})
	if rr.Code != 200 {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}

	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	content := out["content"].([]any)
	if len(content) != 2 {
		t.Fatalf("content blocks = %d, want 2 (note + shell.ls): %s", len(content), rr.Body.String())
	}
	first := content[0].(map[string]any)
	if first["type"] != "text" || !strings.Contains(first["text"].(string), "blocked by Descles policy") {
		t.Fatalf("expected blocked text note first, got %v", first)
	}
	second := content[1].(map[string]any)
	if second["type"] != "tool_use" || second["name"] != "shell.ls" {
		t.Fatalf("expected shell.ls tool_use kept, got %v", second)
	}
}
