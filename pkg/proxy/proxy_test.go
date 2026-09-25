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
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// newHandler wires a proxy against a fake upstream server and returns it with
// its in-memory store.
func newHandler(upstream http.Handler) (*proxy.Handler, storage.Storage) {
	ts := httptest.NewServer(upstream)
	store := storage.NewMemory()
	cfg := config.Config{
		Addr:            ":0",
		UpstreamBaseURL: ts.URL,
		UpstreamAPIKey:  "sk-upstream-secret",
		Storage:         "memory",
		LogLevel:        "error",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := provider.NewRegistry([]provider.Config{{BaseURL: ts.URL, APIKey: "sk-upstream-secret"}})
	return proxy.New(cfg, reg, policy.NewHolder(policy.AllowAll()), store, logger), store
}

func serve(h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestNonStreamChatCompletionRecordsSpan(t *testing.T) {
	// The fake upstream asserts the configured upstream key is forwarded and
	// the descles project key is NOT.
	var gotAuth string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.Method != http.MethodPost || r.URL.Path != "/chat/completions" {
			t.Errorf("unexpected upstream req: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"hi","tool_calls":[{"id":"a","type":"function","function":{"name":"shell","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1200,"completion_tokens":300,"total_tokens":1500,"prompt_tokens_details":{"cached_tokens":400}}}`)
	})

	h, store := newHandler(upstream)
	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"X-Descles-User": "usr_42", "Authorization": "Bearer descles_project_key"})

	if rr.Code != 200 {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if gotAuth != "Bearer sk-upstream-secret" {
		t.Errorf("upstream auth = %q; must be the CONFIGURED key, not the descles key", gotAuth)
	}
	if !strings.Contains(rr.Body.String(), "chatcmpl-1") {
		t.Errorf("response not passed through: %s", rr.Body.String())
	}
	if rr.Header().Get("X-Request-Id") == "" || rr.Header().Get("X-Trace-Id") == "" {
		t.Error("missing X-Request-Id / X-Trace-Id headers")
	}

	spans, _ := store.ListRecent(t.Context(), 10)
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	s := spans[0]
	// Fresh input only (1200 prompt tokens include 400 cached ones), so the
	// separate cached line is not billed on top of it.
	if s.Attributes[tracing.AttrInputToks] != 800 {
		t.Errorf("input_tokens = %v", s.Attributes[tracing.AttrInputToks])
	}
	if s.Attributes[tracing.AttrCachedToks] != 400 {
		t.Errorf("cached_tokens = %v", s.Attributes[tracing.AttrCachedToks])
	}
	if s.Attributes[tracing.AttrToolCalls] != 1 {
		t.Errorf("tool_calls_requested = %v", s.Attributes[tracing.AttrToolCalls])
	}
	if s.ActorType != "user" || s.ActorID != "usr_42" {
		t.Errorf("actor = %s/%s", s.ActorType, s.ActorID)
	}
	if s.SpanType != tracing.SpanTypeLLM {
		t.Errorf("span type = %s", s.SpanType)
	}
	if s.Status != tracing.StatusOK {
		t.Errorf("status = %s", s.Status)
	}
	if cost, ok := s.Attributes[tracing.AttrCostUSD].(float64); !ok || cost <= 0 {
		t.Errorf("cost not recorded: %v", s.Attributes[tracing.AttrCostUSD])
	}
}

func TestStreamingChatCompletionCapturesUsage(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fl, _ := w.(http.Flusher)
		io.WriteString(w, "data: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"he\"}}]}\n\n")
		io.WriteString(w, "data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"type\":\"function\",\"function\":{\"name\":\"shell\",\"arguments\":\"{}\"}}]}}]}\n\n")
		io.WriteString(w, "data: {\"id\":\"x\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
		fl.Flush()
	})

	h, store := newHandler(upstream)
	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"X-Descles-Agent": "coding-agent"})

	if rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "[DONE]") {
		t.Errorf("stream not passed through: %s", rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("content-type = %s", ct)
	}

	spans, _ := store.ListRecent(t.Context(), 10)
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	s := spans[0]
	if s.Attributes[tracing.AttrInputToks] != 10 || s.Attributes[tracing.AttrOutputToks] != 5 {
		t.Errorf("streamed usage = %+v", s.Attributes)
	}
	if s.Attributes[tracing.AttrToolCalls] != 1 {
		t.Errorf("tool_calls_requested = %v", s.Attributes[tracing.AttrToolCalls])
	}
	if s.ActorID != "coding-agent" {
		t.Errorf("actor_id = %q", s.ActorID)
	}
}

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushes int
}

func (w *flushRecorder) Flush() {
	w.flushes++
	w.ResponseRecorder.Flush()
}

func TestStreamingFlushesThroughMiddleware(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"x\",\"choices\":[]}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	})
	h, _ := newHandler(upstream)
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","stream":true,"messages":[]}`))
	w := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.flushes < 2 {
		t.Fatalf("status=%d flushes=%d body=%s", w.Code, w.flushes, w.Body.String())
	}
}

func TestStreamingResponsesForwardsEventsAndCapturesUsage(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("path=%s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: response.completed\n")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-4o\",\"usage\":{\"input_tokens\":7,\"output_tokens\":4,\"total_tokens\":11}}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	})
	h, store := newHandler(upstream)
	rr := serve(h.Routes(), http.MethodPost, "/v1/responses", `{"model":"gpt-4o","stream":true,"input":"hi"}`, nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "response.completed") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	spans, _ := store.ListRecent(t.Context(), 10)
	if len(spans) != 1 || spans[0].Attributes[tracing.AttrInputToks] != 7 || spans[0].Attributes[tracing.AttrOutputToks] != 4 {
		t.Fatalf("responses stream span=%+v", spans)
	}
}

func TestUpstreamErrorPassthroughRecordsErrorSpan(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "7")
		w.Header().Set("X-RateLimit-Remaining-Requests", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"error":{"message":"rate limited","type":"rate_limit_error"}}`)
	})

	h, store := newHandler(upstream)
	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`,
		nil)

	if rr.Code != 429 {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "rate limited") {
		t.Errorf("error body not passed through: %s", rr.Body.String())
	}
	if rr.Header().Get("Retry-After") != "7" || rr.Header().Get("X-RateLimit-Remaining-Requests") != "0" {
		t.Fatalf("rate limit headers not preserved: %v", rr.Header())
	}

	spans, _ := store.ListRecent(t.Context(), 10)
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	s := spans[0]
	if s.Status != tracing.StatusError {
		t.Errorf("status = %s, want error", s.Status)
	}
	if s.ErrorType != "upstream_http_429" {
		t.Errorf("error_type = %q", s.ErrorType)
	}
}

func TestStreamingRequestPreservesJSONUpstreamError(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":{"message":"provider limited"}}`)
	})
	h, _ := newHandler(upstream)
	rr := serve(h.Routes(), http.MethodPost, "/v1/responses", `{"model":"gpt-4o","stream":true,"input":"hi"}`, nil)
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Content-Type") != "application/json" || rr.Header().Get("Retry-After") != "3" || !strings.Contains(rr.Body.String(), "provider limited") {
		t.Fatalf("status=%d headers=%v body=%s", rr.Code, rr.Header(), rr.Body.String())
	}
}

func TestResponsesEndpointRecordsSpan(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"resp_1","object":"response","model":"gpt-4o","usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5,"input_tokens_details":{"cached_tokens":1}},"output":[{"type":"function_call","name":"foo"}]}`)
	})

	h, store := newHandler(upstream)
	rr := serve(h.Routes(), http.MethodPost, "/v1/responses",
		`{"model":"gpt-4o","input":"hi"}`, nil)

	if rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}
	spans, _ := store.ListRecent(t.Context(), 10)
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	s := spans[0]
	if s.Attributes[tracing.AttrInputToks] != 1 || s.Attributes[tracing.AttrOutputToks] != 3 {
		t.Errorf("responses usage = %+v", s.Attributes)
	}
	if s.Attributes[tracing.AttrToolCalls] != 1 {
		t.Errorf("tool_calls_requested = %v", s.Attributes[tracing.AttrToolCalls])
	}
}

func TestTraceViewReturnsSpansOfTrace(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"model":"gpt-4o","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	})
	h, _ := newHandler(upstream)
	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"X-Descles-Trace": "abcdef"})

	traceID := rr.Header().Get("X-Trace-Id")
	if traceID != "abcdef" {
		t.Fatalf("trace id header = %q (client-supplied should be honoured)", traceID)
	}

	tr := httptest.NewRecorder()
	h.Routes().ServeHTTP(tr, httptest.NewRequest(http.MethodGet, "/api/traces/abcdef", nil))
	if tr.Code != 200 {
		t.Fatalf("trace view status = %d", tr.Code)
	}
	var resp struct {
		Spans []map[string]any `json:"spans"`
	}
	if err := json.Unmarshal(tr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal trace: %v", err)
	}
	if len(resp.Spans) != 1 {
		t.Fatalf("expected 1 span in trace, got %d", len(resp.Spans))
	}
}

func TestMultiProviderRoutingByModel(t *testing.T) {
	deepseek := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"ds-1","model":"deepseek-chat","choices":[{"index":0,"message":{"content":"from deepseek"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	}))
	defer deepseek.Close()
	openai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"oa-1","model":"gpt-4o","choices":[{"index":0,"message":{"content":"from openai"}}],"usage":{"prompt_tokens":20,"completion_tokens":6,"total_tokens":26}}`)
	}))
	defer openai.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error"}
	reg := provider.NewRegistry([]provider.Config{
		{Name: "deepseek", BaseURL: deepseek.URL, Models: []string{"deepseek-chat"}},
		{Name: "openai", BaseURL: openai.URL, Models: []string{"gpt-*"}},
	})
	h := proxy.New(cfg, reg, policy.NewHolder(policy.AllowAll()), store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions",
		`{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}`, nil)
	if !strings.Contains(rr.Body.String(), "from deepseek") {
		t.Errorf("deepseek route body = %s", rr.Body.String())
	}

	rr2 := serve(h.Routes(), http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, nil)
	if !strings.Contains(rr2.Body.String(), "from openai") {
		t.Errorf("openai route body = %s", rr2.Body.String())
	}

	spans, _ := store.ListRecent(context.Background(), 10)
	if len(spans) != 2 {
		t.Fatalf("spans = %d", len(spans))
	}
	// ListRecent returns newest first: gpt-4o (openai), then deepseek-chat.
	if spans[0].Attributes[tracing.AttrProvider] != "openai" {
		t.Errorf("spans[0] provider = %v", spans[0].Attributes[tracing.AttrProvider])
	}
	if spans[1].Attributes[tracing.AttrProvider] != "deepseek" {
		t.Errorf("spans[1] provider = %v", spans[1].Attributes[tracing.AttrProvider])
	}
}

func TestBudgetDenialAndAudit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","model":"gpt-4o","choices":[{"index":0,"message":{"content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":1,"total_tokens":11}}`)
	}))
	defer upstream.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error"}
	reg := provider.NewRegistry([]provider.Config{{BaseURL: upstream.URL}})
	// Tiny budget so the pre-seeded span already exceeds it.
	pol, err := policy.FromJSON(`{"agents":{"coding-agent":{"budget":{"daily_usd":0.000001}}}}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	h := proxy.New(cfg, reg, policy.NewHolder(pol), store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Pre-seed a span that puts coding-agent over budget for today.
	now := time.Now().UTC()
	seed := &tracing.Span{
		SpanID: "seed", TraceID: "t-seed", SpanType: tracing.SpanTypeLLM,
		StartedAt: now, EndedAt: now, AgentID: "coding-agent",
		Status: tracing.StatusOK,
		Attributes: map[string]any{
			tracing.AttrModel: "gpt-4o", tracing.AttrProvider: "mock",
			tracing.AttrInputToks: 100, tracing.AttrOutputToks: 100,
			tracing.AttrCostUSD: 0.01, tracing.AttrPolicy: "allow",
		},
	}
	if err := store.PutSpan(context.Background(), seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"X-Descles-Agent": "coding-agent"})
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (budget exceeded): %s", rr.Code, rr.Body.String())
	}

	// The audit endpoint should surface the denied span (policy_decision != allow).
	ar := httptest.NewRecorder()
	h.Routes().ServeHTTP(ar, httptest.NewRequest(http.MethodGet, "/api/policy-events", nil))
	if ar.Code != 200 {
		t.Fatalf("policy-events status = %d", ar.Code)
	}
	var events []map[string]any
	if err := json.Unmarshal(ar.Body.Bytes(), &events); err != nil {
		t.Fatalf("unmarshal policy-events: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected >=1 policy event, got none: %s", ar.Body.String())
	}
	if attrs, _ := events[0]["attributes"].(map[string]any); attrs[tracing.AttrPolicy] != "deny" {
		t.Errorf("expected a deny decision on the first event, got %v", attrs[tracing.AttrPolicy])
	}
}

func TestUserBudgetExceeded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","model":"gpt-4o","choices":[{"index":0,"message":{"content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":1,"total_tokens":11}}`)
	}))
	defer upstream.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error"}
	reg := provider.NewRegistry([]provider.Config{{BaseURL: upstream.URL}})
	pol, _ := policy.FromJSON(`{"users":{"alice":{"budget":{"daily_usd":0.000001}}}}`)
	h := proxy.New(cfg, reg, policy.NewHolder(pol), store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Pre-seed a span that puts employee "alice" over budget for today.
	now := time.Now().UTC()
	seed := &tracing.Span{
		SpanID: "seed-user", TraceID: "t-seed-user", SpanType: tracing.SpanTypeLLM,
		StartedAt: now, EndedAt: now, UserID: "alice",
		Status: tracing.StatusOK,
		Attributes: map[string]any{
			tracing.AttrModel: "gpt-4o", tracing.AttrProvider: "mock",
			tracing.AttrInputToks: 100, tracing.AttrOutputToks: 100,
			tracing.AttrCostUSD: 0.01, tracing.AttrPolicy: "allow",
		},
	}
	if err := store.PutSpan(context.Background(), seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"X-Descles-User": "alice"})
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (user budget exceeded): %s", rr.Code, rr.Body.String())
	}
}

func TestDataPlaneAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","model":"gpt-4o","choices":[{"index":0,"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	defer upstream.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", DataToken: "data-secret"}
	reg := provider.NewRegistry([]provider.Config{{BaseURL: upstream.URL}})
	h := proxy.New(cfg, reg, policy.NewHolder(policy.AllowAll()), store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`

	if rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions", body, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no token status = %d, want 401", rr.Code)
	}
	if rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions", body, map[string]string{"Authorization": "Bearer wrong"}); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401", rr.Code)
	}
	if rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions", body, map[string]string{"Authorization": "Bearer data-secret"}); rr.Code != http.StatusOK {
		t.Fatalf("correct token status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
}

func TestDenyRewrite(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":[{"id":"call_1","type":"function","function":{"name":"shell.rm","arguments":"{\"path\":\"/tmp/x\"}"}},{"id":"call_2","type":"function","function":{"name":"shell.ls","arguments":"{}"}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":1,"total_tokens":11}}`)
	}))
	defer upstream.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", DenyEnforce: true}
	reg := provider.NewRegistry([]provider.Config{{BaseURL: upstream.URL}})
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny"}}}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	h := proxy.New(cfg, reg, policy.NewHolder(pol), store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"delete the file"}]}`
	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions", body, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	choices := out["choices"].([]any)
	msg := choices[0].(map[string]any)["message"].(map[string]any)

	// The denied shell.rm call is stripped; the allowed shell.ls stays.
	tc, _ := msg["tool_calls"].([]any)
	if len(tc) != 1 {
		t.Fatalf("tool_calls after rewrite = %d, want 1 (only shell.ls): %s", len(tc), rr.Body.String())
	}
	fn := tc[0].(map[string]any)["function"].(map[string]any)
	if name, _ := fn["name"].(string); name != "shell.ls" {
		t.Fatalf("kept tool = %q, want shell.ls", name)
	}
	if content, _ := msg["content"].(string); !strings.Contains(content, "blocked by Descles policy") {
		t.Fatalf("expected blocked note in content, got %q", content)
	}
}

func TestDenyEnforceOff(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":[{"id":"call_1","type":"function","function":{"name":"shell.rm","arguments":"{}"}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":1,"total_tokens":11}}`)
	}))
	defer upstream.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", DenyEnforce: false}
	reg := provider.NewRegistry([]provider.Config{{BaseURL: upstream.URL}})
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny"}}}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	h := proxy.New(cfg, reg, policy.NewHolder(pol), store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions", `{"model":"gpt-4o","messages":[{"role":"user","content":"x"}]}`, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	// DenyEnforce off: the denied tool_call is NOT stripped (observability-only).
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	msg := out["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)
	if tc, _ := msg["tool_calls"].([]any); len(tc) != 1 {
		t.Fatalf("DenyEnforce off should NOT strip the tool_call, got %v", msg["tool_calls"])
	}
}

func TestResponsesDenyRewrite(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"model":"gpt-4o","output":[{"type":"function_call","name":"shell.rm","arguments":"{\"path\":\"/tmp/x\"}","call_id":"call_1"},{"type":"function_call","name":"shell.ls","arguments":"{}","call_id":"call_2"}],"usage":{"input_tokens":10,"output_tokens":1,"total_tokens":11}}`)
	}))
	defer upstream.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", DenyEnforce: true}
	reg := provider.NewRegistry([]provider.Config{{BaseURL: upstream.URL}})
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny"}}}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	h := proxy.New(cfg, reg, policy.NewHolder(pol), store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	rr := serve(h.Routes(), http.MethodPost, "/v1/responses", `{"model":"gpt-4o","input":"delete the file"}`, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	output := out["output"].([]any)
	// shell.rm denied -> message note; shell.ls kept as function_call.
	if len(output) != 2 {
		t.Fatalf("output items = %d, want 2 (note + shell.ls): %s", len(output), rr.Body.String())
	}
	first := output[0].(map[string]any)
	if first["type"] != "message" {
		t.Fatalf("expected blocked message note first, got %v", first)
	}
	second := output[1].(map[string]any)
	if second["type"] != "function_call" || second["name"] != "shell.ls" {
		t.Fatalf("expected shell.ls function_call kept, got %v", second)
	}
}

func TestApprovalSuspend(t *testing.T) {
	// A tool_call the policy marks require_approval must NOT reach the runtime
	// as an executable call: the rewrite parks it, opens a pending approval via
	// the suspender, and replaces the call with an approval note.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":[{"id":"call_1","type":"function","function":{"name":"github_create_issue","arguments":"{\"title\":\"spam\"}"}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":1,"total_tokens":11}}`)
	}))
	defer upstream.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", DenyEnforce: true}
	reg := provider.NewRegistry([]provider.Config{{BaseURL: upstream.URL}})
	pol, err := policy.FromJSON(`{"defaults":{"require_approval":["github.create_issue"]}}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	h := proxy.New(cfg, reg, policy.NewHolder(pol), store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var gotArgs map[string]any
	h.ApprovalSuspender = func(agentID, tool string, args map[string]any) (string, error) {
		gotArgs = args
		return "ap_123", nil
	}

	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions", `{"model":"gpt-4o","messages":[{"role":"user","content":"create issue"}]}`, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	msg := out["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)
	if tc, _ := msg["tool_calls"].([]any); len(tc) != 0 {
		t.Fatalf("require_approval tool_call must not stay executable, got %v", msg["tool_calls"])
	}
	content, _ := msg["content"].(string)
	if !strings.Contains(content, "[pending human approval: github_create_issue (approval ap_123)]") {
		t.Fatalf("expected pending-approval note in content, got %q", content)
	}
	if gotArgs == nil || gotArgs["title"] != "spam" {
		t.Fatalf("suspender should receive the parsed arguments, got %v", gotArgs)
	}
}

func TestApprovalSuspendWithoutSuspender(t *testing.T) {
	// No suspender wired: a require_approval call is still stripped (never
	// executable) and the runtime is told it needs human approval.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":[{"id":"call_1","type":"function","function":{"name":"github_create_issue","arguments":"{}"}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":1,"total_tokens":11}}`)
	}))
	defer upstream.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", DenyEnforce: true}
	reg := provider.NewRegistry([]provider.Config{{BaseURL: upstream.URL}})
	pol, err := policy.FromJSON(`{"defaults":{"require_approval":["github.create_issue"]}}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	h := proxy.New(cfg, reg, policy.NewHolder(pol), store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions", `{"model":"gpt-4o","messages":[{"role":"user","content":"x"}]}`, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	msg := out["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)
	if tc, _ := msg["tool_calls"].([]any); len(tc) != 0 {
		t.Fatalf("require_approval tool_call must be stripped without a suspender, got %v", msg["tool_calls"])
	}
	content, _ := msg["content"].(string)
	if !strings.Contains(content, "[requires human approval before execution: github_create_issue]") {
		t.Fatalf("expected requires-approval note in content, got %q", content)
	}
}

func TestOrgUpstreamTransparentPassthrough(t *testing.T) {
	// The gateway's pooled upstream must never be hit once the tenant has
	// configured their own endpoint for the provider.
	pooled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("pooled upstream must not be hit when tenant BYOK endpoint is set")
	}))
	defer pooled.Close()
	tenant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sk-tenant" {
			t.Errorf("tenant auth = %q, want Bearer sk-tenant", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"t-1","model":"deepseek-chat","choices":[{"index":0,"message":{"content":"from tenant upstream"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	}))
	defer tenant.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error"}
	reg := provider.NewRegistry([]provider.Config{
		{Name: "deepseek", BaseURL: pooled.URL, APIKey: "sk-pooled", Models: []string{"deepseek-*"}},
	})
	h := proxy.New(cfg, reg, policy.NewHolder(policy.AllowAll()), store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.OrgUpstream = func(orgID, providerName string) (string, string, bool) {
		if orgID == "org1" && providerName == "deepseek" {
			return tenant.URL, "sk-tenant", true
		}
		return "", "", false
	}

	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions",
		`{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"X-Descles-Org": "org1"})
	if !strings.Contains(rr.Body.String(), "from tenant upstream") {
		t.Errorf("body = %s, want tenant upstream reply", rr.Body.String())
	}

	// A different org with no BYOK endpoint still routes to the gateway's pooled
	// upstream (OrgUpstream never fires for empty org id).
	pooledOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"p-1","model":"deepseek-chat","choices":[{"index":0,"message":{"content":"from pooled upstream"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	}))
	defer pooledOK.Close()
	reg2 := provider.NewRegistry([]provider.Config{
		{Name: "deepseek", BaseURL: pooledOK.URL, APIKey: "sk-pooled", Models: []string{"deepseek-*"}},
	})
	h2 := proxy.New(cfg, reg2, policy.NewHolder(policy.AllowAll()), storage.NewMemory(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	h2.OrgUpstream = h.OrgUpstream
	rr2 := serve(h2.Routes(), http.MethodPost, "/v1/chat/completions",
		`{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}`, nil)
	if !strings.Contains(rr2.Body.String(), "from pooled upstream") {
		t.Errorf("org without BYOK body = %s, want pooled upstream reply", rr2.Body.String())
	}
}

func TestHostedProviderGrantStopsBeforeUpstream(t *testing.T) {
	calls := 0
	tenant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}],"usage":{}}`)
	}))
	defer tenant.Close()
	reg := provider.NewRegistry([]provider.Config{{Name: "openai", BaseURL: tenant.URL, APIKey: "sk-pooled", Models: []string{"gpt-*"}}})
	h := proxy.New(config.Config{Storage: "memory", LogLevel: "error"}, reg, policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.KeyResolver = func(key string) (string, string, string, bool) { return "org", "", "agent", key == "dsk-agent" }
	h.OrgUpstream = func(org, name string) (string, string, bool) {
		return tenant.URL, "sk-company", org == "org" && name == "openai"
	}
	allowed := false
	h.HostedProviderAllowed = func(agent, name string) bool { return allowed && agent == "agent" && name == "openai" }
	body := `{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`
	headers := map[string]string{"Authorization": "Bearer dsk-agent"}
	blocked := serve(h.Routes(), http.MethodPost, "/v1/chat/completions", body, headers)
	if blocked.Code != http.StatusForbidden || calls != 0 {
		t.Fatalf("ungrounded model use: status=%d calls=%d body=%s", blocked.Code, calls, blocked.Body.String())
	}
	allowed = true
	granted := serve(h.Routes(), http.MethodPost, "/v1/chat/completions", body, headers)
	if granted.Code != http.StatusOK || calls != 1 {
		t.Fatalf("granted model use failed: status=%d calls=%d body=%s", granted.Code, calls, granted.Body.String())
	}
}

func TestHostnameRoutedBYOKPassthrough(t *testing.T) {
	// Registry points deepseek-* at a pooled fake; the hostname route must win
	// and forward to the tenant's own endpoint without any registry match.
	pooled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("pooled upstream must not be hit on hostname route")
	}))
	defer pooled.Close()
	tenant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sk-tenant" {
			t.Errorf("auth = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"t-1","model":"some-model","choices":[{"index":0,"message":{"content":"from tenant hostname route"}}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`)
	}))
	defer tenant.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", GatewayDomain: "gw.descles.com"}
	reg := provider.NewRegistry([]provider.Config{
		{Name: "deepseek", BaseURL: pooled.URL, APIKey: "sk-pooled", Models: []string{"deepseek-*"}},
	})
	h := proxy.New(cfg, reg, policy.NewHolder(policy.AllowAll()), store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.OrgUpstream = func(orgID, providerName string) (string, string, bool) {
		if orgID == "org1" && providerName == "deepseek" {
			return tenant.URL, "sk-tenant", true
		}
		return "", "", false
	}
	h.KeyResolver = func(_ string) (string, string, string, bool) {
		return "org1", "", "", true
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"anything-not-in-registry","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dsk_whatever")
	req.Host = "deepseek.gw.descles.com"
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "from tenant hostname route") {
		t.Errorf("body = %s", rr.Body.String())
	}

	// Same request on an unhosted address (no Host subdomain) must not silently
	// reuse the tenant route: registry has no slot for "anything-not-in-registry".
	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"anything-not-in-registry","messages":[{"role":"user","content":"hi"}]}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer dsk_whatever")
	req2.Host = "gw.descles.com"
	rr2 := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Errorf("unhosted unknown-model status = %d, want 400", rr2.Code)
	}
}

func TestHostnameRoutedModelsUseTenantBYOK(t *testing.T) {
	pooled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("global provider must not answer a tenant hostname model probe")
	}))
	defer pooled.Close()
	tenant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("path = %q, want /v1/models", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sk-tenant" {
			t.Errorf("auth = %q, want tenant credential", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"object":"list","data":[{"id":"deepseek-chat","object":"model"}]}`)
	}))
	defer tenant.Close()

	cfg := config.Config{Storage: "memory", LogLevel: "error", GatewayDomain: "gw.descles.com"}
	reg := provider.NewRegistry([]provider.Config{{Name: "deepseek", BaseURL: pooled.URL, APIKey: "sk-pooled", Models: []string{"deepseek-*"}}})
	h := proxy.New(cfg, reg, policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.OrgUpstream = func(orgID, providerName string) (string, string, bool) {
		if orgID == "org1" && providerName == "deepseek" {
			return tenant.URL + "/v1", "sk-tenant", true
		}
		return "", "", false
	}
	h.KeyResolver = func(key string) (string, string, string, bool) {
		switch key {
		case "dsk_org1":
			return "org1", "", "", true
		case "dsk_org2":
			return "org2", "", "", true
		default:
			return "", "", "", false
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer dsk_org1")
	req.Host = "deepseek.gw.descles.com"
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"id":"deepseek-chat"`) {
		t.Fatalf("tenant model probe status=%d body=%s", rr.Code, rr.Body.String())
	}

	// A valid key from another organization must not inherit org1's provider.
	req = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer dsk_org2")
	req.Host = "deepseek.gw.descles.com"
	rr = httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("cross-org model probe status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPerRequestModelsUseExplicitEndpointAndCredential(t *testing.T) {
	egressChecked := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("path = %q, want /v1/models", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sk-request" {
			t.Errorf("auth = %q, want per-request credential", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"object":"list","data":[{"id":"request-model","object":"model"}]}`)
	}))
	defer target.Close()

	h := proxy.New(config.Config{Storage: "memory", LogLevel: "error"}, nil, policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.EgressCheck = func(_ string, baseURL string) error {
		egressChecked = baseURL == target.URL+"/v1"
		return nil
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("X-Descles-Provider-Base-URL", target.URL+"/v1")
	req.Header.Set("X-Descles-Provider-Key", "sk-request")
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"id":"request-model"`) {
		t.Fatalf("per-request model probe status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !egressChecked {
		t.Fatal("per-request model probe bypassed the egress policy")
	}
}

func TestHostnameRoutingDisabledWithoutGatewayDomain(t *testing.T) {
	// No DESCLES_GATEWAY_DOMAIN: even a deepseek.gw.* Host routes by registry
	// model matching (single-tenant / IP-addressed demo mode).
	pooled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"p-1","model":"deepseek-chat","choices":[{"index":0,"message":{"content":"pooled reply"}}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`)
	}))
	defer pooled.Close()
	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error"} // no GatewayDomain
	reg := provider.NewRegistry([]provider.Config{
		{Name: "deepseek", BaseURL: pooled.URL, Models: []string{"deepseek-*"}},
	})
	h := proxy.New(cfg, reg, policy.NewHolder(policy.AllowAll()), store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "deepseek.gw.descles.com"
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "pooled reply") {
		t.Errorf("body = %s, want pooled reply", rr.Body.String())
	}
}

func TestPerRequestBaseURLPassthrough(t *testing.T) {
	// X-Descles-Provider-Base-URL lets a client forward to any endpoint with
	// no org provider pre-configuration (landing test-key quick start).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sk-byok" {
			t.Errorf("auth = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"q-1","model":"deepseek-chat","choices":[{"index":0,"message":{"content":"quick start ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)
	}))
	defer target.Close()

	// Empty registry on purpose: per-request endpoint must not need any slot.
	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error"}
	h := proxy.New(cfg, nil, policy.NewHolder(policy.AllowAll()), store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Descles-Provider-Base-URL", target.URL)
	req.Header.Set("X-Descles-Provider-Key", "sk-byok")
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "quick start ok") {
		t.Errorf("body = %s", rr.Body.String())
	}
}

func TestAnthropicHostnameBYOKPassthrough(t *testing.T) {
	// Claude Code points ANTHROPIC_BASE_URL at anthropic.gw.descles.com; the
	// org's BYOK endpoint + key for "anthropic" transparently replace the
	// gateway's static config.
	tenant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "sk-ant-tenant" {
			t.Errorf("x-api-key = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg-1","type":"message","role":"assistant","model":"claude-3-5-sonnet","content":[{"type":"text","text":"from tenant anthropic"}],"usage":{"input_tokens":10,"output_tokens":5}}`)
	}))
	defer tenant.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", GatewayDomain: "gw.descles.com",
		AnthropicBaseURL: "https://api.anthropic.com", AnthropicAPIKey: "sk-ant-pooled"}
	h := proxy.New(cfg, nil, policy.NewHolder(policy.AllowAll()), store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Slot wire, consulted only on the Anthropic plane: these fixtures' tenant
	// upstreams speak the Anthropic wire, so pass bodies through untranslated.
	h.OrgSlotConfig = func(string, string) (string, map[string]string, string, bool) {
		return "anthropic", nil, "", true
	}
	h.OrgUpstream = func(orgID, providerName string) (string, string, bool) {
		if orgID == "org1" && providerName == "anthropic" {
			return tenant.URL, "sk-ant-tenant", true
		}
		return "", "", false
	}
	h.KeyResolver = func(_ string) (string, string, string, bool) { return "org1", "", "", true }

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages",
		strings.NewReader(`{"model":"claude-3-5-sonnet","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "dsk_whatever")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Host = "anthropic.gw.descles.com"
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "from tenant anthropic") {
		t.Errorf("body = %s", rr.Body.String())
	}
}

func TestHostedOrgKeySatisfiesLimitedKeyBYOK(t *testing.T) {
	// Org admin stored their provider key with Descles (OrgProvider). An
	// employee/limited key needs no X-Descles-Provider-Key header — routing
	// uses the org's hosted key transparently.
	tenant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sk-hosted" {
			t.Errorf("auth = %q, want hosted org key", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"h-1","model":"deepseek-chat","choices":[{"index":0,"message":{"content":"hosted org key ok"}}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`)
	}))
	defer tenant.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", GatewayDomain: "gw.descles.com"}
	// No registry at all: hosted org key is the only credential path.
	h := proxy.New(cfg, nil, policy.NewHolder(policy.AllowAll()), store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Slot wire, consulted only on the Anthropic plane: these fixtures' tenant
	// upstreams speak the Anthropic wire, so pass bodies through untranslated.
	h.OrgSlotConfig = func(string, string) (string, map[string]string, string, bool) {
		return "anthropic", nil, "", true
	}
	h.OrgUpstream = func(orgID, providerName string) (string, string, bool) {
		if orgID == "org1" && providerName == "deepseek" {
			return tenant.URL, "sk-hosted", true
		}
		return "", "", false
	}
	h.KeyResolver = func(k string) (string, string, string, bool) {
		if k == "dsk_limited" {
			return "org1", "emp1", "", true
		}
		return "", "", "", false
	}
	// The limited key requires BYOK — but the org's hosted key satisfies it.
	h.KeyPolicy = func(k string) (int64, bool, bool) {
		if k == "dsk_limited" {
			return 1 << 20, true, true
		}
		return 0, false, false
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dsk_limited")
	req.Host = "deepseek.gw.descles.com"
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "hosted org key ok") {
		t.Errorf("body = %s", rr.Body.String())
	}
}
