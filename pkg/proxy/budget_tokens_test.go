package proxy_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/config"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/proxy"
	"github.com/chiatzenw-cur/descles/pkg/storage"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// TestTokenBudgetExceeded drives the full /v1 route: a token-only daily budget
// below the pre-seeded span's usage must reject the next request with 429.
func TestTokenBudgetExceeded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","model":"gpt-4o","choices":[{"index":0,"message":{"content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":1,"total_tokens":11}}`)
	}))
	defer upstream.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error"}
	reg := provider.NewRegistry([]provider.Config{{BaseURL: upstream.URL}})
	pol, err := policy.FromJSON(`{"agents":{"coding-agent":{"budget":{"daily_tokens":50}}}}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	h := proxy.New(cfg, reg, policy.NewHolder(pol), store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Pre-seed a span putting coding-agent at 60 tokens today (> 50 cap).
	now := time.Now().UTC()
	seed := &tracing.Span{
		SpanID: "seed-tok", TraceID: "t-seed-tok", SpanType: tracing.SpanTypeLLM,
		StartedAt: now, EndedAt: now, AgentID: "coding-agent",
		Status: tracing.StatusOK,
		Attributes: map[string]any{
			tracing.AttrModel: "gpt-4o", tracing.AttrProvider: "mock",
			tracing.AttrInputToks: 40, tracing.AttrOutputToks: 20, tracing.AttrCachedToks: 0,
			tracing.AttrCostUSD: 0.000001, tracing.AttrPolicy: "allow",
		},
	}
	if err := store.PutSpan(context.Background(), seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"X-Descles-Agent": "coding-agent"})
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (token budget exceeded): %s", rr.Code, rr.Body.String())
	}
}

// TestTokenBudgetAllowsUnderLimit checks a token cap that is not yet reached:
// the request passes even though the seeded span's estimated USD cost is above
// any plausible USD concern — proving the gate is reading tokens, not cost.
func TestTokenBudgetAllowsUnderLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","model":"gpt-4o","choices":[{"index":0,"message":{"content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":1,"total_tokens":11}}`)
	}))
	defer upstream.Close()

	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error"}
	reg := provider.NewRegistry([]provider.Config{{BaseURL: upstream.URL}})
	pol, err := policy.FromJSON(`{"agents":{"coding-agent":{"budget":{"daily_tokens":100}}}}`)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	h := proxy.New(cfg, reg, policy.NewHolder(pol), store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	now := time.Now().UTC()
	seed := &tracing.Span{
		SpanID: "seed-ok", TraceID: "t-seed-ok", SpanType: tracing.SpanTypeLLM,
		StartedAt: now, EndedAt: now, AgentID: "coding-agent",
		Status: tracing.StatusOK,
		Attributes: map[string]any{
			tracing.AttrModel: "gpt-4o", tracing.AttrProvider: "mock",
			tracing.AttrInputToks: 40, tracing.AttrOutputToks: 20, tracing.AttrCachedToks: 0,
			tracing.AttrCostUSD: 0.01, tracing.AttrPolicy: "allow",
		},
	}
	if err := store.PutSpan(context.Background(), seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rr := serve(h.Routes(), http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`,
		map[string]string{"X-Descles-Agent": "coding-agent"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 under token budget: %s", rr.Code, rr.Body.String())
	}
}
