package proxy_test

import (
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

// A tenant saves one BYOK provider ("deepseek") and points Claude Code at
// anthropic.gw.descles.com. The host names a slot ("anthropic") that was never
// saved, so the org's single credential must serve the request instead of the
// gateway answering 502 for a credential that does exist.
func TestAnthropicPlaneFallsBackToSoleOrgProvider(t *testing.T) {
	var gotKey, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"msg_fallback","type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"model":"deepseek-chat","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	defer upstream.Close()

	cfg := config.Config{GatewayDomain: "gw.descles.com", UpstreamTimeout: time.Second}
	h := proxy.New(cfg, provider.NewRegistry(nil), policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.KeyResolver = func(key string) (string, string, string, bool) {
		return "org", "", "agent", key == "dsk_test_bearer"
	}
	// The host slot is absent; the tenant's only saved provider is "deepseek".
	// It speaks the Anthropic wire in this fixture, so translation stays off and
	// the assertion below is about routing, not about the wire.
	h.OrgSlotConfig = func(string, string) (string, map[string]string, string, bool) {
		return "anthropic", nil, "", true
	}
	h.OrgUpstream = func(orgID, providerName string) (string, string, bool) { return "", "", false }
	h.OrgFallback = func(orgID string) (string, string, string, bool) {
		return "deepseek", upstream.URL, "sk-ds-upstream", true
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4-5-20250929","max_tokens":10,"messages":[]}`))
	req.Host = "anthropic.gw.descles.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("authorization", "Bearer dsk_test_bearer") // Claude Code's ANTHROPIC_AUTH_TOKEN
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if gotPath != "/v1/messages" {
		t.Fatalf("upstream path=%q", gotPath)
	}
	if gotKey != "sk-ds-upstream" {
		t.Fatalf("upstream x-api-key=%q", gotKey)
	}
}

// Without a resolvable slot and without a fallback hook the request must fail
// loudly rather than forward somewhere arbitrary.
func TestAnthropicPlaneNoSlotAndNoFallbackFails(t *testing.T) {
	cfg := config.Config{GatewayDomain: "gw.descles.com", UpstreamTimeout: time.Second}
	h := proxy.New(cfg, provider.NewRegistry(nil), policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.KeyResolver = func(key string) (string, string, string, bool) {
		return "org", "", "agent", key == "dsk_test_bearer"
	}
	h.OrgUpstream = func(orgID, providerName string) (string, string, bool) { return "", "", false }

	req := httptest.NewRequest(http.MethodPost, "/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4-5-20250929","max_tokens":10,"messages":[]}`))
	req.Host = "anthropic.gw.descles.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("authorization", "Bearer dsk_test_bearer")
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
