package proxy_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/config"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/proxy"
	"github.com/chiatzenw-cur/descles/pkg/storage"
)

// blockingRewrite drives a NON-streaming chat completion through the real
// gateway (httptest upstream), with the given blocking-approval behavior.
func blockingRewrite(t *testing.T, blocker func(approvalID, agent, tool string, args map[string]any) policy.Decision) string {
	t.Helper()
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"deploy_to_prod":"require_approval"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", DenyEnforce: true}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"id":"r1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"deploy_to_prod","arguments":"{\"svc\":\"api\"}"}}]},"finish_reason":"tool_calls"}]}`)
	}))
	t.Cleanup(up.Close)
	reg := provider.NewRegistry([]provider.Config{{Name: "deepseek", BaseURL: up.URL, Models: []string{"*"}}})
	h := proxy.New(cfg, reg, policy.NewHolder(pol), store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.ApprovalSuspender = func(agentID, tool string, args map[string]any) (string, error) {
		return "appr-123", nil
	}
	if blocker != nil {
		h.ApprovalBlocker = blocker
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"deepseek-chat","stream":false,"messages":[{"role":"user","content":"deploy api"}]}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("gateway status %d: %s", rr.Code, rr.Body.String())
	}
	return rr.Body.String()
}

func parseChatResp(t *testing.T, out string) (toolCalls int, content string) {
	t.Helper()
	var msg struct {
		Choices []struct {
			Message struct {
				ToolCalls []map[string]any `json:"tool_calls"`
				Content   string           `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(out), &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m := msg.Choices[0].Message
	return len(m.ToolCalls), m.Content
}

// Blocking approval approved → the REAL tool call arrives in the same turn.
func TestBlockingApprovalAllowDeliversRealCall(t *testing.T) {
	out := blockingRewrite(t, func(approvalID, agent, tool string, args map[string]any) policy.Decision {
		return policy.Allow
	})
	toolCalls, content := parseChatResp(t, out)
	if toolCalls != 1 {
		t.Fatalf("expected the real tool call to survive a blocking approval, got %d calls: %s", toolCalls, out)
	}
	if strings.Contains(content, "pending human approval") || strings.Contains(content, "denied") {
		t.Fatalf("no note expected when blocking approved: %s", out)
	}
	if !strings.Contains(out, "deploy_to_prod") {
		t.Fatalf("deploy_to_prod missing: %s", out)
	}
}

// Blocking approval denied → the call is stripped, a denial note appears.
func TestBlockingApprovalDenyEmitsDenialNote(t *testing.T) {
	out := blockingRewrite(t, func(approvalID, agent, tool string, args map[string]any) policy.Decision {
		return policy.Deny
	})
	toolCalls, content := parseChatResp(t, out)
	if toolCalls != 0 {
		t.Fatalf("denied call must be stripped: %s", out)
	}
	if !strings.Contains(content, "denied by human approval") {
		t.Fatalf("expected denial note, got content %q", content)
	}
}

// Blocking timeout (RequireApproval) → durable pending note, call stripped.
func TestBlockingApprovalTimeoutKeepsPendingNote(t *testing.T) {
	out := blockingRewrite(t, func(approvalID, agent, tool string, args map[string]any) policy.Decision {
		return policy.RequireApproval
	})
	toolCalls, content := parseChatResp(t, out)
	if toolCalls != 0 {
		t.Fatalf("call must stay stripped on timeout: %s", out)
	}
	if !strings.Contains(content, "pending human approval") {
		t.Fatalf("expected durable pending note on timeout, got content %q", content)
	}
}

// No blocker wired → legacy async path unchanged.
func TestBlockingApprovalDisabledByDefault(t *testing.T) {
	out := blockingRewrite(t, nil)
	toolCalls, content := parseChatResp(t, out)
	if toolCalls != 0 {
		t.Fatalf("async path must strip the call: %s", out)
	}
	if !strings.Contains(content, "pending human approval") {
		t.Fatalf("expected pending note without blocker, got content %q", content)
	}
}
