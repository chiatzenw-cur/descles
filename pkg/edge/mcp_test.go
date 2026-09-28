package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

type spanLog struct {
	mu    sync.Mutex
	spans []*tracing.Span
}

func (l *spanLog) PutSpan(_ context.Context, s *tracing.Span) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.spans = append(l.spans, s)
	return nil
}

func newTestGateway(t *testing.T) (*MCPGateway, *spanLog, *int, func() string) {
	t.Helper()
	dir := t.TempDir()
	calls := 0
	var lastAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuth = r.Header.Get("Authorization")
		var req rpcCall
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_customer"},{"name":"refund"},{"name":"delete_customer"}]}}`)
		case "tools/call":
			calls++
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"id":"cus_1","email":"ap@acme.com","name":"Acme","plan":"pro"}}}`)
		}
	}))
	t.Cleanup(upstream.Close)
	tokenFile := filepath.Join(dir, "stripe-token")
	if err := os.WriteFile(tokenFile, []byte("sk_live_local_only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(dir, "mcp.yaml")
	cfgYAML := "connectors:\n  - id: stripe\n    url: " + upstream.URL + "\n    insecure_http: true\n    token_file: " + filepath.ToSlash(tokenFile) + "\nclearances:\n  agents:\n    agent_fin: [finance]\n"
	if err := os.WriteFile(cfgFile, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadMCPConfig(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"stripe.delete_customer":"deny"},"require_approval":["stripe.refund"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	memo := &memoExt{}
	spans := &spanLog{}
	g := &MCPGateway{
		Config: cfg,
		Resolve: func(key string) (string, string, string, bool) {
			switch key {
			case "vk_fin":
				return "org_1", "user_1", "agent_fin", true
			case "vk_sales":
				return "org_1", "user_2", "agent_sales", true
			}
			return "", "", "", false
		},
		Policy: policy.NewHolder(pol), Spans: spans, Extensions: []Extension{memo}, Observers: []Observer{memo},
	}
	return g, spans, &calls, func() string { return lastAuth }
}

func rpc(t *testing.T, g http.Handler, connector, key, body string) (int, map[string]any) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("POST /mcp/{connector}", g)
	req := httptest.NewRequest(http.MethodPost, "/mcp/"+connector, bytes.NewBufferString(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func toolResultText(out map[string]any) (string, bool) {
	res, _ := out["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		return "", false
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	isErr, _ := res["isError"].(bool)
	return text, isErr
}

func TestEdgeMCPGovernsExecutesAndLearns(t *testing.T) {
	g, spans, calls, lastAuth := newTestGateway(t)

	if code, _ := rpc(t, g, "stripe", "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated call: %d", code)
	}

	_, out := rpc(t, g, "stripe", "vk_fin", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	tools := out["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("delete_customer is always denied and must be hidden: %+v", tools)
	}

	_, out = rpc(t, g, "stripe", "vk_fin", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_customer","arguments":{"id":"cus_1","secret_note":"do not export"}}}`)
	if *calls != 1 || lastAuth() != "Bearer sk_live_local_only" {
		t.Fatalf("allowed call must reach upstream with the local credential: calls=%d auth=%q", *calls, lastAuth())
	}
	if res, _ := out["result"].(map[string]any); res["structuredContent"] == nil {
		t.Fatalf("upstream result not returned: %+v", out)
	}

	for _, name := range []string{"refund", "delete_customer"} {
		_, out = rpc(t, g, "stripe", "vk_fin", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"`+name+`","arguments":{}}}`)
		if text, isErr := toolResultText(out); !isErr || text == "" {
			t.Fatalf("%s must be refused: %+v", name, out)
		}
	}
	if *calls != 1 {
		t.Fatal("refused calls reached the upstream")
	}

	// Metadata leaving the edge carries the tool name and decision only.
	if len(spans.spans) != 3 {
		t.Fatalf("want 3 tool spans, got %d", len(spans.spans))
	}
	decisions := map[string]string{}
	for _, s := range spans.spans {
		m := FromSpan("edge-1", s)
		if err := m.Validate(); err != nil {
			t.Fatalf("tool metadata invalid: %v", err)
		}
		raw, _ := json.Marshal(m)
		if strings.Contains(string(raw), "do not export") || strings.Contains(string(raw), "cus_1") || strings.Contains(string(raw), "sk_live") {
			t.Fatalf("content left the edge: %s", raw)
		}
		decisions[m.Tool] = m.Policy
	}
	if decisions["stripe.get_customer"] != "allow" || decisions["stripe.refund"] != "require_approval" || decisions["stripe.delete_customer"] != "deny" {
		t.Fatalf("decisions: %+v", decisions)
	}

	// Observers saw exactly the one successful call; refusals are not results.
	g.Close(5 * time.Second) // observations are delivered in the background
	memo := g.Extensions[0].(*memoExt)
	if len(memo.seen) != 1 || memo.seen[0].Tool != "stripe.get_customer" || memo.seen[0].AgentID != "agent_fin" {
		t.Fatalf("observations: %+v", memo.seen)
	}
	// Extensions are served behind the edge's auth, with edge-computed clearances.
	_, out = rpc(t, g, "org", "vk_fin", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"memo_last","arguments":{}}}`)
	if text, isErr := toolResultText(out); isErr || !strings.Contains(text, "cus_1") {
		t.Fatalf("cleared agent should read the extension: %q", text)
	}
	_, out = rpc(t, g, "org", "vk_sales", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"memo_last","arguments":{}}}`)
	if text, isErr := toolResultText(out); !isErr || text != "not found" {
		t.Fatalf("uncleared agent must get not found: %q", text)
	}
	_, out = rpc(t, g, "org", "vk_sales", `{"jsonrpc":"2.0","id":6,"method":"tools/list"}`)
	if tools := out["result"].(map[string]any)["tools"].([]any); len(tools) != 1 {
		t.Fatalf("extension tools list: %d", len(tools))
	}
	if code, _ := rpc(t, g, "org", "", `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`); code != http.StatusUnauthorized {
		t.Fatalf("extension reachable without an agent key: %d", code)
	}
}

// memoExt is a test extension that remembers the last observed result and
// shows it only to callers cleared for "finance".
type memoExt struct{ seen []Observation }

type adminOnlyTestExt struct{ *memoExt }

func (a *adminOnlyTestExt) ID() string      { return "learning-admin" }
func (a *adminOnlyTestExt) AdminOnly() bool { return true }

func TestAdminOnlyPanelIsNotAnAgentConnector(t *testing.T) {
	g, _, _, _ := newTestGateway(t)
	g.Extensions = append(g.Extensions, &adminOnlyTestExt{&memoExt{}})
	if g.extension("learning-admin") != nil {
		t.Fatal("admin-only panel exposed at MCP connector route")
	}
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer vk_fin")
	rec := httptest.NewRecorder()
	g.ServeConnectors(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "learning-admin") {
		t.Fatalf("admin-only panel in agent connector list: %d %s", rec.Code, rec.Body.String())
	}
}

func (m *memoExt) ID() string           { return OrgConnectorID }
func (m *memoExt) Instructions() string { return "test" }
func (m *memoExt) Tools() []ExtensionTool {
	return []ExtensionTool{{Name: "memo_last", Description: "last result", InputSchema: map[string]any{"type": "object"}}}
}
func (m *memoExt) Call(_ context.Context, c Caller, tool string, _ map[string]any) (any, error) {
	cleared := false
	for _, l := range c.Clearances {
		cleared = cleared || l == "finance"
	}
	if tool != "memo_last" || !cleared || len(m.seen) == 0 {
		return nil, ErrNotFound
	}
	return string(m.seen[len(m.seen)-1].Result), nil
}
func (m *memoExt) Observe(_ context.Context, o Observation) { m.seen = append(m.seen, o) }
