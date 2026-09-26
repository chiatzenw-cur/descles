package edge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

func systemGateway(t *testing.T, pol string) (*MCPGateway, *spanLog, *atomic.Int32, *string) {
	t.Helper()
	calls := &atomic.Int32{}
	var lastAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		lastAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"list_accounts"},{"name":"delete_account"}]}}`)
		case "tools/call":
			calls.Add(1)
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"data":[{"id":"a1"}]}}}`)
		}
	}))
	t.Cleanup(up.Close)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "crm-token")
	if err := os.WriteFile(tokenFile, []byte("crm-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(dir, "mcp.yaml")
	if err := os.WriteFile(cfgFile, []byte("connectors:\n  - id: crm\n    url: "+up.URL+"\n    insecure_http: true\n    token_file: "+filepath.ToSlash(tokenFile)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadMCPConfig(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.FromJSON(pol)
	if err != nil {
		t.Fatal(err)
	}
	spans := &spanLog{}
	g := &MCPGateway{Config: cfg, Policy: policy.NewHolder(p), Spans: spans,
		// Delegated grants must not apply to system work: this would deny it.
		ToolAllowed: func(string, string, map[string]any) bool { return false }}
	return g, spans, calls, &lastAuth
}

func TestSystemCallRunsThroughTheEdgeUnderPolicy(t *testing.T) {
	g, spans, calls, auth := systemGateway(t, `{"defaults":{"tools":{"crm.delete_account":"deny","crm.export":"require_approval"}}}`)
	ctx := context.Background()

	raw, err := g.SystemCall(ctx, "system:sync", "crm.list_accounts", map[string]any{"limit": 10})
	if err != nil || !strings.Contains(string(raw), `"a1"`) {
		t.Fatalf("allowed call: %s %v", raw, err)
	}
	if *auth != "Bearer crm-secret" {
		t.Fatalf("upstream saw %q, want the edge's connector credential", *auth)
	}
	for tool, want := range map[string]string{"crm.delete_account": "deny", "crm.export": "require_approval"} {
		if _, err := g.SystemCall(ctx, "system:sync", tool, nil); !errors.Is(err, ErrSystemCallRefused) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want refused (%s)", tool, err, want)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream ran %d tool calls, want only the allowed one", calls.Load())
	}
	for _, bad := range []string{"agent-1", "system:", "system:a b"} {
		if _, err := g.SystemCall(ctx, bad, "crm.list_accounts", nil); err == nil {
			t.Errorf("principal %q accepted", bad)
		}
	}
	if _, err := g.SystemCall(ctx, "system:sync", "nope.list", nil); err == nil {
		t.Error("unknown connector accepted")
	}

	// Recorded like any call, under the declared tool name and the principal;
	// reported without an agent, since system work is not the org's agent.
	spans.mu.Lock()
	defer spans.mu.Unlock()
	if len(spans.spans) != 3 {
		t.Fatalf("%d records, want 3 (one executed, two refused)", len(spans.spans))
	}
	first := spans.spans[0]
	if first.AgentID != "system:sync" || first.Attributes[tracing.AttrTool] != "crm.list_accounts" || first.Status != "ok" {
		t.Fatalf("record: agent=%s tool=%v status=%s", first.AgentID, first.Attributes[tracing.AttrTool], first.Status)
	}
	md := FromSpan("edge-1", first)
	if md.AgentID != "" || md.Tool != "crm.list_accounts" {
		t.Fatalf("reported metadata: agent=%q tool=%q", md.AgentID, md.Tool)
	}
	if err := md.Validate(); err != nil {
		t.Fatal(err)
	}
}
