package connect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/edge"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

type spans struct {
	mu  sync.Mutex
	got []*tracing.Span
}

func (s *spans) PutSpan(_ context.Context, sp *tracing.Span) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, sp)
	return nil
}

// realEdge runs the actual edge tool gateway, so the hook is tested against
// the same code a customer deploys.
func realEdge(t *testing.T) (Edge, *spans) {
	t.Helper()
	pol, err := policy.FromJSON(`{"defaults":{
		"require_approval":["local.write"],
		"arg_tools":[
			{"tool":"local.bash","args":{"command":["*rm -rf*","*push --force*"]},"decision":"deny"},
			{"tool":"local.read","args":{"path":["*.env","*/secrets/*"]},"decision":"deny"}
		]}}`)
	if err != nil {
		t.Fatal(err)
	}
	rec := &spans{}
	g := &edge.MCPGateway{
		Config: &edge.MCPConfig{Connectors: []edge.MCPConnector{{ID: "github", URL: "https://example.invalid"}}},
		Resolve: func(key string) (string, string, string, bool) {
			return "org_1", "user_1", "agent_1", key == "vk_agent"
		},
		Policy: policy.NewHolder(pol), Spans: rec,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /mcp", g.ServeConnectors)
	mux.HandleFunc("POST /v1/tool-check", g.ServeToolCheck)
	mux.HandleFunc("POST /v1/tool-report", g.ServeToolReport)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return Edge{URL: srv.URL, Key: "vk_agent"}, rec
}

func hook(t *testing.T, e Edge, phase, input string, failOpen bool) HookResult {
	t.Helper()
	return ClaudeHook(context.Background(), e, phase, strings.NewReader(input), failOpen)
}

func decisionOf(t *testing.T, r HookResult) string {
	t.Helper()
	if r.Stdout == "" {
		return ""
	}
	var out struct {
		H struct {
			Decision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(r.Stdout), &out); err != nil {
		t.Fatalf("hook stdout not JSON: %q", r.Stdout)
	}
	return out.H.Decision
}

func TestClaudeHookAgainstRealEdge(t *testing.T) {
	e, rec := realEdge(t)
	cases := []struct {
		name, input, want string
	}{
		{"safe shell passes to Claude Code's own rules", `{"session_id":"s-1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"go test ./..."}}`, ""},
		{"destructive shell denied", `{"session_id":"s-1","tool_name":"Bash","tool_input":{"command":"cd /tmp && rm -rf /"}}`, "deny"},
		{"force push denied", `{"session_id":"s-1","tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}`, "deny"},
		{"secrets read denied", `{"session_id":"s-1","tool_name":"Read","tool_input":{"file_path":"/repo/.env"}}`, "deny"},
		{"edits need the human", `{"session_id":"s-1","tool_name":"Edit","tool_input":{"file_path":"/repo/main.go"}}`, "ask"},
		{"edge MCP tools are governed at the edge, not twice", `{"session_id":"s-1","tool_name":"mcp__descles-github__create_issue","tool_input":{}}`, ""},
	}
	for _, c := range cases {
		if got := decisionOf(t, hook(t, e, "pre", c.input, false)); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if r := hook(t, e, "post", `{"session_id":"s-1","tool_name":"Bash","tool_input":{"command":"go test ./..."},"tool_response":{"stdout":"ok"}}`, false); r.Code != 0 || r.Stderr != "" {
		t.Fatalf("post: %+v", r)
	}
	// 3 denials + 1 approval request at pre, 1 execution at post; nothing for
	// the allowed-but-not-yet-run call or the edge-governed MCP tool.
	if len(rec.got) != 5 {
		t.Fatalf("want 5 spans, got %d", len(rec.got))
	}
	last := rec.got[4]
	if last.Attributes[tracing.AttrTool] != "local.bash" || last.Attributes[tracing.AttrPolicy] != "allow" || last.Status != "ok" || string(last.TraceID) != "s-1" {
		t.Fatalf("execution span: %+v", last)
	}
	for _, s := range rec.got {
		m := edge.FromSpan("edge-1", s)
		if err := m.Validate(); err != nil {
			t.Fatalf("metadata invalid: %v", err)
		}
		raw, _ := json.Marshal(m)
		if strings.Contains(string(raw), "rm -rf") || strings.Contains(string(raw), ".env") {
			t.Fatalf("command or path left the edge: %s", raw)
		}
	}
}

func TestClaudeHookFailsClosed(t *testing.T) {
	dead := Edge{URL: "http://127.0.0.1:1", Key: "vk"}
	in := `{"tool_name":"Bash","tool_input":{"command":"ls"}}`
	if got := decisionOf(t, hook(t, dead, "pre", in, false)); got != "deny" {
		t.Fatalf("unreachable edge must deny, got %q", got)
	}
	if r := hook(t, dead, "pre", in, true); r.Stdout != "" || r.Code != 0 {
		t.Fatalf("fail-open must allow: %+v", r)
	}
	e, _ := realEdge(t)
	e.Key = "stolen"
	if got := decisionOf(t, hook(t, e, "pre", in, false)); got != "deny" {
		t.Fatalf("bad key must deny, got %q", got)
	}
}

func TestConnectorsListing(t *testing.T) {
	e, _ := realEdge(t)
	got, err := e.Connectors(context.Background())
	if err != nil || len(got) != 1 || got[0] != "github" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestClaudeSettingsMergeIsIdempotentAndKeepsUserConfig(t *testing.T) {
	existing := `{"model":"opus","env":{"FOO":"1","ANTHROPIC_AUTH_TOKEN":"old"},"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"my-linter"}]}]}}`
	// Paths built for the running OS: ToSlash converts only this OS's separator.
	self, keyFile := filepath.Join("tools", "descles.exe"), filepath.Join("home", ".descles", "agent-key")
	once, err := ClaudeSettings([]byte(existing), "https://edge.acme", self, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := ClaudeSettings(once, "https://edge.acme", self, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Fatalf("second connect changed settings:\n%s\n---\n%s", once, twice)
	}
	var s map[string]any
	_ = json.Unmarshal(twice, &s)
	env := s["env"].(map[string]any)
	if s["model"] != "opus" || env["FOO"] != "1" || env["ANTHROPIC_BASE_URL"] != "https://edge.acme/anthropic" || env["ANTHROPIC_AUTH_TOKEN"] != nil {
		t.Fatalf("env: %+v", s)
	}
	pre := s["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 2 || !strings.Contains(string(twice), "my-linter") {
		t.Fatalf("user hook lost or descles hook duplicated: %+v", pre)
	}
	if !strings.Contains(s["apiKeyHelper"].(string), shellQuote(self)+" key --file "+shellQuote(keyFile)) || strings.Contains(string(twice), "vk_") {
		t.Fatalf("apiKeyHelper: %v", s["apiKeyHelper"])
	}
	if _, err := ClaudeSettings([]byte("{not json"), "https://e", "d", "k"); err == nil {
		t.Fatal("corrupt settings must not be overwritten")
	}
}

func TestCodexConfigManagedBlock(t *testing.T) {
	user := "model = \"o3\"\n\n[mcp_servers.mine]\ncommand = \"x\"\n"
	once := CodexConfig(user, "https://edge.acme", "gpt-5", []string{"org", "github"})
	twice := CodexConfig(once, "https://edge.acme", "gpt-5", []string{"org"})
	if !strings.HasPrefix(twice, user) || strings.Count(twice, codexBegin) != 1 {
		t.Fatalf("user config must be kept and block replaced:\n%s", twice)
	}
	if strings.Contains(twice, "descles-github") || !strings.Contains(twice, `[mcp_servers."descles-org"]`) || !strings.Contains(twice, `base_url = "https://edge.acme/v1"`) {
		t.Fatalf("block content:\n%s", twice)
	}
}

func TestHermesHookAgainstRealEdge(t *testing.T) {
	e, rec := realEdge(t)
	run := func(in string) HookResult {
		return HermesHook(context.Background(), e, strings.NewReader(in), false)
	}
	r := run(`{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"rm -rf ./build"},"session_id":"h-1"}`)
	var out map[string]string
	if json.Unmarshal([]byte(r.Stdout), &out) != nil || out["decision"] != "block" || !strings.Contains(out["reason"], "local.bash") {
		t.Fatalf("Hermes terminal rm -rf must be blocked in Hermes' dialect: %q", r.Stdout)
	}
	if r := run(`{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo hi"},"session_id":"h-1"}`); r.Stdout != "" || r.Code != 0 {
		t.Fatalf("allowed command must defer to Hermes: %+v", r)
	}
	if r := run(`{"hook_event_name":"pre_tool_call","tool_name":"patch","tool_input":{"path":"main.go"},"session_id":"h-1"}`); !strings.Contains(r.Stdout, `"block"`) {
		t.Fatalf("patch is a write and the test policy requires approval for writes: %q", r.Stdout)
	}
	before := len(rec.got)
	if r := run(`{"hook_event_name":"post_tool_call","tool_name":"terminal","tool_input":{"command":"echo hi"},"session_id":"h-1","extra":{"result":"hi"}}`); r.Code != 0 || len(rec.got) != before+1 {
		t.Fatalf("post_tool_call must report one execution: %+v", r)
	}
	dead := Edge{URL: "http://127.0.0.1:1", Key: "k"}
	if r := HermesHook(context.Background(), dead, strings.NewReader(`{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"ls"}}`), false); !strings.Contains(r.Stdout, "fail-closed") {
		t.Fatalf("unreachable edge must block: %q", r.Stdout)
	}
}

func TestShellQuoteWorksForBothWindowsShells(t *testing.T) {
	defer func(old string) { goos = old }(goos)
	goos = "windows"
	if got := shellQuote(`C:\Program Files\descles\descles.exe`); got != `"C:/Program Files/descles/descles.exe"` {
		t.Fatalf("windows: %s (cmd.exe rejects single quotes)", got)
	}
	goos = "linux"
	if got := shellQuote("/opt/it's $HOME/descles"); got != `'/opt/it'\''s $HOME/descles'` {
		t.Fatalf("posix: %s", got)
	}
}

func TestPlaybookVersionStamp(t *testing.T) {
	base, _ := ClaudeSettings(nil, "https://edge", "d", "k")
	out, err := SetPlaybookVersion(base, "eng@2026-09-26.1")
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	_ = json.Unmarshal(out, &s)
	env := s["env"].(map[string]any)
	if env["DESCLES_PLAYBOOK_VERSION"] != "eng@2026-09-26.1" || env["ANTHROPIC_CUSTOM_HEADERS"] != "X-Descles-Playbook-Version: eng@2026-09-26.1" || env["ANTHROPIC_BASE_URL"] != "https://edge/anthropic" {
		t.Fatalf("env: %+v", env)
	}
	if _, err := SetPlaybookVersion(base, "v1 with spaces"); err == nil {
		t.Fatal("free text accepted as a version")
	}
	cleared, _ := SetPlaybookVersion(out, "")
	if strings.Contains(string(cleared), "Playbook") {
		t.Fatal("empty version must remove the stamp")
	}
}

func TestPlaybookStampKeepsUsersOwnHeaders(t *testing.T) {
	base, _ := ClaudeSettings([]byte(`{"env":{"ANTHROPIC_CUSTOM_HEADERS":"X-Team: payments"}}`), "https://edge", "d", "k")
	out, _ := SetPlaybookVersion(base, "v2")
	if !strings.Contains(string(out), `X-Team: payments\nX-Descles-Playbook-Version: v2`) {
		t.Fatalf("user header lost: %s", out)
	}
	cleared, _ := SetPlaybookVersion(out, "")
	if !strings.Contains(string(cleared), "X-Team: payments") || strings.Contains(string(cleared), "Playbook") {
		t.Fatalf("clearing must remove only our header: %s", cleared)
	}
}
