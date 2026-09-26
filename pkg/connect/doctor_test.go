package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/edge"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/storage"
)

func doctorEdge(t *testing.T) (Edge, string) {
	t.Helper()
	mem := storage.NewMemory()
	g := &edge.MCPGateway{Config: &edge.MCPConfig{}, Policy: policy.NewHolder(policy.AllowAll()), Spans: mem,
		Resolve: func(k string) (string, string, string, bool) { return "o", "u", "a", k == "vk_ok" }}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /mcp", g.ServeConnectors)
	mux.HandleFunc("POST /v1/tool-check", g.ServeToolCheck)
	mux.HandleFunc("POST /v1/tool-report", g.ServeToolReport)
	(&edge.ApprovalAdmin{Store: &edge.ApprovalStore{}, Token: "admin-tok", Traces: mem}).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return Edge{URL: srv.URL, Key: "vk_ok"}, "admin-tok"
}

func statuses(checks []Check) map[string]string {
	out := map[string]string{}
	for _, c := range checks {
		out[c.Name] = c.Status
	}
	return out
}

func TestDoctorHealthySetup(t *testing.T) {
	e, admin := doctorEdge(t)
	home := t.TempDir()
	settings, _ := ClaudeSettings(nil, e.URL, `C:\tools\descles.exe`, filepath.Join(home, "key"))
	settings, _ = SetPlaybookVersion(settings, "eng@1")
	_ = os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	_ = os.WriteFile(filepath.Join(home, ".claude", "settings.json"), settings, 0o600)
	_ = os.WriteFile(filepath.Join(home, "key"), []byte("vk_ok"), 0o600)
	t.Setenv("ANTHROPIC_BASE_URL", "")
	checks := Doctor(context.Background(), DoctorOptions{Edge: e, AdminToken: admin, Home: home, KeyFile: filepath.Join(home, "key"), GOOS: goos})
	s := statuses(checks)
	for _, name := range []string{"edge reachable", "agent key accepted", "tool-check", "trace linkage", "claude code model traffic", "claude code PreToolUse hook", "claude code PostToolUse hook", "claude code key", "claude code playbook version"} {
		if s[name] != CheckOK {
			t.Errorf("%s: %s (%+v)", name, s[name], checks)
		}
	}
	if s["codex"] != CheckSkip {
		t.Errorf("codex not configured must be skipped, got %s", s["codex"])
	}
}

func TestDoctorCatchesKnownBreakages(t *testing.T) {
	e, _ := doctorEdge(t)
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	// The Windows quoting bug found live, a base URL pointing elsewhere, no hooks.
	_ = os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{"env":{"ANTHROPIC_BASE_URL":"https://api.anthropic.com"},"apiKeyHelper":"'C:/tools/descles.exe' key"}`), 0o600)
	t.Setenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
	checks := Doctor(context.Background(), DoctorOptions{Edge: e, Home: home, GOOS: "windows"})
	s := statuses(checks)
	for name, want := range map[string]string{
		"claude code model traffic": CheckFail, "claude code PreToolUse hook": CheckFail, "claude code key": CheckFail,
		"trace linkage": CheckSkip, "environment": CheckWarn,
	} {
		if s[name] != want {
			t.Errorf("%s = %s, want %s", name, s[name], want)
		}
	}
	for _, c := range checks {
		if c.Status == CheckFail && c.Fix == "" {
			t.Errorf("%s fails without saying how to fix it", c.Name)
		}
	}
	bad := Edge{URL: e.URL, Key: "vk_wrong"}
	if s := statuses(Doctor(context.Background(), DoctorOptions{Edge: bad, Home: home})); s["agent key accepted"] != CheckFail || strings.Contains(strings.Join(keys(s), ","), "tool-check") {
		t.Fatalf("a rejected key must stop the checks there: %v", s)
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDoctorReportsFailingApprovalSweep(t *testing.T) {
	for _, tc := range []struct {
		body, want string
	}{
		{`{"approval_sweep":{"interval":"1m0s","consecutive_failures":3,"last_error":"disk I/O error"}}`, CheckFail},
		{`{"approval_sweep":{"interval":"1m0s","consecutive_failures":0}}`, CheckOK},
		{`{"edge_id":"old-edge"}`, CheckSkip},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/admin/info" || r.Header.Get("Authorization") != "Bearer admin-tok" {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(tc.body))
		}))
		c := approvalSweepCheck(context.Background(), DoctorOptions{Edge: Edge{URL: srv.URL}, AdminToken: "admin-tok"})
		srv.Close()
		if c.Status != tc.want {
			t.Errorf("%s: got %s (%s), want %s", tc.body, c.Status, c.Detail, tc.want)
		}
	}
}
