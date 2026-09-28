package edgeapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/edge"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/provider"
)

func TestStandaloneConsoleManagementPersistsAndMasksSecrets(t *testing.T) {
	dir := t.TempDir()
	sum := sha256.Sum256([]byte("seed-key"))
	seed := filepath.Join(dir, "seed.json")
	raw, _ := json.Marshal([]edge.LocalKeyGrant{{KeySHA256: hex.EncodeToString(sum[:]), OrgID: "local", AgentID: "first"}})
	if err := os.WriteFile(seed, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := edge.LoadWritableKeyring(seed, filepath.Join(dir, "agent-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	seedProviders := []provider.Config{{Name: "openai", BaseURL: "https://api.openai.com/v1", APIKey: "env-key"}}
	registry := provider.NewRegistry(seedProviders)
	policySource := filepath.Join(dir, "policy-seed.yaml")
	if err := os.WriteFile(policySource, []byte("defaults:\n  tools:\n    '*': allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := openLocalManagement(dir, keys, registry, seedProviders, "admin-token", policy.NewHolder(policy.AllowAll()), policySource)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	m.RegisterAdmin(mux, func(h http.Handler) http.Handler { return h })
	call := func(method, path, body string) (int, []byte) {
		t.Helper()
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code, w.Body.Bytes()
	}
	if code, _ := call("POST", "/admin/teams", `{"id":"engineering","name":"Engineering"}`); code != 200 {
		t.Fatalf("create team: %d", code)
	}
	code, body := call("POST", "/admin/agents", `{"id":"builder","group_id":"engineering"}`)
	if code != 200 {
		t.Fatalf("issue key: %d %s", code, body)
	}
	var issued struct {
		Key string `json:"key"`
	}
	_ = json.Unmarshal(body, &issued)
	if org, _, agent, ok := keys.Resolve(issued.Key); !ok || org != "local" || agent != "builder" {
		t.Fatal("issued key did not authenticate")
	}
	if keys.GroupOf("builder") != "engineering" {
		t.Fatal("team did not reach policy resolver")
	}
	code, body = call("POST", "/admin/agents/builder/rotate", "")
	if code != 200 {
		t.Fatalf("rotate: %d %s", code, body)
	}
	if _, _, _, ok := keys.Resolve(issued.Key); ok {
		t.Fatal("rotated key still works")
	}
	if code, body = call("POST", "/admin/providers", `{"name":"custom","base_url":"https://example.com/v1","api_key":"secret-value","models":["custom-*"]}`); code != 200 {
		t.Fatalf("add provider: %d %s", code, body)
	}
	if p, ok := registry.ResolveMatch("custom-v1"); !ok || p.Upstream.APIKey != "secret-value" {
		t.Fatal("new provider did not reach live router")
	}
	if code, body = call("POST", "/admin/providers", `{"name":"openai","base_url":"https://example.com/v1","api_key":"replacement-key","models":["gpt-*"]}`); code != 200 {
		t.Fatalf("replace environment provider: %d %s", code, body)
	}
	if p, ok := registry.ResolveMatch("gpt-test"); !ok || p.Upstream.APIKey != "replacement-key" {
		t.Fatal("console override did not replace environment key")
	}
	_, body = call("GET", "/admin/providers", "")
	if bytes.Contains(body, []byte("secret-value")) {
		t.Fatal("provider list exposed key")
	}
	disk, err := os.ReadFile(filepath.Join(dir, "console.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, []byte("secret-value")) {
		t.Fatal("provider key was stored in plaintext")
	}
	if _, err := openLocalManagement(dir, keys, provider.NewRegistry(nil), seedProviders, "admin-token", policy.NewHolder(policy.AllowAll()), policySource); err != nil {
		t.Fatalf("reload state: %v", err)
	}
	if _, err := openLocalManagement(dir, keys, provider.NewRegistry(nil), seedProviders, "changed-token", policy.NewHolder(policy.AllowAll()), policySource); err == nil || !strings.Contains(err.Error(), "cannot decrypt") {
		t.Fatal("admin token change did not fail safely")
	}
	reloaded, err := edge.LoadWritableKeyring(seed, filepath.Join(dir, "agent-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.GroupOf("builder") != "engineering" {
		t.Fatal("agent team not persisted")
	}
	if code, body = call("DELETE", "/admin/teams/engineering", ""); code != 409 {
		t.Fatalf("removed nonempty team: %d %s", code, body)
	}
	if code, body = call("PUT", "/admin/policy/source", `{"raw":"defaults:\n  tools:\n    local.bash: deny\n"}`); code != 200 {
		t.Fatalf("save policy: %d %s", code, body)
	}
	if code, body = call("GET", "/admin/policy/source", ""); code != 200 || !bytes.Contains(body, []byte("local.bash")) {
		t.Fatalf("saved policy not readable: %d %s", code, body)
	}
	if code, body = call("PUT", "/admin/policy/source", `{"raw":"defaults: [invalid"}`); code != 400 {
		t.Fatalf("invalid policy accepted: %d %s", code, body)
	}
}

func TestTeamAdminCannotManageAnotherTeamsKeys(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed.json")
	sum := sha256.Sum256([]byte("seed-key"))
	raw, _ := json.Marshal([]edge.LocalKeyGrant{{KeySHA256: hex.EncodeToString(sum[:]), OrgID: "local", AgentID: "seed"}})
	if err := os.WriteFile(seed, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := edge.LoadWritableKeyring(seed, filepath.Join(dir, "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	policySource := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policySource, []byte("defaults:\n  tools: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := openLocalManagement(dir, keys, provider.NewRegistry(nil), nil, "owner-secret", policy.NewHolder(policy.AllowAll()), policySource)
	if err != nil {
		t.Fatal(err)
	}
	access, err := edge.OpenAdminAccess(filepath.Join(dir, "console-users.json"))
	if err != nil {
		t.Fatal(err)
	}
	teamKey, err := access.IssueScoped("lead", "Lead", "team_admin", []string{"red"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := edge.OpenApprovals(filepath.Join(dir, "approvals.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admin := &edge.ApprovalAdmin{Store: store, Token: "owner-secret", Access: access, GroupOf: keys.GroupOf, LocalManagement: m}
	mux := http.NewServeMux()
	admin.Register(mux)
	call := func(token, method, path, body string) (int, string) {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	for _, team := range []string{"red", "blue"} {
		if code, body := call("owner-secret", "POST", "/admin/teams", `{"id":"`+team+`","name":"`+team+`"}`); code != 200 {
			t.Fatalf("team: %d %s", code, body)
		}
	}
	if code, body := call(teamKey, "POST", "/admin/agents", `{"id":"blue-bot","group_id":"blue"}`); code != 403 {
		t.Fatalf("cross-team issue: %d %s", code, body)
	}
	if code, body := call(teamKey, "POST", "/admin/agents", `{"id":"red-bot","group_id":"red"}`); code != 200 {
		t.Fatalf("in-team issue: %d %s", code, body)
	}
	if code, body := call("owner-secret", "POST", "/admin/agents", `{"id":"blue-bot","group_id":"blue"}`); code != 200 {
		t.Fatalf("owner issue: %d %s", code, body)
	}
	if code, body := call(teamKey, "GET", "/admin/agents", ""); code != 200 || !strings.Contains(body, "red-bot") || strings.Contains(body, "blue-bot") {
		t.Fatalf("scoped list: %d %s", code, body)
	}
	if code, body := call(teamKey, "POST", "/admin/agents/blue-bot/rotate", ""); code != 404 {
		t.Fatalf("cross-team rotation: %d %s", code, body)
	}
	if code, body := call(teamKey, "DELETE", "/admin/agents/blue-bot", ""); code != 404 {
		t.Fatalf("cross-team revoke: %d %s", code, body)
	}
	if code, body := call(teamKey, "GET", "/admin/providers", ""); code != 403 {
		t.Fatalf("global provider access: %d %s", code, body)
	}
}
