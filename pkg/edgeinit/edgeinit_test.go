package edgeinit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/config"
	"github.com/chiatzenw-cur/descles/pkg/edge"
	"github.com/chiatzenw-cur/descles/pkg/edgeapp"
)

// TestGeneratedStandaloneEdgeBootsAndEnforces is the promise of `edge init`:
// fill in one credential and the generated deployment runs and governs.
func TestGeneratedStandaloneEdgeBootsAndEnforces(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "edge")
	res, err := Generate(Options{Dir: dir, Providers: []string{"anthropic"}, AgentName: "dev-laptop",
		Connectors: []Connector{{ID: "github", URL: "https://api.githubcopilot.com/mcp/"}}, UID: -1, GID: -1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.AgentKey, "vk_") {
		t.Fatalf("agent key: %q", res.AgentKey)
	}
	keys, _ := os.ReadFile(filepath.Join(dir, "config", "keys.json"))
	if strings.Contains(string(keys), res.AgentKey) {
		t.Fatal("plaintext agent key stored")
	}
	compose, _ := os.ReadFile(filepath.Join(dir, "compose.yml"))
	if strings.Contains(string(compose), "user:") || !strings.Contains(string(compose), "Pin by digest") {
		t.Fatalf("compose:\n%s", compose)
	}
	if _, err := Generate(Options{Dir: dir, UID: -1, GID: -1}); err == nil {
		t.Fatal("re-running init must not overwrite an existing deployment")
	}
	if err := os.WriteFile(filepath.Join(dir, "config", "secrets", "anthropic-key"), []byte("sk-ant-local-only"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Run the edge exactly as the container would, with host paths for the
	// container mount points.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	envFile, _ := os.Open(filepath.Join(dir, "edge.env"))
	sc := bufio.NewScanner(envFile)
	for sc.Scan() {
		line := sc.Text()
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		v = strings.ReplaceAll(v, "/config/", filepath.ToSlash(filepath.Join(dir, "config"))+"/")
		v = strings.ReplaceAll(v, "/data/", filepath.ToSlash(filepath.Join(dir, "data"))+"/")
		t.Setenv(k, v)
	}
	envFile.Close()
	t.Setenv("DESCLES_ADDR", addr)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- edgeapp.Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("edge exited with %v", err)
		}
	}()
	base := "http://" + addr
	var up bool
	for i := 0; i < 50 && !up; i++ {
		if resp, err := http.Get(base + "/healthz"); err == nil {
			up = resp.StatusCode == http.StatusOK
			resp.Body.Close()
		}
		if !up {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !up {
		select {
		case err := <-done:
			t.Fatalf("edge did not start: %v", err)
		default:
			t.Fatal("edge did not become healthy")
		}
	}
	call := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, base+path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+res.AgentKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := call(http.MethodGet, "/mcp", ""); code != 200 || strings.Contains(body, `"org"`) || !strings.Contains(body, `"github"`) {
		t.Fatalf("connectors: %d %s", code, body)
	}
	_, body := call(http.MethodPost, "/v1/tool-check", `{"client":"claude-code","tool":"Bash","input":{"command":"sudo rm -rf /"}}`)
	var v struct{ Decision string }
	_ = json.Unmarshal([]byte(body), &v)
	if v.Decision != "deny" {
		t.Fatalf("generated policy must deny rm -rf: %s", body)
	}
	_, body = call(http.MethodPost, "/v1/tool-check", `{"client":"claude-code","tool":"Bash","input":{"command":"go test ./..."}}`)
	if !strings.Contains(body, `"allow"`) {
		t.Fatalf("safe command: %s", body)
	}
	if code, _ := call(http.MethodPost, "/mcp/org", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); code != http.StatusNotFound {
		t.Fatalf("the open-core edge has no org extension: %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "config", "orgctx-extractors.yaml")); err == nil {
		t.Fatal("org context config generated without --org-context")
	}
	req, _ := http.NewRequest(http.MethodGet, base+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer vk_wrong")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong key: %v %v", resp, err)
	}
	// Approvals are on, behind the generated admin token.
	adminToken, _ := os.ReadFile(filepath.Join(dir, "config", "secrets", "admin-token"))
	for token, want := range map[string]int{strings.TrimSpace(string(adminToken)): 200, res.AgentKey: 401} {
		req, _ := http.NewRequest(http.MethodGet, base+"/admin/approvals?state=pending", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != want {
			t.Fatalf("admin approvals with token %q...: %v %v", token[:6], resp, err)
		}
		resp.Body.Close()
	}
	if resp, err := http.Get(base + "/admin/"); err != nil || resp.StatusCode != 200 {
		t.Fatalf("approver page: %v %v", resp, err)
	}
	// Standalone means nothing is queued for anyone.
	if _, err := os.Stat(filepath.Join(dir, "data", "outbox.db")); err == nil {
		t.Fatal("standalone edge created an outbox")
	}
}

func TestHostedAndValidation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hosted")
	key := strings.Repeat("ab", 32)
	res, err := Generate(Options{Dir: dir, Mode: "hosted", HostedURL: "https://app.descles.com", OrgID: "org_123", BundleKey: key, UID: 1000, GID: 1000, Image: "ghcr.io/descles/edge@sha256:" + strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if res.AgentKey != "" {
		t.Fatal("hosted agents get keys from the control plane, not init")
	}
	env, _ := os.ReadFile(filepath.Join(dir, "edge.env"))
	for _, want := range []string{"DESCLES_EDGE_REPORT_URL=https://app.descles.com/edge/spans", "DESCLES_EDGE_BUNDLE_URL=https://app.descles.com/edge/bundle", "DESCLES_EDGE_BUNDLE_PUBKEY=" + key, "DESCLES_EDGE_REPORT_TOKEN_FILE=/config/secrets/report-token"} {
		if !strings.Contains(string(env), want) {
			t.Errorf("missing %s", want)
		}
	}
	compose, _ := os.ReadFile(filepath.Join(dir, "compose.yml"))
	if !strings.Contains(string(compose), `user: "1000:1000"`) || strings.Contains(string(compose), "Pin by digest") {
		t.Fatalf("compose:\n%s", compose)
	}
	for i, bad := range []Options{
		{Mode: "hosted", HostedURL: "http://insecure", OrgID: "o", BundleKey: key},
		{Mode: "hosted", HostedURL: "https://app.descles.com", OrgID: "o", BundleKey: "short"},
		{Connectors: []Connector{{ID: "org", URL: "https://x"}}},
		{Providers: []string{"gemini"}},
	} {
		bad.Dir = filepath.Join(t.TempDir(), fmt.Sprint(i))
		if _, err := Generate(bad); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestSelfhostInitKeepsReportingOffAndUsesSignedGrants(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "selfhost")
	key := strings.Repeat("ab", 32)
	_, err := Generate(Options{Dir: dir, Mode: "selfhost", HostedURL: "http://127.0.0.1:8080", OrgID: "org_123", BundleKey: key, UID: -1, GID: -1})
	if err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(filepath.Join(dir, "edge.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DESCLES_EDGE_REPORT_URL=off", "DESCLES_EDGE_BUNDLE_URL=http://127.0.0.1:8080/edge/bundle", "DESCLES_EDGE_REPORT_TOKEN_FILE=/config/secrets/report-token"} {
		if !strings.Contains(string(env), want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(string(env), "DESCLES_EDGE_OUTBOX_DB") || strings.Contains(string(env), "DESCLES_EDGE_REPORT_URL=http") {
		t.Fatal("selfhost unexpectedly exports usage metadata")
	}
}

func TestSelfhostEdgeFetchesBundleWithoutReporting(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const agentKey = "vk_customer_agent"
	sum := sha256.Sum256([]byte(agentKey))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/edge/bundle" || r.Header.Get("Authorization") != "Bearer edge-sync-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		now := time.Now().UTC()
		signed, err := edge.SignBundle(edge.BundlePayload{Version: 1, OrgID: "org_test", Policy: json.RawMessage(`{}`), Grants: []edge.Grant{{KeySHA256: hex.EncodeToString(sum[:]), AgentID: "agent_test", Permission: "*", Resource: "*"}}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}, private)
		if err != nil {
			t.Error(err)
			http.Error(w, "sign", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(signed)
	}))
	defer server.Close()
	dir := filepath.Join(t.TempDir(), "selfhost-live")
	_, err = Generate(Options{Dir: dir, Mode: "selfhost", HostedURL: server.URL, OrgID: "org_test", BundleKey: hex.EncodeToString(pub), Providers: []string{"anthropic"}, UID: -1, GID: -1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config", "secrets", "report-token"), []byte("edge-sync-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config", "secrets", "anthropic-key"), []byte("sk-local"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "edge.env"))
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		v = strings.ReplaceAll(v, "/config/", filepath.ToSlash(filepath.Join(dir, "config"))+"/")
		v = strings.ReplaceAll(v, "/data/", filepath.ToSlash(filepath.Join(dir, "data"))+"/")
		t.Setenv(k, v)
	}
	_ = f.Close()
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	t.Setenv("DESCLES_ADDR", addr)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- edgeapp.Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("edge exit: %v", err)
		}
	}()
	var response *http.Response
	for i := 0; i < 50; i++ {
		response, err = http.Get("http://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+agentKey)
	response, err = http.DefaultClient.Do(req)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("signed grant not active: %v %v", response, err)
	}
	_ = response.Body.Close()
	if _, err := os.Stat(filepath.Join(dir, "data", "outbox.db")); err == nil {
		t.Fatal("metadata outbox created despite reporting off")
	}
}
