package proxy_test

import (
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
)

// Clients probe /v1/models to discover an endpoint. With a model map configured
// the alias is a name this gateway accepts but the upstream has never heard of,
// so it has to be advertised here or it cannot be discovered at all.
func TestModelCatalogAdvertisesAliases(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" && r.URL.Path != "/models" {
			t.Errorf("upstream path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"object":"list","data":[{"id":"deepseek-v4-pro","object":"model","owned_by":"deepseek"}]}`)
	}))
	defer upstream.Close()

	h := catalogHandler(t, upstream.URL, "openai")
	body := getModels(t, h)

	var out struct {
		Object string `json:"object"`
		Data   []struct {
			ID       string `json:"id"`
			Object   string `json:"object"`
			Upstream string `json:"descles_upstream_model"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("catalogue is not JSON: %v (%s)", err, body)
	}
	if out.Object != "list" {
		t.Fatalf("object = %q, want list", out.Object)
	}
	ids := map[string]string{}
	for _, m := range out.Data {
		ids[m.ID] = m.Upstream
	}
	for _, want := range []string{"deepseek-v4-pro", "deepseek-flash", "claude-opus-*", "claude-haiku-*"} {
		if _, ok := ids[want]; !ok {
			t.Fatalf("catalogue missing %q: %s", want, body)
		}
	}
	if ids["claude-opus-*"] != "deepseek-v4-pro" {
		t.Fatalf("alias does not name its upstream target: %q", ids["claude-opus-*"])
	}
	if ids["deepseek-v4-pro"] != "" {
		t.Fatalf("an upstream model should not be marked as an alias: %s", body)
	}
}

// An Anthropic-wire slot answers in the shape an Anthropic client parses.
func TestModelCatalogUsesAnthropicShapeForAnthropicWire(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":[{"type":"model","id":"claude-sonnet-4-5","display_name":"Sonnet"}]}`)
	}))
	defer upstream.Close()

	h := catalogHandler(t, upstream.URL, "anthropic")
	body := getModels(t, h)

	var out struct {
		HasMore bool   `json:"has_more"`
		FirstID string `json:"first_id"`
		Data    []struct {
			Type        string `json:"type"`
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, body)
	}
	found := false
	for _, m := range out.Data {
		if m.Type != "model" {
			t.Fatalf("entry type = %q, want model: %s", m.Type, body)
		}
		if m.ID == "claude-opus-*" {
			found = true
			if !strings.Contains(m.DisplayName, "deepseek-v4-pro") {
				t.Fatalf("alias entry does not name its target: %+v", m)
			}
		}
	}
	if !found {
		t.Fatalf("alias missing from the Anthropic-shaped catalogue: %s", body)
	}
	if out.FirstID == "" {
		t.Fatalf("first_id not set: %s", body)
	}
}

// Without a map there is nothing to add and the upstream body must pass through
// byte for byte.
func TestModelCatalogUnchangedWithoutAliases(t *testing.T) {
	const upstreamBody = `{"object":"list","data":[{"id":"deepseek-flash"}]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, upstreamBody)
	}))
	defer upstream.Close()

	cfg := config.Config{Storage: "memory", LogLevel: "error", GatewayDomain: "gw.descles.com", UpstreamTimeout: 5 * time.Second}
	h := proxy.New(cfg, provider.NewRegistry(nil), policy.NewHolder(policy.AllowAll()),
		storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.KeyResolver = func(key string) (string, string, string, bool) { return "org1", "", "agent1", key == "dsk_cat" }
	h.OrgUpstream = func(orgID, slot string) (string, string, bool) { return upstream.URL, "sk", orgID == "org1" }
	// No OrgSlotConfig: a slot with no map advertises nothing extra.
	if got := string(getModels(t, h)); got != upstreamBody {
		t.Fatalf("body altered:\n got %s\nwant %s", got, upstreamBody)
	}
}

func catalogHandler(t *testing.T, upstreamURL, wire string) *proxy.Handler {
	t.Helper()
	cfg := config.Config{Storage: "memory", LogLevel: "error", GatewayDomain: "gw.descles.com", UpstreamTimeout: 5 * time.Second}
	h := proxy.New(cfg, provider.NewRegistry(nil), policy.NewHolder(policy.AllowAll()),
		storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.KeyResolver = func(key string) (string, string, string, bool) { return "org1", "", "agent1", key == "dsk_cat" }
	h.OrgUpstream = func(orgID, slot string) (string, string, bool) {
		if orgID == "org1" {
			return upstreamURL, "sk-upstream", true
		}
		return "", "", false
	}
	h.OrgSlotConfig = func(orgID, slot string) (string, map[string]string, string, bool) {
		return wire, map[string]string{"claude-opus-*": "deepseek-v4-pro", "claude-haiku-*": "deepseek-flash"}, "deepseek-flash", true
	}
	return h
}

func getModels(t *testing.T, h *proxy.Handler) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Host = "anthropic.gw.descles.com"
	req.Header.Set("Authorization", "Bearer dsk_cat")
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	return rr.Body.Bytes()
}
