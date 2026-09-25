package proxy_test

import (
	"context"
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

func TestBoundKeyDoesNotInheritSpoofedUserOrAgent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"model":"test-model","choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	defer upstream.Close()
	st := storage.NewMemory()
	h := proxy.New(config.Config{}, provider.NewRegistry([]provider.Config{{BaseURL: upstream.URL}}), policy.NewHolder(policy.AllowAll()), st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.KeyResolver = func(key string) (string, string, string, bool) { return "org_1", "", "", key == "valid" }
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer valid")
	req.Header.Set("X-Descles-Org", "other-org")
	req.Header.Set("X-Descles-User", "mallory")
	req.Header.Set("X-Descles-Agent", "admin-agent")
	resp := httptest.NewRecorder()
	h.Routes().ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	spans, err := st.ListRecent(context.Background(), 1)
	if err != nil || len(spans) != 1 {
		t.Fatalf("spans=%d err=%v", len(spans), err)
	}
	if spans[0].OrganizationID != "org_1" || spans[0].UserID != "" || spans[0].AgentID != "" {
		t.Fatalf("caller identity leaked into bound span: %+v", spans[0])
	}
}
