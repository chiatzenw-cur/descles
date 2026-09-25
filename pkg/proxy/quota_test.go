package proxy

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
	"github.com/chiatzenw-cur/descles/pkg/storage"
)

func TestLimitedKeyQuotaGate(t *testing.T) {
	h := &Handler{}
	h.KeyResolver = func(key string) (string, string, string, bool) {
		return "org", "", "agent", key == "dsk_test_valid"
	}
	remaining := int64(1)
	h.QuotaGate = func(key string) (int64, bool, bool) {
		if remaining == 0 {
			return 0, true, false
		}
		remaining--
		return remaining, true, true
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	guarded := h.requireDataToken(next)

	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		r.Header.Set("Authorization", "Bearer dsk_test_valid")
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, r)
		return w
	}
	first := request()
	if first.Code != http.StatusNoContent || first.Header().Get("X-Descles-Requests-Remaining") != "0" {
		t.Fatal(first.Code, first.Header())
	}
	second := request()
	if second.Code != http.StatusTooManyRequests {
		t.Fatal(second.Code, second.Body.String())
	}
}

func TestBYOKCredentialReplacesPooledKeyAndIsNotForwardedAsMetadata(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sk-customer" {
			t.Errorf("upstream authorization = %q", got)
		}
		if got := r.Header.Get("X-Descles-Provider-Key"); got != "" {
			t.Errorf("private middleware header leaked upstream: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"x","model":"customer-model","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	defer upstream.Close()

	h := New(config.Config{}, provider.NewRegistry([]provider.Config{{BaseURL: upstream.URL, APIKey: "sk-pooled"}}), policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.KeyResolver = func(key string) (string, string, string, bool) { return "org", "", "agent", key == "dsk_test_valid" }
	h.KeyPolicy = func(string) (int64, bool, bool) { return 4096, true, true }
	h.QuotaGate = func(string) (int64, bool, bool) { return 999, true, true }

	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"customer-model","messages":[]}`))
	r.Header.Set("Authorization", "Bearer dsk_test_valid")
	r.Header.Set("X-Descles-Provider-Key", "sk-customer")
	w := httptest.NewRecorder()
	h.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestLimitedKeyPolicyRequiresBYOKBeforeChargingQuota(t *testing.T) {
	h := &Handler{Registry: provider.NewRegistry([]provider.Config{{BaseURL: "https://provider.example/v1", Models: []string{"customer-model"}}})}
	h.KeyResolver = func(key string) (string, string, string, bool) {
		return "org", "", "agent", key == "dsk_test_valid"
	}
	h.KeyPolicy = func(string) (int64, bool, bool) {
		return 4096, true, true
	}
	quotaCalls := 0
	h.QuotaGate = func(string) (int64, bool, bool) {
		quotaCalls++
		return 999, true, true
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if got := body["max_tokens"]; got != float64(9999) {
			t.Fatalf("max_tokens changed to %v; BYOK middleware must forward it unchanged", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	guarded := h.requireDataToken(next)

	request := func(withProviderKey bool, model string) *httptest.ResponseRecorder {
		body := `{"model":"` + model + `","max_tokens":9999}`
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer dsk_test_valid")
		if withProviderKey {
			r.Header.Set("X-Descles-Provider-Key", "sk-customer")
		}
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, r)
		return w
	}
	if denied := request(false, "customer-model"); denied.Code != http.StatusBadRequest || quotaCalls != 0 {
		t.Fatalf("denied status=%d quota calls=%d", denied.Code, quotaCalls)
	}
	h.OrgUpstream = func(orgID, _ string) (string, string, bool) {
		return "https://provider.example/v1", "sk-hosted", orgID == "org"
	}
	if allowed := request(false, "customer-model"); allowed.Code != http.StatusNoContent || quotaCalls != 1 {
		t.Fatalf("hosted BYOK status=%d quota calls=%d", allowed.Code, quotaCalls)
	}
	h.OrgUpstream = nil
	quotaCalls = 0
	if denied := request(true, "unknown-model"); denied.Code != http.StatusBadRequest || quotaCalls != 0 {
		t.Fatalf("unknown model status=%d quota calls=%d", denied.Code, quotaCalls)
	}
	if allowed := request(true, "customer-model"); allowed.Code != http.StatusNoContent || quotaCalls != 1 {
		t.Fatalf("allowed status=%d quota calls=%d body=%s", allowed.Code, quotaCalls, allowed.Body.String())
	}
}
