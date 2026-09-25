package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/config"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/storage"
)

type observedRequest struct {
	provider, method, path, auth, organization, project, idempotency, body string
}

func TestConcurrentBYOKRequestsDoNotCrossCredentials(t *testing.T) {
	var mismatches atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RequestID int `json:"request_id"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || r.Header.Get("Authorization") != fmt.Sprintf("Bearer sk-customer-%d", body.RequestID) {
			mismatches.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"ok","model":"gpt-test","choices":[],"usage":{}}`)
	}))
	defer upstream.Close()
	h := New(config.Config{}, provider.NewRegistry([]provider.Config{{BaseURL: upstream.URL, APIKey: "pooled", Models: []string{"gpt-*"}}}), policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	var wg sync.WaitGroup
	for requestID := range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := fmt.Sprintf(`{"model":"gpt-test","request_id":%d}`, requestID)
			r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
			r.Header.Set("X-Descles-Provider-Key", fmt.Sprintf("sk-customer-%d", requestID))
			w := httptest.NewRecorder()
			h.Routes().ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				mismatches.Add(1)
			}
		}()
	}
	wg.Wait()
	if mismatches.Load() != 0 {
		t.Fatalf("credential/request mismatches=%d", mismatches.Load())
	}
}

func TestOpenAIEndpointAndModelRoutingAcceptance(t *testing.T) {
	var mu sync.Mutex
	var observed []observedRequest
	newUpstream := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			observed = append(observed, observedRequest{name, r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("OpenAI-Organization"), r.Header.Get("OpenAI-Project"), r.Header.Get("Idempotency-Key"), string(body)})
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/models":
				_, _ = io.WriteString(w, `{"object":"list","data":[]}`)
			case "/responses":
				_, _ = io.WriteString(w, `{"id":"resp_1","object":"response","model":"gpt-test","output":[],"usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5}}`)
			default:
				_, _ = io.WriteString(w, `{"id":"chat_1","model":"deepseek-chat","choices":[],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}}`)
			}
		}))
	}
	deepseek := newUpstream("deepseek")
	defer deepseek.Close()
	openai := newUpstream("openai")
	defer openai.Close()

	h := New(config.Config{}, provider.NewRegistry([]provider.Config{
		{Name: "deepseek", BaseURL: deepseek.URL, APIKey: "pooled-deepseek", Models: []string{"deepseek-*"}},
		{Name: "openai", BaseURL: openai.URL, APIKey: "pooled-openai", Models: []string{"gpt-*"}},
	}), policy.NewHolder(policy.AllowAll()), storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	call := func(method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		for name, value := range headers {
			r.Header.Set(name, value)
		}
		w := httptest.NewRecorder()
		h.Routes().ServeHTTP(w, r)
		return w
	}
	common := map[string]string{
		"X-Descles-Provider-Key": "sk-customer",
		"OpenAI-Organization":    "org_customer",
		"OpenAI-Project":         "proj_customer",
		"Idempotency-Key":        "idem-123",
	}
	if got := call(http.MethodPost, "/v1/chat/completions", `{"model":"deepseek-chat","messages":[]}`, common); got.Code != http.StatusOK {
		t.Fatalf("chat status=%d body=%s", got.Code, got.Body.String())
	}
	if got := call(http.MethodPost, "/v1/responses", `{"model":"gpt-test","input":"hi"}`, common); got.Code != http.StatusOK {
		t.Fatalf("responses status=%d body=%s", got.Code, got.Body.String())
	}
	modelsHeaders := map[string]string{"X-Descles-Provider-Key": "sk-customer", "X-Descles-Provider": "openai", "OpenAI-Organization": "org_customer", "OpenAI-Project": "proj_customer"}
	if got := call(http.MethodGet, "/v1/models", "", modelsHeaders); got.Code != http.StatusOK {
		t.Fatalf("models status=%d body=%s", got.Code, got.Body.String())
	}
	beforeInvalid := len(observed)
	if got := call(http.MethodPost, "/v1/chat/completions", `{"model":"claude-unknown","messages":[]}`, common); got.Code != http.StatusBadRequest {
		t.Fatalf("unknown model status=%d body=%s", got.Code, got.Body.String())
	}
	if len(observed) != beforeInvalid {
		t.Fatal("unknown model reached an upstream")
	}
	if got := call(http.MethodPost, "/v1/models", `{}`, common); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /models status=%d", got.Code)
	}

	if len(observed) != 3 {
		t.Fatalf("observed %d upstream calls: %+v", len(observed), observed)
	}
	if first := observed[0]; first.provider != "deepseek" || first.path != "/chat/completions" || first.auth != "Bearer sk-customer" || first.organization != "org_customer" || first.project != "proj_customer" || first.idempotency != "idem-123" || !strings.Contains(first.body, `"deepseek-chat"`) {
		t.Fatalf("chat forwarding mismatch: %+v", first)
	}
	if second := observed[1]; second.provider != "openai" || second.path != "/responses" || second.auth != "Bearer sk-customer" {
		t.Fatalf("responses forwarding mismatch: %+v", second)
	}
	if third := observed[2]; third.provider != "openai" || third.method != http.MethodGet || third.path != "/models" || third.auth != "Bearer sk-customer" {
		t.Fatalf("models forwarding mismatch: %+v", third)
	}
}
