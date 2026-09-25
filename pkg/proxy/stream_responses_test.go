package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/config"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/proxy"
	"github.com/chiatzenw-cur/descles/pkg/storage"
	"log/slog"
)

func respEvent(evt string, payload map[string]any) string {
	b, _ := json.Marshal(payload)
	return "event: " + evt + "\ndata: " + string(b) + "\n\n"
}

func funcCallAdded(idx int, id, name string) string {
	return respEvent("response.output_item.added", map[string]any{
		"type": "response.output_item.added", "output_index": idx,
		"item": map[string]any{"id": id, "type": "function_call", "status": "in_progress", "name": name, "arguments": ""},
	})
}

func funcCallDone(idx int, id, name, args string) string {
	return respEvent("response.output_item.done", map[string]any{
		"type": "response.output_item.done", "output_index": idx,
		"item": map[string]any{"id": id, "type": "function_call", "status": "completed", "name": name, "call_id": id, "arguments": args},
	})
}

func argsDelta(id, partial string) string {
	return respEvent("response.function_call_arguments.delta", map[string]any{
		"type": "response.function_call_arguments.delta", "item_id": id, "output_index": 0, "delta": partial,
	})
}

func argsDone(id, full string) string {
	return respEvent("response.function_call_arguments.done", map[string]any{
		"type": "response.function_call_arguments.done", "item_id": id, "output_index": 0, "arguments": full,
	})
}

func respCompleted() string {
	return respEvent("response.completed", map[string]any{"type": "response.completed", "response": map[string]any{"id": "resp_1", "usage": map[string]any{"input_tokens": 3, "output_tokens": 7}}})
}

func responsesStream(body string, pol *policy.Holder) (string, int) {
	store := storage.NewMemory()
	cfg := config.Config{Storage: "memory", LogLevel: "error", DenyEnforce: true}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, body)
	}))
	defer up.Close()
	reg := provider.NewRegistry([]provider.Config{{Name: "deepseek", BaseURL: up.URL, Models: []string{"*"}}})
	h := proxy.New(cfg, reg, pol, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.ApprovalSuspender = func(agentID, tool string, args map[string]any) (string, error) {
		return "appr-77", nil
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/responses",
		strings.NewReader(`{"model":"deepseek-chat","stream":true,"input":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	return rr.Body.String(), rr.Code
}

func TestResponsesStreamingDenyDropsCallAndInjectsNote(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	sse := funcCallAdded(0, "fc_bad", "shell.rm") + argsDelta("fc_bad", `{"path":`) + argsDelta("fc_bad", `"/etc"}`) +
		argsDone("fc_bad", `{"path":"/etc"}`) + funcCallDone(0, "fc_bad", "shell.rm", `{"path":"/etc"}`) + respCompleted()

	out, code := responsesStream(sse, policy.NewHolder(pol))
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	if strings.Contains(out, "fc_bad") {
		t.Errorf("denied function_call leaked:\n%s", out)
	}
	if !strings.Contains(out, "[blocked by Descles policy: shell.rm]") {
		t.Errorf("missing deny note:\n%s", out)
	}
	// The note must be a message item at the same output_index.
	if !strings.Contains(out, `"type":"message"`) || !strings.Contains(out, `"output_index":0`) {
		t.Errorf("note should be a message item at output_index 0:\n%s", out)
	}
}

func TestResponsesStreamingSuspendBuffersUntilArgsThenParks(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"require_approval":["kubectl.delete"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	sse := funcCallAdded(0, "fc_k", "kubectl.delete") +
		argsDelta("fc_k", `{"pod":"`) + argsDelta("fc_k", `prod"}`) +
		argsDone("fc_k", `{"pod":"prod"}`) +
		funcCallDone(0, "fc_k", "kubectl.delete", `{"pod":"prod"}`) + respCompleted()

	out, _ := responsesStream(sse, policy.NewHolder(pol))
	if strings.Contains(out, "fc_k") {
		t.Errorf("parked function_call leaked:\n%s", out)
	}
	if !strings.Contains(out, "[pending human approval: kubectl.delete (approval appr-77)]") {
		t.Errorf("missing approval note:\n%s", out)
	}
	if strings.Contains(out, "kubectl.delete\",\"arguments\"") {
		t.Errorf("function_call arguments should not surface for parked call:\n%s", out)
	}
}

func TestResponsesStreamingAllowRelaysVerbatim(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	sse := funcCallAdded(0, "fc_ok", "get_weather") +
		argsDelta("fc_ok", `{"city":"Tor`) + argsDelta("fc_ok", `onto"}`) +
		argsDone("fc_ok", `{"city":"Toronto"}`) +
		funcCallDone(0, "fc_ok", "get_weather", `{"city":"Toronto"}`) + respCompleted()

	out, _ := responsesStream(sse, policy.NewHolder(pol))
	if !strings.Contains(out, "fc_ok") || !strings.Contains(out, "get_weather") {
		t.Errorf("allowed call should relay verbatim:\n%s", out)
	}
	if strings.Contains(out, "blocked by Descles") {
		t.Errorf("no note expected for allowed call:\n%s", out)
	}
}
