package proxy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/policy"
)

// verifySSEFormat parses an OpenAI-style SSE body the way an eventsource
// client does: events are separated by blank lines, each event's data lines
// must be independently valid JSON (a single chunk per event).
func verifySSEFormat(t *testing.T, body string, label string) {
	t.Helper()
	events := strings.Split(body, "\n\n")
	if len(events) < 2 {
		t.Fatalf("%s: expected blank-line-separated events, got %q", label, body)
	}
	for i, ev := range events {
		ev = strings.TrimSpace(ev)
		if ev == "" {
			continue
		}
		lines := strings.Split(ev, "\n")
		var dataLines []string
		for _, ln := range lines {
			if strings.HasPrefix(ln, "data:") {
				dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(ln, "data:")))
			}
		}
		if len(dataLines) != 1 {
			t.Errorf("%s event %d: expected exactly ONE data line per event (eventsource would merge multiple), got %d: %q",
				label, i, len(dataLines), ev)
			continue
		}
		payload := dataLines[0]
		if payload == "[DONE]" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(payload), &m); err != nil {
			t.Errorf("%s event %d: data is not valid JSON: %v (payload %q)", label, i, err, payload)
		}
	}
}

// TestOpenAIDenyStreamIsConformantSSE drives the real filter (deny outcome)
// and asserts every chunk is a separate, valid, blank-line-terminated event.
func TestOpenAIDenyStreamIsConformantSSE(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	sse := "data: " + `{"id":"x","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}` + "\n\n" +
		"data: " + `{"id":"x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"shell.rm","arguments":"{}"}}]},"finish_reason":null}]}` + "\n\n" +
		"data: " + `{"id":"x","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n" +
		"data: [DONE]\n\n"
	out, _ := relayFilter(t, sse, policy.NewHolder(pol))
	verifySSEFormat(t, out, "openai-deny")
	if !strings.Contains(out, "blocked by Descles policy") {
		t.Errorf("deny note missing:\n%s", out)
	}
}

// TestOpenAIPartialAllowStreamIsConformantSSE exercises the replay path
// (compact + finish tool_calls), the riskiest for multi-data-line events.
func TestOpenAIPartialAllowStreamIsConformantSSE(t *testing.T) {
	pol, err := policy.FromJSON(`{"defaults":{"tools":{"shell.rm":"deny"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	sse := "data: " + `{"id":"x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"bad","type":"function","function":{"name":"shell.rm","arguments":"{}"}}]},"finish_reason":null}]}` + "\n\n" +
		"data: " + `{"id":"x","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"ok","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Toronto\"}"}}]},"finish_reason":null}]}` + "\n\n" +
		"data: " + `{"id":"x","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n" +
		"data: [DONE]\n\n"
	out, _ := relayFilter(t, sse, policy.NewHolder(pol))
	verifySSEFormat(t, out, "openai-partial-allow")
	if !strings.Contains(out, `"id":"ok"`) || !strings.Contains(out, "get_weather") {
		t.Errorf("allowed call missing:\n%s", out)
	}
}
