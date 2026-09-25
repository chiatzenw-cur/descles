package translate

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAnthropicToOpenAIRequest(t *testing.T) {
	body := []byte(`{
	  "model": "claude-sonnet-4-5-20250929",
	  "max_tokens": 512,
	  "temperature": 0.3,
	  "stop_sequences": ["</done>"],
	  "thinking": {"type": "enabled", "budget_tokens": 4000},
	  "stream": true,
	  "system": [{"type":"text","text":"You are terse."},{"type":"text","text":"Answer in one word."}],
	  "tools": [{"name":"Bash","description":"run","input_schema":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}}],
	  "tool_choice": {"type": "any"},
	  "messages": [
	    {"role":"user","content":"list files"},
	    {"role":"assistant","content":[
	      {"type":"text","text":"running"},
	      {"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"ls"}}
	    ]},
	    {"role":"user","content":[
	      {"type":"tool_result","tool_use_id":"toolu_1","content":"a.txt\nb.txt"}
	    ]}
	  ]
	}`)

	tr, err := AnthropicToOpenAI(body, "deepseek-chat")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if !tr.Stream || tr.MappedModel != "deepseek-chat" || tr.RequestedName != "claude-sonnet-4-5-20250929" {
		t.Fatalf("metadata wrong: %+v", tr)
	}

	var out map[string]any
	if err := json.Unmarshal(tr.Body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Anthropic-only fields must not leak upstream: several OpenAI-compatible
	// servers reject unknown keys outright.
	for _, banned := range []string{"thinking", "top_k", "anthropic_version"} {
		if _, present := out[banned]; present {
			t.Fatalf("leaked %q into the upstream request", banned)
		}
	}
	if out["model"] != "deepseek-chat" || out["stream"] != true {
		t.Fatalf("model/stream wrong: %v %v", out["model"], out["stream"])
	}
	if out["stop"] == nil {
		t.Fatalf("stop_sequences not mapped to stop")
	}
	if so, ok := out["stream_options"].(map[string]any); !ok || so["include_usage"] != true {
		t.Fatalf("stream_options.include_usage missing: %v", out["stream_options"])
	}
	tc, _ := json.Marshal(out["tool_choice"])
	if string(tc) != `"required"` {
		t.Fatalf("tool_choice any -> %s, want \"required\"", tc)
	}

	msgs := out["messages"].([]any)
	if len(msgs) != 4 {
		t.Fatalf("want 4 messages (system, user, assistant, tool), got %d: %v", len(msgs), msgs)
	}
	sys := msgs[0].(map[string]any)
	if sys["role"] != "system" || !strings.Contains(sys["content"].(string), "Answer in one word.") {
		t.Fatalf("system not flattened: %v", sys)
	}
	asst := msgs[2].(map[string]any)
	calls, ok := asst["tool_calls"].([]any)
	if !ok || len(calls) != 1 {
		t.Fatalf("assistant tool_calls missing: %v", asst)
	}
	fn := calls[0].(map[string]any)["function"].(map[string]any)
	if fn["name"] != "Bash" || !strings.Contains(fn["arguments"].(string), `"ls"`) {
		t.Fatalf("tool call wrong: %v", fn)
	}
	toolMsg := msgs[3].(map[string]any)
	if toolMsg["role"] != "tool" || toolMsg["tool_call_id"] != "toolu_1" {
		t.Fatalf("tool result wrong: %v", toolMsg)
	}

	tools := out["tools"].([]any)
	fn0 := tools[0].(map[string]any)["function"].(map[string]any)
	if fn0["name"] != "Bash" || fn0["parameters"] == nil {
		t.Fatalf("tools not mapped: %v", fn0)
	}
}

func TestAnthropicToOpenAIImageAndStringContent(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":8,"messages":[
	  {"role":"user","content":[{"type":"text","text":"what is this"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAA"}}]}
	]}`)
	tr, err := AnthropicToOpenAI(body, "deepseek-flash")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var out struct {
		Messages []struct {
			Content []struct {
				Type     string `json:"type"`
				ImageURL struct {
					URL string `json:"url"`
				} `json:"image_url"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(tr.Body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Messages) != 1 || len(out.Messages[0].Content) != 2 {
		t.Fatalf("content blocks wrong: %+v", out.Messages)
	}
	if got := out.Messages[0].Content[1].ImageURL.URL; got != "data:image/png;base64,AAA" {
		t.Fatalf("image url = %q", got)
	}
}

func TestOpenAIToAnthropicResponse(t *testing.T) {
	body := []byte(`{
	  "id":"chatcmpl-9","model":"deepseek-chat",
	  "choices":[{"index":0,"finish_reason":"tool_calls","message":{
	    "content":"let me check","reasoning_content":"hmm",
	    "tool_calls":[{"id":"call_7","type":"function","function":{"name":"Bash","arguments":"{\"command\":\"ls\"}"}}]
	  }}],
	  "usage":{"prompt_tokens":120,"completion_tokens":9,"prompt_tokens_details":{"cached_tokens":64}}
	}`)
	out, err := OpenAIToAnthropic(body, "claude-sonnet-4-5-20250929")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	var got struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Role    string `json:"role"`
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			Think string          `json:"thinking"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			Input  int `json:"input_tokens"`
			Output int `json:"output_tokens"`
			Cached int `json:"cache_read_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != "msg_chatcmpl-9" {
		t.Fatalf("id = %q, want msg_ prefix", got.ID)
	}
	if got.Model != "claude-sonnet-4-5-20250929" {
		t.Fatalf("model = %q, want the requested alias echoed", got.Model)
	}
	if got.StopReason != "tool_use" {
		t.Fatalf("stop_reason = %q", got.StopReason)
	}
	if len(got.Content) != 3 || got.Content[0].Type != "thinking" || got.Content[1].Type != "text" || got.Content[2].Type != "tool_use" {
		t.Fatalf("content blocks wrong: %+v", got.Content)
	}
	if got.Content[2].ID != "toolu_call_7" || got.Content[2].Name != "Bash" {
		t.Fatalf("tool block wrong: %+v", got.Content[2])
	}
	if string(got.Content[2].Input) != `{"command":"ls"}` {
		t.Fatalf("tool input not parsed into an object: %s", got.Content[2].Input)
	}
	// 120 prompt tokens include 64 cached ones: input must be the fresh 56, so a
	// client that adds input + cache_read (Claude Code does) sees 120, not 184.
	if got.Usage.Input != 56 || got.Usage.Output != 9 || got.Usage.Cached != 64 {
		t.Fatalf("usage wrong: %+v", got.Usage)
	}
	if got.Usage.Input+got.Usage.Cached != 120 {
		t.Fatalf("input + cache_read must equal the upstream prompt tokens: %+v", got.Usage)
	}
}

func TestStopReasonMapping(t *testing.T) {
	cases := map[string]string{
		"stop":           "end_turn",
		"length":         "max_tokens",
		"tool_calls":     "tool_use",
		"content_filter": "refusal",
	}
	for in, want := range cases {
		if got := stopReason(in, false); got != want {
			t.Fatalf("stopReason(%q) = %q, want %q", in, got, want)
		}
	}
	if got := stopReason("", true); got != "tool_use" {
		t.Fatalf("tools present but empty finish_reason -> %q", got)
	}
}

type testFrame struct {
	Event string
	Data  map[string]any
}

func flatten(frames []testFrame) string {
	var sb strings.Builder
	for _, f := range frames {
		sb.WriteString("event: " + f.Event + "\n")
	}
	return sb.String()
}

func TestStreamTranslatorTextAndToolCall(t *testing.T) {
	tr := NewStreamTranslator("claude-opus-5")
	var got []testFrame
	collect := func(raw [][]byte) {
		for _, f := range raw {
			text := string(f)
			lines := strings.Split(strings.TrimSpace(text), "\n")
			if len(lines) != 2 || !strings.HasPrefix(lines[0], "event: ") || !strings.HasPrefix(lines[1], "data: ") {
				t.Fatalf("malformed SSE frame: %q", text)
			}
			var data map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[1], "data: ")), &data); err != nil {
				t.Fatalf("frame data not JSON: %q", lines[1])
			}
			got = append(got, testFrame{Event: strings.TrimPrefix(lines[0], "event: "), Data: data})
		}
	}
	feed := func(payload string) { collect(tr.Feed([]byte(payload))) }
	feed(`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"reasoning_content":"thinking..."},"finish_reason":null}]}`)
	feed(`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"Hel"},"finish_reason":null}]}`)
	feed(`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":null}]}`)
	// Arguments arrive fragmented across chunks, as real providers send them.
	feed(`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"Bash","arguments":"{\"comm"}}]},"finish_reason":null}]}`)
	feed(`{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"and\":\"ls\"}"}}]},"finish_reason":"tool_calls"}]}`)
	feed(`{"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":42,"completion_tokens":7}}`)
	feed(`[DONE]`)
	collect(tr.Finish())
	collect(tr.Finish()) // [DONE] then EOF must not repeat the ending

	if got[0].Event != "message_start" {
		t.Fatalf("first frame = %s, want message_start", got[0].Event)
	}
	if got[len(got)-1].Event != "message_stop" {
		t.Fatalf("last frame = %s, want message_stop", got[len(got)-1].Event)
	}
	for _, f := range got {
		if f.Event == "message_start" || f.Event == "message_stop" {
			if n := strings.Count(flatten(got), "event: "+f.Event); n != 1 {
				t.Fatalf("%s emitted %d times", f.Event, n)
			}
		}
	}
	msg := got[0].Data["message"].(map[string]any)
	if msg["model"] != "claude-opus-5" || msg["role"] != "assistant" {
		t.Fatalf("message_start wrong: %v", msg)
	}

	// Block layout: thinking (0), text (1), tool_use (2), each opened then closed.
	var blocks []struct {
		kind string
		idx  float64
	}
	deltaText := map[float64][]string{}
	var partialJSON string
	for _, f := range got {
		switch f.Event {
		case "content_block_start":
			cb := f.Data["content_block"].(map[string]any)
			blocks = append(blocks, struct {
				kind string
				idx  float64
			}{cb["type"].(string), f.Data["index"].(float64)})
			if cb["type"] == "tool_use" {
				if cb["id"] != "toolu_call_1" || cb["name"] != "Bash" {
					t.Fatalf("tool block wrong: %v", cb)
				}
				if _, ok := cb["input"].(map[string]any); !ok {
					t.Fatalf("tool_use input must be an object: %v", cb["input"])
				}
			}
		case "content_block_delta":
			d := f.Data["delta"].(map[string]any)
			switch d["type"] {
			case "text_delta":
				deltaText[f.Data["index"].(float64)] = append(deltaText[f.Data["index"].(float64)], d["text"].(string))
			case "thinking_delta":
				if d["thinking"] != "thinking..." {
					t.Fatalf("thinking delta = %v", d)
				}
			case "input_json_delta":
				partialJSON = d["partial_json"].(string)
			}
		}
	}
	if len(blocks) != 3 || blocks[0].kind != "thinking" || blocks[1].kind != "text" || blocks[2].kind != "tool_use" {
		t.Fatalf("block layout = %+v", blocks)
	}
	if got := deltaText[blocks[1].idx]; strings.Join(got, "") != "Hello" {
		t.Fatalf("text deltas = %v", got)
	}
	if partialJSON != `{"command":"ls"}` {
		t.Fatalf("buffered tool arguments = %q", partialJSON)
	}
	if opens, closes := strings.Count(flatten(got), "event: content_block_start"), strings.Count(flatten(got), "event: content_block_stop"); opens != closes {
		t.Fatalf("unbalanced blocks: %d starts, %d stops", opens, closes)
	}
	// The ending must carry the upstream's real token counts, not a guess.
	last := got[len(got)-2]
	if last.Event != "message_delta" {
		t.Fatalf("penultimate frame = %s", last.Event)
	}
	if dr := last.Data["delta"].(map[string]any)["stop_reason"]; dr != "tool_use" {
		t.Fatalf("stop_reason = %v", dr)
	}
	usage := last.Data["usage"].(map[string]any)
	if usage["output_tokens"].(float64) != 7 || usage["input_tokens"].(float64) != 42 {
		t.Fatalf("usage = %v", usage)
	}
	if in, out, _ := tr.Usage(); in != 42 || out != 7 {
		t.Fatalf("Usage() = %d/%d", in, out)
	}
	if names := tr.ToolNames(); len(names) != 1 || names[0] != "Bash" {
		t.Fatalf("tool names = %v", names)
	}
}

func TestStreamTranslatorEmptyStreamStillWellFormed(t *testing.T) {
	tr := NewStreamTranslator("alias")
	frames := tr.Finish()
	all := ""
	for _, f := range frames {
		all += string(f)
	}
	if !strings.Contains(all, "event: message_start") || !strings.Contains(all, "event: message_stop") {
		t.Fatalf("empty stream not wrapped in a valid envelope: %s", all)
	}
	if !strings.Contains(all, `"stop_reason":"end_turn"`) {
		t.Fatalf("missing stop_reason: %s", all)
	}
}

func TestAnthropicErrorFromUpstreamPreservesStatusAndType(t *testing.T) {
	body := []byte(`{"error":{"message":"model not found","type":"invalid_request_error"}}`)
	out := AnthropicErrorFromUpstream(404, body)
	var got struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Type != "error" || got.Error.Type != "not_found_error" || got.Error.Message != "model not found" {
		t.Fatalf("mapped error wrong: %+v", got)
	}
}
