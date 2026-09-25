package provider

import (
	"bytes"
	"testing"
)

func TestParseChatCompletion(t *testing.T) {
	body := `{
	  "id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o",
	  "choices":[{
	    "index":0,"message":{"role":"assistant","content":"hi",
	      "tool_calls":[
	        {"id":"a","type":"function","function":{"name":"github.create_pr","arguments":"{}"}},
	        {"id":"b","type":"function","function":{"name":"shell","arguments":"{}"}}
	      ]},"finish_reason":"tool_calls"
	  }],
	  "usage":{"prompt_tokens":1200,"completion_tokens":300,"total_tokens":1500,
	    "prompt_tokens_details":{"cached_tokens":400}}
	}`
	res, err := ParseChatCompletion([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Model != "gpt-4o" {
		t.Errorf("model = %q", res.Model)
	}
	// prompt_tokens (1200) includes the cached subset (400), so fresh input is
	// 800: billing input + cached separately must not charge the prefix twice.
	if res.Usage.InputTokens != 800 || res.Usage.OutputTokens != 300 || res.Usage.CachedTokens != 400 {
		t.Errorf("usage = %+v", res.Usage)
	}
	// The vendor's total is preserved, so token-budget sums are unchanged.
	if res.Usage.InputTokens+res.Usage.CachedTokens != 1200 {
		t.Errorf("input + cached must equal the reported prompt tokens: %+v", res.Usage)
	}
	if res.ToolCallCount != 2 {
		t.Errorf("tool calls = %d, want 2", res.ToolCallCount)
	}
}

func TestParseResponses(t *testing.T) {
	body := `{
	  "id":"resp_1","object":"response","model":"gpt-4o",
	  "usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5,
	    "input_tokens_details":{"cached_tokens":1}},
	  "output":[{"type":"function_call","name":"foo"}]
	}`
	res, err := ParseResponses([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Usage.InputTokens != 1 || res.Usage.OutputTokens != 3 || res.Usage.CachedTokens != 1 {
		t.Errorf("usage = %+v", res.Usage)
	}
	if res.ToolCallCount != 1 {
		t.Errorf("tool calls = %d, want 1", res.ToolCallCount)
	}
}

func TestRelayStreamCapturesUsageAndToolCallIndexes(t *testing.T) {
	var src bytes.Buffer
	// Note the SSE "data:" prefix + a trailing blank line per event.
	src.WriteString("data: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"he\"}}]}\n\n")
	src.WriteString("data: {\"id\":\"x\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"type\":\"function\",\"function\":{\"name\":\"shell\",\"arguments\":\"{}\"}}]}}]}\n\n")
	src.WriteString("data: {\"id\":\"x\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n")
	src.WriteString("data: [DONE]\n\n")

	var dst bytes.Buffer
	res, err := RelayStream(&dst, &src, nil)
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	if !res.Done {
		t.Error("expected Done")
	}
	if res.Usage.InputTokens != 10 || res.Usage.OutputTokens != 5 {
		t.Errorf("usage = %+v", res.Usage)
	}
	if res.ToolCallCount != 1 {
		t.Errorf("tool calls = %d, want 1", res.ToolCallCount)
	}
	if !bytes.Contains(dst.Bytes(), []byte("[DONE]")) {
		t.Errorf("relayed stream missing [DONE]: %q", dst.String())
	}
}

func TestProviderName(t *testing.T) {
	cases := map[string]string{
		"https://api.openai.com/v1":                                "openai",
		"https://api.deepseek.com/v1":                              "deepseek",
		"https://openrouter.ai/api/v1":                             "openrouter",
		"https://api.anthropic.com/v1":                             "anthropic",
		"https://generativelanguage.googleapis.com/v1beta/openai/": "gemini",
		"https://example.com/v1":                                   "example.com",
	}
	for in, want := range cases {
		if got := ProviderName(in); got != want {
			t.Errorf("ProviderName(%q) = %q, want %q", in, got, want)
		}
	}
}
