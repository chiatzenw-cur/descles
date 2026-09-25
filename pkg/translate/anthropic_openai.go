// Package translate converts between the Anthropic Messages wire format and the
// OpenAI chat/completions wire format so a client speaking one can reach an
// upstream speaking the other. It is pure: no HTTP, no config, no global state —
// callers hand it bytes and get bytes back, which keeps the mapping testable
// against recorded payloads.
//
// Direction implemented here: Anthropic request → OpenAI request, and
// OpenAI response/stream → Anthropic response/stream. That is the direction a
// Claude Code user pointed at an OpenAI-wire provider needs.
package translate

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ---------- Anthropic request → OpenAI request ----------

// anthropicRequest is the subset of the Messages API this gateway translates.
type anthropicRequest struct {
	Model         string             `json:"model"`
	System        json.RawMessage    `json:"system"`
	Messages      []anthropicMessage `json:"messages"`
	MaxTokens     int                `json:"max_tokens"`
	Temperature   *float64           `json:"temperature"`
	TopP          *float64           `json:"top_p"`
	TopK          *int               `json:"top_k"`
	StopSequences []string           `json:"stop_sequences"`
	Stream        bool               `json:"stream"`
	Tools         []anthropicTool    `json:"tools"`
	ToolChoice    json.RawMessage    `json:"tool_choice"`
	Metadata      json.RawMessage    `json:"metadata"`
	// Thinking / container / mcp_servers / anthropic-beta have no OpenAI
	// equivalent and are dropped rather than forwarded as junk fields: unknown
	// keys make some OpenAI-compatible servers reject the whole request.
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"` // string or []block
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	// text
	Text string `json:"text"`
	// image
	Source *struct {
		Type      string `json:"type"` // base64 | url
		MediaType string `json:"media_type"`
		Data      string `json:"data"`
		URL       string `json:"url"`
	} `json:"source"`
	// tool_use
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
	// tool_result
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// OpenAI request shapes (only what we emit).
type openAIMessage struct {
	Role       string           `json:"role"`
	Content    any              `json:"content,omitempty"`
	ToolCalls  []openAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
	Name       string           `json:"name,omitempty"`
}

type openAIToolCall struct {
	ID       string             `json:"id"`
	Type     string             `json:"type"`
	Function openAIFunctionCall `json:"function"`
}

type openAIFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// TranslatedRequest carries the OpenAI body plus what accounting needs to know.
type TranslatedRequest struct {
	Body          []byte
	Stream        bool
	RequestedName string // the model name the client asked for (echoed back to it)
	MappedModel   string // the model name actually sent upstream
	StreamOptions bool   // whether include_usage was requested
}

// AnthropicToOpenAI converts a Messages request body into a chat/completions
// body. model is the upstream model name already resolved by the caller (alias
// mapping is a routing concern, not a wire concern).
func AnthropicToOpenAI(body []byte, model string) (*TranslatedRequest, error) {
	var in anthropicRequest
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, fmt.Errorf("parse anthropic request: %w", err)
	}
	if model == "" {
		model = in.Model
	}

	out := map[string]any{
		"model":  model,
		"stream": in.Stream,
	}
	if in.MaxTokens > 0 {
		out["max_tokens"] = in.MaxTokens
	}
	if in.Temperature != nil {
		out["temperature"] = *in.Temperature
	}
	if in.TopP != nil {
		out["top_p"] = *in.TopP
	}
	if len(in.StopSequences) > 0 {
		out["stop"] = in.StopSequences
	}
	if in.Stream {
		// Without this OpenAI-compatible servers omit usage entirely on streamed
		// responses, and every translated call would be accounted as zero tokens.
		out["stream_options"] = map[string]any{"include_usage": true}
	}

	msgs := make([]openAIMessage, 0, len(in.Messages)+1)
	system, err := flattenSystem(in.System)
	if err != nil {
		return nil, err
	}
	if system != "" {
		msgs = append(msgs, openAIMessage{Role: "system", Content: system})
	}
	for _, m := range in.Messages {
		converted, err := convertAnthropicMessage(m)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, converted...)
	}
	out["messages"] = msgs

	if len(in.Tools) > 0 {
		tools := make([]map[string]any, 0, len(in.Tools))
		for _, t := range in.Tools {
			params := t.InputSchema
			if len(params) == 0 {
				params = json.RawMessage(`{"type":"object"}`)
			}
			tools = append(tools, map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        t.Name,
					"description": t.Description,
					"parameters":  params,
				},
			})
		}
		out["tools"] = tools
		if tc, ok := convertToolChoice(in.ToolChoice); ok {
			out["tool_choice"] = tc
		}
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("encode openai request: %w", err)
	}
	return &TranslatedRequest{
		Body:          encoded,
		Stream:        in.Stream,
		RequestedName: in.Model,
		MappedModel:   model,
		StreamOptions: in.Stream,
	}, nil
}

func flattenSystem(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var blocks []anthropicContentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return "", fmt.Errorf("parse system: %w", err)
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n\n"), nil
}

func convertAnthropicMessage(m anthropicMessage) ([]openAIMessage, error) {
	var text string
	if err := json.Unmarshal(m.Content, &text); err == nil {
		if m.Role == "assistant" {
			return []openAIMessage{{Role: "assistant", Content: text}}, nil
		}
		return []openAIMessage{{Role: m.Role, Content: text}}, nil
	}
	var blocks []anthropicContentBlock
	if err := json.Unmarshal(m.Content, &blocks); err != nil {
		return nil, fmt.Errorf("parse message content: %w", err)
	}

	// One Anthropic message can carry both text and tool traffic; OpenAI splits
	// those across an assistant message (tool_calls) and one tool message per
	// result, in that order.
	assistant := openAIMessage{Role: "assistant"}
	var parts []map[string]any
	var toolResults []openAIMessage

	for _, b := range blocks {
		switch b.Type {
		case "text":
			if b.Text != "" {
				if m.Role == "assistant" {
					parts = append(parts, map[string]any{"type": "text", "text": b.Text})
				} else {
					parts = append(parts, map[string]any{"type": "text", "text": b.Text})
				}
			}
		case "image":
			if b.Source != nil {
				url := b.Source.URL
				if b.Source.Data != "" {
					url = "data:" + b.Source.MediaType + ";base64," + b.Source.Data
				}
				parts = append(parts, map[string]any{"type": "image_url", "image_url": map[string]any{"url": url}})
			}
		case "tool_use":
			args := "{}"
			if len(b.Input) > 0 {
				args = string(b.Input)
			}
			assistant.ToolCalls = append(assistant.ToolCalls, openAIToolCall{
				ID:       b.ID,
				Type:     "function",
				Function: openAIFunctionCall{Name: b.Name, Arguments: args},
			})
		case "tool_result":
			content := string(b.Content)
			var asString string
			if err := json.Unmarshal(b.Content, &asString); err == nil {
				content = asString
			} else {
				var inner []anthropicContentBlock
				if err := json.Unmarshal(b.Content, &inner); err == nil {
					var sb strings.Builder
					for _, ib := range inner {
						if ib.Type == "text" {
							sb.WriteString(ib.Text)
						}
					}
					content = sb.String()
				}
			}
			if b.IsError && content != "" {
				content = "error: " + content
			}
			toolResults = append(toolResults, openAIMessage{
				Role:       "tool",
				ToolCallID: b.ToolUseID,
				Content:    content,
			})
		}
	}

	if m.Role == "assistant" {
		if len(parts) > 0 {
			assistant.Content = parts
		}
		if len(assistant.ToolCalls) == 0 && len(parts) == 0 {
			assistant.Content = ""
		}
		return []openAIMessage{assistant}, nil
	}

	out := make([]openAIMessage, 0, len(toolResults)+1)
	if len(parts) > 0 {
		out = append(out, openAIMessage{Role: "user", Content: parts})
	}
	out = append(out, toolResults...)
	if len(out) == 0 {
		out = append(out, openAIMessage{Role: "user", Content: ""})
	}
	return out, nil
}

// convertToolChoice maps Anthropic's tool_choice object ({"type":"auto"|"any"|
// "tool"|"none"}) onto OpenAI's. The string form is accepted too: some clients
// send OpenAI's shape to an Anthropic endpoint by mistake, and rejecting it
// costs the caller more than tolerating it.
func convertToolChoice(raw json.RawMessage) (any, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		switch s {
		case "auto":
			return "auto", true
		case "any", "required":
			return "required", true
		case "none":
			return "none", true
		}
		return nil, false
	}
	var obj struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false
	}
	switch obj.Type {
	case "auto":
		return "auto", true
	case "any":
		return "required", true
	case "none":
		return "none", true
	case "tool":
		if obj.Name == "" {
			return nil, false
		}
		return map[string]any{"type": "function", "function": map[string]any{"name": obj.Name}}, true
	}
	return nil, false
}

// ---------- OpenAI response → Anthropic response ----------

type openAIResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int    `json:"index"`
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content          string           `json:"content"`
			ReasoningContent string           `json:"reasoning_content"`
			ToolCalls        []openAIToolCall `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		PromptDetails    *struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	} `json:"usage"`
	Error json.RawMessage `json:"error"`
}

// OpenAIToAnthropic converts a non-streaming chat/completions response into a
// Messages response. requestedModel is echoed as the response model so a client
// that asked for one of our aliases sees the alias back, not the upstream name.
func OpenAIToAnthropic(body []byte, requestedModel string) ([]byte, error) {
	var in openAIResponse
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, fmt.Errorf("parse openai response: %w", err)
	}
	if len(in.Error) > 0 {
		return nil, fmt.Errorf("upstream error: %s", string(in.Error))
	}
	if len(in.Choices) == 0 {
		return nil, fmt.Errorf("upstream returned no choices")
	}
	ch := in.Choices[0]
	model := requestedModel
	if model == "" {
		model = in.Model
	}

	content := make([]map[string]any, 0, 2)
	if ch.Message.ReasoningContent != "" {
		content = append(content, map[string]any{"type": "thinking", "thinking": ch.Message.ReasoningContent})
	}
	if ch.Message.Content != "" {
		content = append(content, map[string]any{"type": "text", "text": ch.Message.Content})
	}
	for _, tc := range ch.Message.ToolCalls {
		content = append(content, map[string]any{
			"type":  "tool_use",
			"id":    toolID(tc.ID),
			"name":  tc.Function.Name,
			"input": parseArguments(tc.Function.Arguments),
		})
	}

	// Anthropic reports cache reads OUTSIDE input_tokens, so fresh input is the
	// upstream's prompt_tokens minus its cached subset — otherwise a client that
	// adds the two fields up (as Claude Code does) sees the prefix twice.
	inTok, outTok, cached := 0, 0, 0
	if in.Usage != nil {
		inTok, outTok = in.Usage.PromptTokens, in.Usage.CompletionTokens
		if in.Usage.PromptDetails != nil {
			cached = in.Usage.PromptDetails.CachedTokens
			if cached > 0 && cached <= inTok {
				inTok -= cached
			}
		}
	}

	out := map[string]any{
		"id":            messageID(in.ID),
		"type":          "message",
		"role":          "assistant",
		"model":         model,
		"content":       content,
		"stop_reason":   stopReason(ch.FinishReason, len(ch.Message.ToolCalls) > 0),
		"stop_sequence": nil,
		"usage": map[string]any{
			"input_tokens":                inTok,
			"output_tokens":               outTok,
			"cache_read_input_tokens":     cached,
			"cache_creation_input_tokens": 0,
		},
	}
	return json.Marshal(out)
}

// AnthropicError renders an error in the shape an Anthropic client expects.
func AnthropicError(status int, errType, message string) (int, []byte) {
	body, _ := json.Marshal(map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    errType,
			"message": message,
		},
	})
	return status, body
}

// AnthropicErrorFromUpstream maps an OpenAI-shaped error body (or an arbitrary
// one) onto the Anthropic error envelope, preserving the status code.
func AnthropicErrorFromUpstream(status int, body []byte) []byte {
	var e struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
		Message string `json:"message"`
	}
	msg := strings.TrimSpace(string(body))
	if err := json.Unmarshal(body, &e); err == nil {
		if e.Error.Message != "" {
			msg = e.Error.Message
		} else if e.Message != "" {
			msg = e.Message
		}
	}
	if msg == "" {
		msg = "upstream error"
	}
	kind := "api_error"
	switch status {
	case 400:
		kind = "invalid_request_error"
	case 401:
		kind = "authentication_error"
	case 403:
		kind = "permission_error"
	case 404:
		kind = "not_found_error"
	case 413:
		kind = "request_too_large"
	case 429:
		kind = "rate_limit_error"
	case 529:
		kind = "overloaded_error"
	}
	_, out := AnthropicError(status, kind, msg)
	return out
}

// ---------- shared helpers ----------

func messageID(id string) string {
	if id == "" {
		return "msg_" + fmt.Sprint(time.Now().UnixNano())
	}
	if strings.HasPrefix(id, "msg_") {
		return id
	}
	return "msg_" + id
}

func toolID(id string) string {
	if id == "" {
		return "toolu_" + fmt.Sprint(time.Now().UnixNano())
	}
	if strings.HasPrefix(id, "toolu_") {
		return id
	}
	return "toolu_" + id
}

func parseArguments(raw string) any {
	if strings.TrimSpace(raw) == "" {
		return map[string]any{}
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		// Anthropic requires an object; a malformed fragment becomes an empty
		// object rather than a response the client cannot parse at all.
		return map[string]any{}
	}
	return v
}

func stopReason(finish string, hasTools bool) string {
	switch finish {
	case "tool_calls", "function_call":
		return "tool_use"
	case "length":
		return "max_tokens"
	case "stop":
		return "end_turn"
	case "content_filter":
		return "refusal"
	case "":
		if hasTools {
			return "tool_use"
		}
		return "end_turn"
	}
	if hasTools {
		return "tool_use"
	}
	return "end_turn"
}
