package translate

import (
	"encoding/json"
	"fmt"
	"strings"
)

// StreamTranslator turns an OpenAI chat/completions SSE stream into the Anthropic
// Messages SSE event sequence.
//
// Two deliberate simplifications, both chosen to remove failure modes that are
// hard to see in tests:
//
//   - Text and reasoning stream live (text_delta / thinking_delta).
//   - Tool calls are buffered and emitted as complete blocks at the end. OpenAI
//     streams tool arguments as fragments keyed by call index, and those
//     fragments can interleave; emitting Anthropic blocks per fragment would
//     require reopening closed blocks. A client only executes tools after the
//     message ends, so buffering costs nothing observable.
//
// Usage is held until the final chunk (StreamOptions include_usage) so
// message_delta carries real output_tokens instead of a guess.
type StreamTranslator struct {
	requestedModel string
	msgID          string
	started        bool

	thinkingOpen bool
	thinkingIdx  int
	textOpen     bool
	textIdx      int
	nextIndex    int

	tools []*toolAcc

	usageIn, usageOut, usageCached int
	stopReason                     string
	finishSeen                     bool
	finished                       bool
}

type toolAcc struct {
	id   string
	name string
	args strings.Builder
}

// NewStreamTranslator starts a translation for a client that asked for
// requestedModel (the alias is echoed back so the client sees what it sent).
func NewStreamTranslator(requestedModel string) *StreamTranslator {
	return &StreamTranslator{requestedModel: requestedModel, textIdx: -1, thinkingIdx: -1}
}

type openAIStreamChunk struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content"`
			ToolCalls        []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		PromptDetails    *struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	} `json:"usage"`
}

// Feed consumes one upstream data payload (the JSON after "data: ") and returns
// the SSE frames to write to the client, each already terminated by a blank line.
func (t *StreamTranslator) Feed(payload []byte) [][]byte {
	trimmed := strings.TrimSpace(string(payload))
	if trimmed == "" || trimmed == "[DONE]" {
		return nil
	}
	var chunk openAIStreamChunk
	if err := json.Unmarshal([]byte(trimmed), &chunk); err != nil {
		// A malformed upstream chunk is skipped rather than failing the stream:
		// the client already has a 200 and partial content.
		return nil
	}
	if chunk.Usage != nil {
		t.usageIn = chunk.Usage.PromptTokens
		t.usageOut = chunk.Usage.CompletionTokens
		if chunk.Usage.PromptDetails != nil {
			t.usageCached = chunk.Usage.PromptDetails.CachedTokens
			// Anthropic's input_tokens excludes cache reads, so fresh input is
			// prompt_tokens minus the cached subset; Usage() and the emitted
			// frames must agree or the cached prefix is counted (and billed)
			// twice on every cache hit.
			if t.usageCached > 0 && t.usageCached <= t.usageIn {
				t.usageIn -= t.usageCached
			}
		}
	}
	var out [][]byte
	if chunk.ID != "" && t.msgID == "" {
		t.msgID = messageID(chunk.ID)
	}
	if t.msgID == "" {
		t.msgID = messageID("")
	}

	for _, choice := range chunk.Choices {
		if choice.Delta.ReasoningContent != "" {
			out = append(out, t.ensureThinking()...)
			out = append(out, sse("content_block_delta", map[string]any{
				"type":  "content_block_delta",
				"index": t.thinkingIdx,
				"delta": map[string]any{"type": "thinking_delta", "thinking": choice.Delta.ReasoningContent},
			}))
		}
		if choice.Delta.Content != "" {
			out = append(out, t.closeThinking()...)
			out = append(out, t.ensureText()...)
			out = append(out, sse("content_block_delta", map[string]any{
				"type":  "content_block_delta",
				"index": t.textIdx,
				"delta": map[string]any{"type": "text_delta", "text": choice.Delta.Content},
			}))
		}
		for _, tc := range choice.Delta.ToolCalls {
			t.accumulateTool(tc.Index, tc.ID, tc.Function.Name, tc.Function.Arguments)
		}
		if choice.FinishReason != "" {
			t.finishSeen = true
			t.stopReason = stopReason(choice.FinishReason, len(t.tools) > 0)
		}
	}
	return out
}

func (t *StreamTranslator) accumulateTool(index int, id, name, args string) {
	for len(t.tools) <= index {
		t.tools = append(t.tools, &toolAcc{})
	}
	acc := t.tools[index]
	if id != "" && acc.id == "" {
		acc.id = id
	}
	if name != "" && acc.name == "" {
		acc.name = name
	}
	acc.args.WriteString(args)
}

// Finish flushes buffered tool blocks, then message_delta + message_stop. It is
// idempotent: a relay that sees both [DONE] and EOF must not emit two endings.
func (t *StreamTranslator) Finish() [][]byte {
	if t.finished {
		return nil
	}
	t.finished = true
	var out [][]byte
	out = append(out, t.ensureStart()...)
	out = append(out, t.closeThinking()...)
	out = append(out, t.closeText()...)
	for _, acc := range t.tools {
		if acc == nil || acc.name == "" {
			continue
		}
		idx := t.nextIndex
		t.nextIndex++
		out = append(out, sse("content_block_start", map[string]any{
			"type":  "content_block_start",
			"index": idx,
			"content_block": map[string]any{
				"type":  "tool_use",
				"id":    toolID(acc.id),
				"name":  acc.name,
				"input": map[string]any{},
			},
		}))
		args := acc.args.String()
		if strings.TrimSpace(args) == "" {
			args = "{}"
		}
		out = append(out, sse("content_block_delta", map[string]any{
			"type":  "content_block_delta",
			"index": idx,
			"delta": map[string]any{"type": "input_json_delta", "partial_json": args},
		}))
		out = append(out, sse("content_block_stop", map[string]any{"type": "content_block_stop", "index": idx}))
	}
	stop := t.stopReason
	if stop == "" {
		stop = stopReason("", len(t.tools) > 0)
	}
	out = append(out, sse("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": stop, "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": t.usageOut, "input_tokens": t.usageIn},
	}))
	out = append(out, sse("message_stop", map[string]any{"type": "message_stop"}))
	return out
}

// Usage reports the translated token accounting. input excludes cached, matching
// Anthropic's own reporting (see the parse path).
func (t *StreamTranslator) Usage() (input, output, cached int) {
	return t.usageIn, t.usageOut, t.usageCached
}

// StopReason exposes the translated Anthropic stop reason, for spans.
func (t *StreamTranslator) StopReason() string {
	if t.stopReason != "" {
		return t.stopReason
	}
	return stopReason("", len(t.tools) > 0)
}

// ToolNames lists the tools the model asked to call, for tool-evidence tracing.
func (t *StreamTranslator) ToolNames() []string {
	var names []string
	for _, acc := range t.tools {
		if acc != nil && acc.name != "" {
			names = append(names, acc.name)
		}
	}
	return names
}

func (t *StreamTranslator) ensureStart() [][]byte {
	if t.started {
		return nil
	}
	t.started = true
	return [][]byte{sse("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id":            t.msgID,
			"type":          "message",
			"role":          "assistant",
			"model":         t.requestedModel,
			"content":       []any{},
			"stop_reason":   nil,
			"stop_sequence": nil,
			"usage": map[string]any{
				"input_tokens":                t.usageIn,
				"output_tokens":               0,
				"cache_read_input_tokens":     t.usageCached,
				"cache_creation_input_tokens": 0,
			},
		},
	})}
}

func (t *StreamTranslator) ensureThinking() [][]byte {
	if t.thinkingOpen {
		return nil
	}
	out := t.ensureStart()
	// A reasoning block precedes the text block, so it takes the first index.
	if t.textOpen {
		out = append(out, t.closeText()...)
	}
	t.thinkingOpen = true
	t.thinkingIdx = t.nextIndex
	t.nextIndex++
	out = append(out, sse("content_block_start", map[string]any{
		"type":          "content_block_start",
		"index":         t.thinkingIdx,
		"content_block": map[string]any{"type": "thinking", "thinking": ""},
	}))
	return out
}

func (t *StreamTranslator) closeThinking() [][]byte {
	if !t.thinkingOpen {
		return nil
	}
	t.thinkingOpen = false
	return [][]byte{sse("content_block_stop", map[string]any{
		"type":  "content_block_stop",
		"index": t.thinkingIdx,
	})}
}

func (t *StreamTranslator) ensureText() [][]byte {
	if t.textOpen {
		return nil
	}
	out := t.ensureStart()
	t.textOpen = true
	t.textIdx = t.nextIndex
	t.nextIndex++
	out = append(out, sse("content_block_start", map[string]any{
		"type":          "content_block_start",
		"index":         t.textIdx,
		"content_block": map[string]any{"type": "text", "text": ""},
	}))
	return out
}

func (t *StreamTranslator) closeText() [][]byte {
	if !t.textOpen {
		return nil
	}
	t.textOpen = false
	return [][]byte{sse("content_block_stop", map[string]any{
		"type":  "content_block_stop",
		"index": t.textIdx,
	})}
}

func sse(event string, payload any) []byte {
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"type":"error","error":{"type":"api_error","message":"encode event"}}`)
	}
	return []byte(fmt.Sprintf("event: %s\ndata: %s\n\n", event, body))
}
