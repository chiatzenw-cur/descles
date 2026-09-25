package proxy

// Streaming tool-call policy enforcement for Anthropic Messages SSE.
//
// Anthropic streams tool_use as content blocks:
//
//	content_block_start {type:"tool_use", name, id}
//	content_block_delta {delta:{type:"input_json_delta", partial_json}}  (many)
//	content_block_stop
//
// A tool block is only complete at content_block_stop (name + full input
// JSON), and a started block cannot be retracted — so the whole block is
// buffered until stop, then decided: deny -> dropped, require_approval ->
// parked (note block injected in its place + approval opened), allow ->
// replayed. Text blocks are NOT buffered: they stream through immediately
// with only their index field rewritten to the current output-block count,
// so a dropped tool never leaves index holes in what the client sees.
// stop_reason on message_delta is rewritten tool_use -> end_turn when every
// tool in the round was blocked.
//
// Known v1 limits (documented, rare): interleaved concurrent tool blocks
// (a second content_block_start before the first tool's stop) bypass
// governance for that segment; usage is still captured and relayed.

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// anthropicSSEEvent is one SSE logical event (event: line + data: line).
type anthropicSSEEvent struct {
	event string // "event: content_block_start" (may be "")
	data  string // "data: {...}\n\n"
}

func (h *Handler) relayAnthropicStreamWithPolicy(ctx context.Context, w http.ResponseWriter, span *tracing.Span, upResp *http.Response, orgID, agent string, pol *policy.Policy) error {
	var denied, held, allowed, toolTotal int
	outBlocks := 0 // content blocks emitted so far (drives index rewriting)
	model := ""
	var usage provider.Usage
	var proposed []string

	// Tool block accumulation.
	var toolBuf []anthropicSSEEvent
	var toolIndex int
	var toolName, toolID string
	var toolJSON strings.Builder
	inTool := false
	bypass := false

	// Text block index rewriting (text streams immediately).
	pendingTextIndex := -1

	// Message-delta stop_reason rewrite state.
	swallowedToolRound := false

	flushToolBlock := func() error {
		if len(toolBuf) == 0 {
			return nil
		}
		toolTotal++
		proposed = append(proposed, toolName)
		var args map[string]any
		_ = json.Unmarshal([]byte(toolJSON.String()), &args)
		base := h.toolDecision(pol, agent, h.groupOf(agent), toolName, args)
		if h.ToolCall != nil && orgID != "" && toolName != "" {
			h.ToolCall(orgID, agent, toolName, string(base), compactJSON(args))
		}
		switch base {
		case policy.Deny:
			denied++
			swallowedToolRound = true
			idx := outBlocks
			outBlocks++
			if err := emitAnthropicTextBlock(w, idx, "[blocked by Descles policy: "+toolName+"]"); err != nil {
				return err
			}
		case policy.RequireApproval:
			dec, appID := h.approvalOutcome(h.ApprovalSuspender, agent, toolName, args)
			if dec == policy.Allow {
				allowed++
				for _, ev := range toolBuf {
					nd := rewriteAnthropicIndex(ev.data, outBlocks)
					if err := emitSSE(w, ev.event, nd); err != nil {
						return err
					}
				}
				outBlocks++
				toolBuf = nil
				toolJSON.Reset()
				inTool, bypass = false, false
				return nil
			}
			if dec == policy.Deny {
				denied++
				idx := outBlocks
				outBlocks++
				toolBuf = nil
				toolJSON.Reset()
				inTool, bypass = false, false
				return emitAnthropicTextBlock(w, idx, "[denied by human approval: "+toolName+"]")
			}
			held++
			swallowedToolRound = true
			note := "[requires human approval before execution: " + toolName + "]"
			if appID != "" {
				note = "[pending human approval: " + toolName + " (approval " + appID + ")]"
			}
			// Inject a text note block in the tool's position.
			idx := outBlocks
			outBlocks++
			if err := emitAnthropicTextBlock(w, idx, note); err != nil {
				return err
			}
		default: // allow — replay the buffered block with a compacted index.
			allowed++
			idx := outBlocks
			outBlocks++
			for _, ev := range toolBuf {
				nd := rewriteAnthropicIndex(ev.data, idx)
				if err := emitSSE(w, ev.event, nd); err != nil {
					return err
				}
			}
		}
		toolBuf = nil
		toolJSON.Reset()
		inTool, bypass = false, false
		_ = toolID
		_ = toolIndex
		return nil
	}

	flushTextStart := func(eventLine, data string) error {
		idx := outBlocks
		pendingTextIndex = idx
		if err := emitSSE(w, eventLine, data); err != nil {
			return err
		}
		return nil
	}

	body := bufio.NewReader(upResp.Body)
	var pendingEvent string
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "event:") {
			pendingEvent = trimmed
			continue
		}
		if !strings.HasPrefix(trimmed, "data:") {
			continue // blank line / comment / ping without data
		}
		payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		ev := anthropicSSEEvent{event: pendingEvent, data: trimmed + "\n\n"}
		pendingEvent = ""

		var frame struct {
			Type    string `json:"type"`
			Index   int    `json:"index"`
			Content struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				PartialJSON string `json:"partial_json"`
				StopReason  string `json:"stop_reason"`
			} `json:"delta"`
			Message struct {
				Model string `json:"model"`
				Usage struct {
					InputTokens  int `json:"input_tokens"`
					OutputTokens int `json:"output_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Usage struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
				CachedTokens int `json:"cache_read_input_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(payload), &frame); err != nil {
			continue
		}

		switch frame.Type {
		case "content_block_start":
			if inTool || bypass {
				// A second start before our tool's stop (interleaved/parallel
				// blocks) — v1 degrades: flush whatever we buffered untouched
				// and let this segment stream ungoverned rather than corrupt it.
				for _, b := range toolBuf {
					if err := emitSSE(w, b.event, b.data); err != nil {
						return err
					}
				}
				toolBuf, inTool, bypass = nil, false, true
				if frame.Content.Type == "tool_use" {
					bypass = true
				}
				if err := emitSSE(w, ev.event, ev.data); err != nil {
					return err
				}
				continue
			}
			if frame.Content.Type == "tool_use" {
				inTool = true
				toolIndex, toolID, toolName = frame.Index, frame.Content.ID, frame.Content.Name
				toolJSON.Reset()
				toolBuf = append(toolBuf[:0], ev)
				continue
			}
			// Text (or other) block — stream now, rewrite its index.
			if err := flushTextStart(ev.event, ev.data); err != nil {
				return err
			}
		case "content_block_delta":
			if inTool {
				if frame.Delta.Type == "input_json_delta" {
					toolJSON.WriteString(frame.Delta.PartialJSON)
				}
				toolBuf = append(toolBuf, ev)
				continue
			}
			if bypass {
				if err := emitSSE(w, ev.event, ev.data); err != nil {
					return err
				}
				continue
			}
			// Text delta — stream, carrying the block's rewritten index.
			if pendingTextIndex >= 0 {
				nd := rewriteAnthropicIndex(ev.data, pendingTextIndex)
				if err := emitSSE(w, ev.event, nd); err != nil {
					return err
				}
				continue
			}
			if err := emitSSE(w, ev.event, ev.data); err != nil {
				return err
			}
		case "content_block_stop":
			if inTool {
				toolBuf = append(toolBuf, ev)
				if err := flushToolBlock(); err != nil {
					return err
				}
				bypass = false
				continue
			}
			if bypass {
				bypass = false
				if err := emitSSE(w, ev.event, ev.data); err != nil {
					return err
				}
				continue
			}
			if pendingTextIndex >= 0 {
				nd := rewriteAnthropicIndex(ev.data, pendingTextIndex)
				pendingTextIndex = -1
				outBlocks++
				if err := emitSSE(w, ev.event, nd); err != nil {
					return err
				}
				continue
			}
			if err := emitSSE(w, ev.event, ev.data); err != nil {
				return err
			}
		case "message_delta":
			if frame.Delta.StopReason == "tool_use" && swallowedToolRound && allowed == 0 {
				// Every tool in the round was blocked — the client must not
				// wait for tool results it will never see.
				nd := rewriteAnthropicStopReason(ev.data, "end_turn")
				if err := emitSSE(w, ev.event, nd); err != nil {
					return err
				}
				continue
			}
			swallowedToolRound = false
			if frame.Usage.OutputTokens > 0 {
				usage.OutputTokens = frame.Usage.OutputTokens
			}
			// A translated (OpenAI-wire) upstream reports prompt tokens only at
			// the end, so the input count arrives on message_delta, not on
			// message_start where a native Anthropic upstream puts it. Without
			// this, every translated stream was accounted as input_tokens=0 and
			// its cost was under-reported.
			if frame.Usage.InputTokens > 0 {
				usage.InputTokens = frame.Usage.InputTokens
			}
			if frame.Usage.CachedTokens > 0 {
				usage.CachedTokens = frame.Usage.CachedTokens
			}
			if err := emitSSE(w, ev.event, ev.data); err != nil {
				return err
			}
		case "message_start":
			if frame.Message.Model != "" {
				model = frame.Message.Model
			}
			if frame.Message.Usage.InputTokens > 0 {
				usage.InputTokens = frame.Message.Usage.InputTokens
			}
			if err := emitSSE(w, ev.event, ev.data); err != nil {
				return err
			}
		default:
			if err := emitSSE(w, ev.event, ev.data); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	toolTotal = denied + held + allowed
	if len(proposed) > 0 {
		span.Attributes["tools_proposed"] = proposed
	}
	if denied > 0 || held > 0 {
		span.Attributes[tracing.AttrPolicy] = "deny"
		if denied > 0 {
			span.Attributes["policy_denied_tools"] = denied
		}
		if held > 0 {
			span.Attributes["policy_suspended_tools"] = held
		}
	}
	span.Attributes["tool_calls_requested"] = toolTotal
	cost := h.estimate(span, span.OrganizationID, priceModelFor(span, model), usage.InputTokens, usage.OutputTokens, usage.CachedTokens)
	finalizeSpan(span, model, usage, toolTotal, cost, upResp.StatusCode)
	if _, ok := span.Attributes[tracing.AttrPolicy]; !ok {
		span.Attributes[tracing.AttrPolicy] = string(policy.Allow)
	}
	if err := h.Store.PutSpan(ctx, span); err != nil {
		h.Logger.Error("store span", "err", err)
	}
	return nil
}

// emitAnthropicTextBlock writes a synthetic text content block (start/delta/stop).
// Every frame carries its event name: an SSE frame without an `event:` line
// defaults to the type "message", so an Anthropic client ignores the block's
// start and then receives deltas for a block it never opened.
func emitAnthropicTextBlock(w io.Writer, index int, text string) error {
	start := map[string]any{"type": "content_block_start", "index": index,
		"content_block": map[string]any{"type": "text", "text": ""}}
	sb, _ := json.Marshal(start)
	if err := emitSSE(w, "event: content_block_start", "data: "+string(sb)+"\n\n"); err != nil {
		return err
	}
	delta := map[string]any{"type": "content_block_delta", "index": index,
		"delta": map[string]any{"type": "text_delta", "text": text}}
	db, _ := json.Marshal(delta)
	if err := emitSSE(w, "event: content_block_delta", "data: "+string(db)+"\n\n"); err != nil {
		return err
	}
	stop := map[string]any{"type": "content_block_stop", "index": index}
	ob, _ := json.Marshal(stop)
	return emitSSE(w, "event: content_block_stop", "data: "+string(ob)+"\n\n")
}

// rewriteAnthropicIndex rewrites the index field of a content-block SSE event.
func rewriteAnthropicIndex(data string, index int) string {
	payload := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(data), "data:"))
	var m map[string]any
	if err := json.Unmarshal([]byte(payload), &m); err != nil {
		return data
	}
	m["index"] = index
	out, err := json.Marshal(m)
	if err != nil {
		return data
	}
	return "data: " + string(out) + "\n\n"
}

// rewriteAnthropicStopReason rewrites message_delta's stop_reason.
func rewriteAnthropicStopReason(data string, reason string) string {
	payload := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(data), "data:"))
	var m map[string]any
	if err := json.Unmarshal([]byte(payload), &m); err != nil {
		return data
	}
	if d, ok := m["delta"].(map[string]any); ok {
		d["stop_reason"] = reason
	}
	out, err := json.Marshal(m)
	if err != nil {
		return data
	}
	return "data: " + string(out) + "\n\n"
}

func emitSSE(w io.Writer, eventLine, dataLine string) error {
	if eventLine != "" {
		if _, err := io.WriteString(w, eventLine+"\n"); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, dataLine)
	return err
}
