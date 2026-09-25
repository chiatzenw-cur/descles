package proxy

// Streaming tool-call policy enforcement for the OpenAI Responses API SSE
// event stream.
//
// Responses streaming uses named events rather than chunk deltas:
//
//	response.output_item.added            item{type:"function_call", id, name}
//	response.function_call_arguments.delta   (many, partial arguments)
//	response.function_call_arguments.done    (arguments complete)
//	response.output_item.done             item complete
//
// Decision timing differs per rule:
//   - deny: the function name is known at output_item.added, so the item is
//     dropped immediately — its arguments delta/done events are swallowed by
//     item_id, and a synthetic text message item (output_text note) is
//     injected at the SAME output_index so the client's output array stays
//     dense and ordered.
//   - require_approval: arguments are needed for the approval record, so the
//     item is buffered until function_call_arguments.done, then parked (note
//     message item injected at the same output_index). A resumer grant flows
//     the original item through untouched.
//   - allow / resumed: everything is relayed verbatim.
//
// Text message items stream through untouched (no buffering, no added
// latency). Usage arrives on response.completed / response.incomplete.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

func (h *Handler) relayResponsesStreamWithPolicy(ctx context.Context, w http.ResponseWriter, span *tracing.Span, upResp *http.Response, agent string, pol *policy.Policy) error {
	var denied, held, allowed, toolTotal int
	var usage provider.Usage
	var proposed []string

	dropped := map[string]bool{} // function_call item_ids fully swallowed (deny/held)

	var bufItemID string
	var bufIndex int
	var bufName string
	var bufArgs strings.Builder
	buffering := false

	var pendingEvent string
	scanner := bufio.NewScanner(upResp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "event:") {
			pendingEvent = trimmed
			continue
		}
		if !strings.HasPrefix(trimmed, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		evEvent := pendingEvent
		evData := trimmed + "\n\n"
		pendingEvent = ""

		var frame struct {
			Type        string `json:"type"`
			OutputIndex int    `json:"output_index"`
			ItemID      string `json:"item_id"`
			Item        struct {
				ID      string `json:"id"`
				Type    string `json:"type"`
				Name    string `json:"name"`
				Status  string `json:"status"`
				Content []any  `json:"content"`
			} `json:"item"`
			Delta     string `json:"delta"`
			Arguments string `json:"arguments"`
			Usage     struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
				TotalTokens  int `json:"total_tokens"`
			} `json:"usage"`
			Response struct {
				Usage struct {
					InputTokens  int `json:"input_tokens"`
					OutputTokens int `json:"output_tokens"`
					TotalTokens  int `json:"total_tokens"`
				} `json:"usage"`
			} `json:"response"`
		}
		if err := json.Unmarshal([]byte(payload), &frame); err != nil {
			continue
		}

		switch frame.Type {
		case "response.output_item.added":
			if frame.Item.Type == "function_call" {
				group := h.groupOf(agent)
				proposed = append(proposed, frame.Item.Name)
				// Arguments are not known yet. If the tool could carry an
				// argument-scoped rule (finest grain), park until
				// function_call_arguments.done and decide with args — a relayed
				// function call cannot be retracted.
				if pol.HasArgRulesFor(agent, group, frame.Item.Name) {
					buffering = true
					bufItemID = frame.Item.ID
					bufIndex = frame.OutputIndex
					bufName = frame.Item.Name
					bufArgs.Reset()
					continue
				}
				dec := pol.ToolDecisionIn(agent, group, frame.Item.Name)
				switch dec {
				case policy.Deny:
					denied++
					toolTotal++
					dropped[frame.Item.ID] = true
					if err := emitResponsesNoteItem(w, frame.OutputIndex, "[blocked by Descles policy: "+frame.Item.Name+"]"); err != nil {
						return err
					}
					continue // original function_call added is NOT relayed
				case policy.RequireApproval:
					// Arguments are not known yet, so the resume check happens at
					// function_call_arguments.done (below). Park until then.
					buffering = true
					bufItemID = frame.Item.ID
					bufIndex = frame.OutputIndex
					bufName = frame.Item.Name
					bufArgs.Reset()
					continue
				}
				// allow: relay verbatim.
				toolTotal++
				allowed++
				if err := emitSSE(w, evEvent, evData); err != nil {
					return err
				}
				continue
			}
			// message or anything else: relay.
			if err := emitSSE(w, evEvent, evData); err != nil {
				return err
			}
		case "response.function_call_arguments.delta":
			if dropped[frame.ItemID] || (buffering && frame.ItemID == bufItemID) {
				if buffering && frame.ItemID == bufItemID {
					bufArgs.WriteString(frame.Delta)
				}
				continue // swallowed
			}
			if err := emitSSE(w, evEvent, evData); err != nil {
				return err
			}
		case "response.function_call_arguments.done":
			if dropped[frame.ItemID] {
				continue
			}
			if buffering && frame.ItemID == bufItemID {
				// arguments complete — decide now.
				if frame.Arguments != "" {
					bufArgs.WriteString(frame.Arguments)
				}
				var args map[string]any
				_ = json.Unmarshal([]byte(bufArgs.String()), &args)
				// Argument-scoped rules (finest grain) are decided here, once
				// the full arguments are known.
				base := h.toolDecision(pol, agent, h.groupOf(agent), bufName, args)
				dec := base
				appID := ""
				noteDenied := false
				if base == policy.RequireApproval {
					dec, appID = h.approvalOutcome(h.ApprovalSuspender, agent, bufName, args)
					noteDenied = dec == policy.Deny
				}
				if dec == policy.Allow {
					allowed++
					toolTotal++
					// Replay: the added event was not relayed — emit the full item now.
					if err := emitResponsesFullFunctionCall(w, bufIndex, bufItemID, bufName, bufArgs.String()); err != nil {
						return err
					}
				} else if dec == policy.Deny {
					denied++
					toolTotal++
					dropped[bufItemID] = true
					note := "[blocked by Descles policy: " + bufName + "]"
					if noteDenied {
						note = "[denied by human approval: " + bufName + "]"
					}
					if err := emitResponsesNoteItem(w, bufIndex, note); err != nil {
						return err
					}
				} else {
					held++
					toolTotal++
					dropped[bufItemID] = true
					note := "[requires human approval before execution: " + bufName + "]"
					if appID != "" {
						note = "[pending human approval: " + bufName + " (approval " + appID + ")]"
					}
					if err := emitResponsesNoteItem(w, bufIndex, note); err != nil {
						return err
					}
				}
				buffering = false
				continue
			}
			if err := emitSSE(w, evEvent, evData); err != nil {
				return err
			}
		case "response.output_item.done":
			if frame.Item.Type == "function_call" && dropped[frame.Item.ID] {
				continue // the dropped call's done is swallowed; note item already emitted
			}
			if err := emitSSE(w, evEvent, evData); err != nil {
				return err
			}
		case "response.completed", "response.incomplete", "response.failed":
			if frame.Response.Usage.InputTokens > 0 {
				usage.InputTokens = frame.Response.Usage.InputTokens
			}
			if frame.Response.Usage.OutputTokens > 0 {
				usage.OutputTokens = frame.Response.Usage.OutputTokens
			}
			if err := emitSSE(w, evEvent, evData); err != nil {
				return err
			}
		case "response.usage":
			if frame.Usage.InputTokens > 0 {
				usage.InputTokens = frame.Usage.InputTokens
			}
			if frame.Usage.OutputTokens > 0 {
				usage.OutputTokens = frame.Usage.OutputTokens
			}
			if err := emitSSE(w, evEvent, evData); err != nil {
				return err
			}
		default:
			if err := emitSSE(w, evEvent, evData); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

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
	cost := h.estimate(span, span.OrganizationID, "", usage.InputTokens, usage.OutputTokens, 0)
	finalizeSpan(span, "", usage, toolTotal, cost, upResp.StatusCode)
	if _, ok := span.Attributes[tracing.AttrPolicy]; !ok {
		span.Attributes[tracing.AttrPolicy] = string(policy.Allow)
	}
	if err := h.Store.PutSpan(ctx, span); err != nil {
		h.Logger.Error("store span", "err", err)
	}
	return nil
}

// emitResponsesNoteItem injects a synthetic text message item (output_item.added
// then output_item.done) at the given output_index.
func emitResponsesNoteItem(w io.Writer, outputIndex int, text string) error {
	noteID := "msg_" + shortID()
	item := map[string]any{
		"id": noteID, "type": "message", "status": "completed", "role": "assistant",
		"content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}},
	}
	added := map[string]any{"type": "response.output_item.added", "output_index": outputIndex, "item": item}
	a, _ := json.Marshal(added)
	if err := emitSSE(w, "event: response.output_item.added", "data: "+string(a)+"\n\n"); err != nil {
		return err
	}
	done := map[string]any{"type": "response.output_item.done", "output_index": outputIndex, "item": item}
	d, _ := json.Marshal(done)
	return emitSSE(w, "event: response.output_item.done", "data: "+string(d)+"\n\n")
}

// emitResponsesFullFunctionCall injects a complete function_call item (used to
// replay a resumed call whose buffered .added was never relayed).
func emitResponsesFullFunctionCall(w io.Writer, outputIndex int, itemID, name, arguments string) error {
	item := map[string]any{
		"id": itemID, "type": "function_call", "status": "completed", "name": name,
		"call_id": itemID, "arguments": arguments,
	}
	added := map[string]any{"type": "response.output_item.added", "output_index": outputIndex, "item": item}
	a, _ := json.Marshal(added)
	if err := emitSSE(w, "event: response.output_item.added", "data: "+string(a)+"\n\n"); err != nil {
		return err
	}
	done := map[string]any{"type": "response.output_item.done", "output_index": outputIndex, "item": item}
	d, _ := json.Marshal(done)
	return emitSSE(w, "event: response.output_item.done", "data: "+string(d)+"\n\n")
}

// shortID returns a short random id for synthesized items.
func shortID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "descles"
	}
	return fmt.Sprintf("%x", b[:])
}
