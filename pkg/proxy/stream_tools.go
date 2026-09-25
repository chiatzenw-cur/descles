package proxy

// Streaming tool-call policy enforcement for OpenAI chat.completions SSE.
//
// Tool calls arrive split across many chunks (per-index name + arguments
// fragments). We cannot retract bytes already flushed, so tool-call deltas are
// buffered until the turn ends (finish_reason) and only then decided: allowed
// calls are replayed unchanged (indexes compacted), denied calls are dropped
// and parked calls replaced by a text note — exactly like the non-streaming
// rewrite. Ordinary text deltas stream through untouched with zero added
// latency; the tool segment only delays the few chunks of the tool round.

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// chatToolAccumulator reassembles one streamed tool call across chunks.
type chatToolAccumulator struct {
	index   int
	id      string
	typ     string
	name    string
	args    string
	lines   []string // raw "data:" payloads that carried this tool call
	decided policy.Decision
	note    string
}

// relayChatStreamWithPolicy relays an OpenAI chat SSE stream, applying tool
// policy to streamed tool calls. Non-tool traffic is never buffered.
func (h *Handler) relayChatStreamWithPolicy(w http.ResponseWriter, r *http.Request, span *tracing.Span, upResp *http.Response, agent string, pol *policy.Policy) error {
	w.Header().Set("Content-Type", upResp.Header.Get("Content-Type"))
	copyUpstreamResponseHeaders(w.Header(), upResp.Header)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(upResp.StatusCode)
	flusher, _ := w.(http.Flusher)

	_ = pol
	suspend := h.ApprovalSuspender
	writeLine := func(line string) error {
		if _, err := io.WriteString(w, line+"\n"); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}

	var (
		tools     []*chatToolAccumulator // in-flight streamed tool calls
		pending   []string               // raw data payloads buffered for the tool turn
		inTool    bool
		model     string
		denied    int
		held      int
		toolTotal int
		finished  bool
		usage     provider.Usage
		usageOK   bool
	)

	scanner := bufio.NewScanner(upResp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	// Record proposed tool names on the span. flushToolTurn clears the tools
	// slice right after each decision, so this must run at every flush site,
	// never at function tail.
	recordProposed := func(ts []*chatToolAccumulator) {
		if len(ts) == 0 {
			return
		}
		existing, _ := span.Attributes["tools_proposed"].([]string)
		seen := make(map[string]bool, len(existing)+len(ts))
		for _, n := range existing {
			seen[n] = true
		}
		for _, acc := range ts {
			if acc.name != "" && !seen[acc.name] {
				seen[acc.name] = true
				existing = append(existing, acc.name)
			}
		}
		if len(existing) > 0 {
			span.Attributes["tools_proposed"] = existing
		}
		if h.ToolCall != nil {
			if orgID := h.requestOrg(r); orgID != "" {
				for _, acc := range ts {
					if acc.name == "" {
						continue
					}
					dec := h.toolDecision(pol, agent, h.groupOf(agent), acc.name, toolArgsMap(acc.args))
					h.ToolCall(orgID, agent, acc.name, string(dec), acc.args)
				}
			}
		}
	}
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			if err := writeLine(line); err != nil {
				return err
			}
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" {
			if err := writeLine(line); err != nil {
				return err
			}
			continue
		}
		if payload == "[DONE]" {
			if inTool {
				toolTotal += len(tools)
				recordProposed(tools)
				if err := h.flushToolTurn(w, tools, pending, agent, pol, suspend, &denied, &held); err != nil {
					return err
				}
				tools, pending, inTool = nil, nil, false
			}
			if err := writeLine(line); err != nil {
				return err
			}
			continue
		}

		// Parse the chunk enough to see text vs tool fragments.
		var chunk struct {
			Model   string `json:"model"`
			Choices []struct {
				FinishReason *string `json:"finish_reason"`
				Delta        struct {
					Content   *string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function *struct {
							Name      *string `json:"name"`
							Arguments *string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			// Unparseable line: pass through if not in a tool segment.
			if inTool {
				pending = append(pending, payload)
			} else if err := writeLine(line); err != nil {
				return err
			}
			continue
		}
		if chunk.Model != "" {
			model = chunk.Model
		}
		if !usageOK && strings.Contains(payload, "\"usage\"") {
			var withUsage struct {
				Usage json.RawMessage `json:"usage"`
			}
			if json.Unmarshal([]byte(payload), &withUsage) == nil && len(withUsage.Usage) > 0 && string(withUsage.Usage) != "null" {
				if u, err := unmarshalStreamUsage(withUsage.Usage); err == nil {
					usage, usageOK = u, true
				}
			}
		}

		hasToolDelta := false
		for _, c := range chunk.Choices {
			if len(c.Delta.ToolCalls) > 0 {
				hasToolDelta = true
				break
			}
		}

		if hasToolDelta {
			if !inTool {
				inTool = true
				tools = nil
				pending = nil
			}
			pending = append(pending, payload)
			// Accumulate fragments per index.
			for _, c := range chunk.Choices {
				for _, tc := range c.Delta.ToolCalls {
					acc := findToolAcc(tools, tc.Index)
					if acc == nil {
						acc = &chatToolAccumulator{index: tc.Index}
						tools = append(tools, acc)
					}
					if tc.ID != "" {
						acc.id = tc.ID
					}
					if tc.Type != "" {
						acc.typ = tc.Type
					}
					if tc.Function != nil {
						if tc.Function.Name != nil {
							acc.name += *tc.Function.Name
						}
						if tc.Function.Arguments != nil {
							acc.args += *tc.Function.Arguments
						}
					}
				}
			}
			continue
		}

		// Non-tool delta: if a tool segment is open, decide it now (the
		// finish_reason line closes the tool round). The original line is
		// swallowed — flushToolTurn emits its own finish/notes — so clients
		// never see a duplicate finish or a tool_calls finish with missing
		// calls.
		if inTool {
			toolTotal += len(tools)
			recordProposed(tools)
			if err := h.flushToolTurn(w, tools, pending, agent, pol, suspend, &denied, &held); err != nil {
				return err
			}
			tools, pending, inTool = nil, nil, false
			continue
		}
		// Text deltas pass through untouched.
		if err := writeLine(line); err != nil {
			return err
		}
		_ = finished
	}
	if inTool {
		toolTotal += len(tools)
		recordProposed(tools)
		if err := h.flushToolTurn(w, tools, pending, agent, pol, suspend, &denied, &held); err != nil {
			return err
		}
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
	if !usageOK {
		usageOK = true // keep span finalization symmetrical; zero usage is valid
	}
	cost := h.estimate(span, span.OrganizationID, model, usage.InputTokens, usage.OutputTokens, usage.CachedTokens)
	finalizeSpan(span, model, usage, toolTotal, cost, upResp.StatusCode)
	if _, ok := span.Attributes[tracing.AttrPolicy]; !ok {
		span.Attributes[tracing.AttrPolicy] = string(policy.Allow)
	}
	if err := h.Store.PutSpan(r.Context(), span); err != nil {
		h.Logger.Error("store span", "err", err)
	}
	return scanner.Err()
}

// unmarshalStreamUsage parses a chat chunk's top-level usage object
// (prompt_tokens / completion_tokens naming) into the provider Usage shape.
func unmarshalStreamUsage(raw json.RawMessage) (provider.Usage, error) {
	var cu struct {
		PromptTokens        int `json:"prompt_tokens"`
		CompletionTokens    int `json:"completion_tokens"`
		TotalTokens         int `json:"total_tokens"`
		PromptTokensDetails struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	}
	if err := json.Unmarshal(raw, &cu); err != nil {
		return provider.Usage{}, err
	}
	// prompt_tokens include the cached subset; Usage.InputTokens means fresh
	// input (see provider.UncachedInput for why this matters to the bill).
	return provider.Usage{
		InputTokens:  provider.UncachedInput(cu.PromptTokens, cu.PromptTokensDetails.CachedTokens),
		OutputTokens: cu.CompletionTokens,
		CachedTokens: cu.PromptTokensDetails.CachedTokens,
		TotalTokens:  cu.TotalTokens,
	}, nil
}

func findToolAcc(tools []*chatToolAccumulator, index int) *chatToolAccumulator {
	for _, t := range tools {
		if t.index == index {
			return t
		}
	}
	return nil
}

// flushToolTurn decides every accumulated streamed tool call and writes the
// replayed segment: allowed calls with compacted indexes, then the closing
// note + finish_reason rewrite when something was blocked or parked.
func (h *Handler) flushToolTurn(w io.Writer, tools []*chatToolAccumulator, pending []string, agent string, pol *policy.Policy, suspend approvalSuspender, denied, held *int) error {
	if len(tools) == 0 {
		// No tool fragments actually arrived; replay buffer verbatim.
		for _, p := range pending {
			if _, err := io.WriteString(w, "data: "+p+"\n\n"); err != nil {
				return err
			}
		}
		return nil
	}
	// Decide each tool.
	type outcome struct {
		acc  *chatToolAccumulator
		keep bool
		note string
	}
	outs := make([]outcome, 0, len(tools))
	keptAny := false
	for _, acc := range tools {
		args := toolArgsMap(acc.args)
		acc.decided = h.toolDecision(pol, agent, h.groupOf(agent), acc.name, args)
		o := outcome{acc: acc, keep: acc.decided == policy.Allow}
		switch acc.decided {
		case policy.Deny:
			*denied++
			o.note = "[blocked by Descles policy: " + acc.name + "]"
		case policy.RequireApproval:
			switch dec, appID := h.approvalOutcome(suspend, agent, acc.name, args); dec {
			case policy.Allow:
				// Blocking gate approved (or a resume grant hit): deliver the
				// real call this turn.
				o.keep = true
				acc.decided = policy.Allow
			case policy.Deny:
				*denied++
				o.note = "[denied by human approval: " + acc.name + "]"
				acc.decided = policy.Deny
			default:
				*held++
				if appID != "" {
					o.note = "[pending human approval: " + acc.name + " (approval " + appID + ")]"
				} else {
					o.note = "[requires human approval before execution: " + acc.name + "]"
				}
			}
		}
		if o.keep {
			keptAny = true
		}
		outs = append(outs, o)
	}

	// Replay: template comes from the first pending payload (id/object/model).
	template := map[string]any{}
	_ = json.Unmarshal([]byte(pending[0]), &template)
	var note string
	for _, o := range outs {
		if o.note != "" {
			if note == "" {
				note = o.note
			} else {
				note += "\n" + o.note
			}
		}
	}

	if keptAny {
		// Emit a text note first (content), then replay allowed tool deltas
		// with compacted indexes.
		if note != "" {
			if err := emitChatTextDelta(w, template, note); err != nil {
				return err
			}
		}
		compact := 0
		for _, o := range outs {
			if !o.keep {
				continue
			}
			rewritten := compactChatToolDeltas(pending, o.acc.index, compact)
			for _, p := range rewritten {
				if _, err := io.WriteString(w, "data: "+p+"\n\n"); err != nil {
					return err
				}
			}
			compact++
		}
		// Finish reason stays tool_calls (allowed calls remain for the client).
		if err := emitChatFinish(w, template, "tool_calls"); err != nil {
			return err
		}
		return nil
	}
	// Everything was blocked/parked: text note + stop.
	if note != "" {
		if err := emitChatTextDelta(w, template, note); err != nil {
			return err
		}
	}
	if err := emitChatFinish(w, template, "stop"); err != nil {
		return err
	}
	return nil
}

func toolArgsMap(raw string) map[string]any {
	args := map[string]any{}
	_ = json.Unmarshal([]byte(raw), &args)
	return args
}

// compactChatToolDeltas rewrites every pending payload so only the tool call
// with wantIndex survives, renumbered to newIndex.
func compactChatToolDeltas(pending []string, wantIndex, newIndex int) []string {
	out := make([]string, 0, len(pending))
	for _, p := range pending {
		var chunk map[string]any
		if err := json.Unmarshal([]byte(p), &chunk); err != nil {
			continue
		}
		choices, ok := chunk["choices"].([]any)
		if !ok || len(choices) == 0 {
			continue
		}
		for _, ci := range choices {
			choice, ok := ci.(map[string]any)
			if !ok {
				continue
			}
			delta, ok := choice["delta"].(map[string]any)
			if !ok {
				continue
			}
			tcs, ok := delta["tool_calls"].([]any)
			if !ok {
				continue
			}
			kept := make([]any, 0, 1)
			for _, tci := range tcs {
				tc, ok := tci.(map[string]any)
				if !ok {
					continue
				}
				if idx, _ := tc["index"].(float64); int(idx) == wantIndex {
					tc["index"] = float64(newIndex)
					kept = append(kept, tc)
				}
			}
			if len(kept) == 0 {
				continue
			}
			delta["tool_calls"] = kept
		}
		b, err := json.Marshal(chunk)
		if err != nil {
			continue
		}
		out = append(out, string(b))
	}
	return out
}

// emitChatTextDelta writes a content-only chat chunk copying the template's
// envelope fields (id/object/model/created).
func emitChatTextDelta(w io.Writer, template map[string]any, text string) error {
	chunk := cloneEnvelope(template)
	chunk["choices"] = []any{map[string]any{
		"index": 0, "delta": map[string]any{"content": text}, "finish_reason": nil,
	}}
	return writeChatChunk(w, chunk)
}

func emitChatFinish(w io.Writer, template map[string]any, reason string) error {
	chunk := cloneEnvelope(template)
	chunk["choices"] = []any{map[string]any{
		"index": 0, "delta": map[string]any{}, "finish_reason": reason,
	}}
	return writeChatChunk(w, chunk)
}

func writeChatChunk(w io.Writer, chunk map[string]any) error {
	b, err := json.Marshal(chunk)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, "data: "+string(b)+"\n\n"); err != nil {
		return err
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

func cloneEnvelope(template map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"id", "object", "model", "created"} {
		if v, ok := template[k]; ok {
			out[k] = v
		}
	}
	if out["object"] == nil {
		out["object"] = "chat.completion.chunk"
	}
	return out
}
