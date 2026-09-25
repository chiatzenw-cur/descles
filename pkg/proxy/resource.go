package proxy

// Tool execution evidence extracted from the NEXT request in an agent loop.
//
// An agent that executed a local tool must put the result back into the model
// context to continue — for OpenAI chat that is messages[role=tool] (linked by
// tool_call_id to a prior assistant tool_calls entry), for Anthropic it is
// user content blocks of type tool_result (linked by tool_use_id). Both paths
// transit Descles, so we can record *what resource the agent touched and that
// a result came back* without any runtime shim. This is Tier-1 evidence
// ("result reported") — the agent itself reports the outcome; it is NOT
// authoritative execution proof (that requires Descles executing the tool).
//
// We store a fingerprint + short preview by default, never raw content
// (customer code may contain secrets).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// ToolEvidence is one observed tool execution handoff.
type ToolEvidence struct {
	Tool        string `json:"tool"`
	CallID      string `json:"call_id,omitempty"`
	Resource    string `json:"resource,omitempty"` // file://…, https://…, or tool:name
	Op          string `json:"op,omitempty"`       // read|write|delete|execute|unknown
	Status      string `json:"status"`             // "result_reported"
	ContentLen  int    `json:"content_len,omitempty"`
	ContentHash string `json:"content_hash,omitempty"` // sha256 of reported result text
	Preview     string `json:"preview,omitempty"`      // first ~180 chars
}

// extractToolEvidence scans an OpenAI chat request body for assistant
// tool_calls followed by role=tool results, plus prior assistant tool_calls in
// the same conversation (paired by tool_call_id).
func extractToolEvidence(body []byte) []ToolEvidence {
	var req struct {
		Messages []struct {
			Role       string          `json:"role"`
			ToolCallID string          `json:"tool_call_id"`
			Content    json.RawMessage `json:"content"`
			ToolCalls  []struct {
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}
	type intent struct {
		name string
		args map[string]any
	}
	intents := map[string]intent{}
	for _, m := range req.Messages {
		if m.Role == "assistant" {
			for _, tc := range m.ToolCalls {
				args := map[string]any{}
				_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
				intents[tc.ID] = intent{name: tc.Function.Name, args: args}
			}
		}
	}
	var out []ToolEvidence
	for _, m := range req.Messages {
		if m.Role != "tool" || m.ToolCallID == "" {
			continue
		}
		text := contentText(m.Content)
		if strings.TrimSpace(text) == "" {
			continue
		}
		it := intents[m.ToolCallID]
		sum := sha256.Sum256([]byte(text))
		preview := []rune(text)
		if len(preview) > 180 {
			preview = preview[:180]
		}
		out = append(out, ToolEvidence{
			Tool:        it.name,
			CallID:      m.ToolCallID,
			Resource:    resourceFor(it.name, it.args),
			Op:          opFor(it.name),
			Status:      "result_reported",
			ContentLen:  len(text),
			ContentHash: hex.EncodeToString(sum[:]),
			Preview:     string(preview),
		})
	}
	return out
}

// extractToolEvidenceAnthropic scans an Anthropic Messages body: assistant
// tool_use blocks paired with user tool_result blocks by tool_use_id.
func extractToolEvidenceAnthropic(body []byte) []ToolEvidence {
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}
	type block struct {
		Type       string          `json:"type"`
		ID         string          `json:"id"`
		Name       string          `json:"name"`
		Input      json.RawMessage `json:"input"`
		ToolUseID  string          `json:"tool_use_id"`
		ContentRaw json.RawMessage `json:"content"`
	}
	blocks := func(raw json.RawMessage) []block {
		var out []block
		if json.Unmarshal(raw, &out) == nil {
			return out
		}
		return nil
	}
	type intent struct {
		name string
		args map[string]any
	}
	intents := map[string]intent{}
	for _, m := range req.Messages {
		for _, c := range blocks(m.Content) {
			if c.Type == "tool_use" && c.ID != "" {
				args := map[string]any{}
				_ = json.Unmarshal(c.Input, &args)
				intents[c.ID] = intent{name: c.Name, args: args}
			}
		}
	}
	var out []ToolEvidence
	for _, m := range req.Messages {
		if m.Role != "user" {
			continue
		}
		for _, c := range blocks(m.Content) {
			if c.Type != "tool_result" || c.ToolUseID == "" {
				continue
			}
			text := contentText(c.ContentRaw)
			if strings.TrimSpace(text) == "" {
				continue
			}
			it := intents[c.ToolUseID]
			sum := sha256.Sum256([]byte(text))
			preview := []rune(text)
			if len(preview) > 180 {
				preview = preview[:180]
			}
			out = append(out, ToolEvidence{
				Tool:        it.name,
				CallID:      c.ToolUseID,
				Resource:    resourceFor(it.name, it.args),
				Op:          opFor(it.name),
				Status:      "result_reported",
				ContentLen:  len(text),
				ContentHash: hex.EncodeToString(sum[:]),
				Preview:     string(preview),
			})
		}
	}
	return out
}

// contentText flattens a message content field (string or array of parts).
func contentText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Type    string          `json:"type"`
		Text    string          `json:"text"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		var sb strings.Builder
		for _, p := range parts {
			if p.Text != "" {
				sb.WriteString(p.Text)
				continue
			}
			// nested content (e.g. some providers wrap text deeper)
			if len(p.Content) > 0 {
				sb.WriteString(contentText(p.Content))
			}
		}
		return sb.String()
	}
	return ""
}

// resourceFor derives a canonical resource from tool name + arguments.
// Prefers URL/path-ish keys, falls back to tool:name.
func resourceFor(tool string, args map[string]any) string {
	if args != nil {
		for _, key := range []string{"url", "endpoint", "base_url", "website", "link"} {
			if v, ok := strVal(args[key]); ok && looksLikeURL(v) {
				return v
			}
		}
		for _, key := range []string{"file_path", "path", "file", "filename"} {
			if v, ok := strVal(args[key]); ok {
				return "file://" + v
			}
		}
		for _, key := range []string{"repo", "repository", "full_name"} {
			if v, ok := strVal(args[key]); ok {
				return "github:" + v
			}
		}
	}
	if tool != "" {
		return "tool:" + tool
	}
	return ""
}

func looksLikeURL(v string) bool {
	return strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "www.")
}

func strVal(v any) (string, bool) {
	s, ok := v.(string)
	return strings.TrimSpace(s), ok && strings.TrimSpace(s) != ""
}

// opFor heuristically classifies a tool call's operation from its name.
func opFor(tool string) string {
	t := strings.ToLower(tool)
	switch {
	case strings.Contains(t, "delete") || strings.Contains(t, "remove") || strings.Contains(t, "rm "):
		return "delete"
	case strings.Contains(t, "write") || strings.Contains(t, "create") || strings.Contains(t, "edit") ||
		strings.Contains(t, "patch") || strings.Contains(t, "update") || strings.Contains(t, "add") ||
		strings.Contains(t, "post") || strings.Contains(t, "put") || strings.Contains(t, "send") ||
		strings.Contains(t, "submit"):
		return "write"
	case strings.Contains(t, "exec") || strings.Contains(t, "run") || strings.Contains(t, "shell") ||
		strings.Contains(t, "bash") || strings.Contains(t, "command") || strings.Contains(t, "kubectl"):
		return "execute"
	case strings.Contains(t, "read") || strings.Contains(t, "fetch") || strings.Contains(t, "get") ||
		strings.Contains(t, "list") || strings.Contains(t, "search") || strings.Contains(t, "view") ||
		strings.Contains(t, "cat") || strings.Contains(t, "open"):
		return "read"
	}
	return "unknown"
}

// evidence applies the payload-logging switch: without DESCLES_LOG_PAYLOADS
// the stored record keeps what happened (tool, resource, op, length, hash)
// but not a preview of the result text.
func (h *Handler) evidence(ev []ToolEvidence) []ToolEvidence {
	if h.Cfg.LogPayloads {
		return ev
	}
	for i := range ev {
		ev[i].Preview = ""
	}
	return ev
}
