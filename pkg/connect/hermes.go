package connect

import (
	"context"
	"encoding/json"
	"io"
	"strings"
)

// hermesInput is what Hermes Agent's shell hooks write to stdin for
// pre_tool_call / post_tool_call.
type hermesInput struct {
	Event     string         `json:"hook_event_name"`
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
	SessionID string         `json:"session_id"`
	Extra     map[string]any `json:"extra"`
}

// HermesHook runs one Hermes shell hook against the edge.
//
// pre_tool_call: deny and require_approval block the tool (Hermes shell hooks
// have no "ask a person" verdict, so a call that needs approval is stopped
// with the reason); allow prints nothing, so Hermes' own approvals still
// apply. An unreachable edge blocks unless failOpen.
//
// post_tool_call: report the execution; never blocks.
func HermesHook(ctx context.Context, e Edge, stdin io.Reader, failOpen bool) HookResult {
	var in hermesInput
	if err := json.NewDecoder(io.LimitReader(stdin, 4<<20)).Decode(&in); err != nil {
		return HookResult{Stderr: "descles: unreadable hook input: " + err.Error(), Code: 1}
	}
	if in.ToolName == "" || strings.HasPrefix(in.ToolName, "mcp_descles-") {
		return HookResult{}
	}
	ctx = WithTrace(ctx, in.SessionID)
	switch in.Event {
	case "pre_tool_call":
		v, err := e.Check(ctx, "hermes", in.ToolName, in.ToolInput, in.SessionID)
		if err != nil {
			if failOpen {
				return HookResult{Stderr: "descles: edge unreachable, allowing (fail-open): " + err.Error()}
			}
			return hermesBlock("Descles edge unreachable, so the tool was blocked (fail-closed): " + err.Error())
		}
		switch v.Decision {
		case "allow":
			return HookResult{}
		case "require_approval":
			return hermesBlock("Descles: " + v.Reason + ". Ask a person to run it or to change the policy.")
		default:
			return hermesBlock("Descles: " + v.Reason)
		}
	case "post_tool_call":
		outcome := "ok"
		if failed(in.Extra["result"]) || failed(in.Extra) {
			outcome = "error"
		}
		if err := e.Report(ctx, "hermes", in.ToolName, outcome, in.SessionID); err != nil {
			return HookResult{Stderr: "descles: could not report tool execution: " + err.Error()}
		}
	}
	return HookResult{}
}

func hermesBlock(reason string) HookResult {
	b, _ := json.Marshal(map[string]string{"decision": "block", "reason": reason})
	return HookResult{Stdout: string(b)}
}
