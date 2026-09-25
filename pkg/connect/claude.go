package connect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ClaudeSettings merges Descles into a Claude Code settings.json:
//
//   - model traffic: env ANTHROPIC_BASE_URL -> <edge>/anthropic, and the key
//     comes from apiKeyHelper (`descles key`), so it never sits in settings;
//   - native tools: PreToolUse / PostToolUse hooks -> `descles hook`.
//
// Existing settings and hooks are kept; a previous Descles entry is replaced.
func ClaudeSettings(existing []byte, edgeURL, self, keyFile string) ([]byte, error) {
	settings := map[string]any{}
	if len(strings.TrimSpace(string(existing))) > 0 {
		if err := json.Unmarshal(existing, &settings); err != nil {
			return nil, fmt.Errorf("existing settings are not valid JSON: %w", err)
		}
	}
	env, _ := settings["env"].(map[string]any)
	if env == nil {
		env = map[string]any{}
	}
	env["ANTHROPIC_BASE_URL"] = edgeURL + "/anthropic"
	env["DESCLES_EDGE_URL"] = edgeURL
	delete(env, "ANTHROPIC_AUTH_TOKEN") // superseded by apiKeyHelper
	settings["env"] = env
	settings["apiKeyHelper"] = shellQuote(self) + " key --file " + shellQuote(keyFile)

	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	for event, phase := range map[string]string{"PreToolUse": "pre", "PostToolUse": "post"} {
		var kept []any
		list, _ := hooks[event].([]any)
		for _, entry := range list {
			if !isDesclesHook(entry) {
				kept = append(kept, entry)
			}
		}
		cmd := shellQuote(self) + " hook claude-code " + phase + " --edge " + shellQuote(edgeURL) + " --key-file " + shellQuote(keyFile)
		kept = append(kept, map[string]any{
			"matcher": "*",
			"hooks":   []any{map[string]any{"type": "command", "command": cmd, "timeout": 15}},
		})
		hooks[event] = kept
	}
	settings["hooks"] = hooks
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func isDesclesHook(entry any) bool {
	m, _ := entry.(map[string]any)
	hs, _ := m["hooks"].([]any)
	for _, h := range hs {
		hm, _ := h.(map[string]any)
		if cmd, _ := hm["command"].(string); strings.Contains(cmd, " hook claude-code ") {
			return true
		}
	}
	return false
}

// shellQuote quotes a path for the shell Claude Code runs helpers and hooks
// in. On Windows that can be cmd.exe (apiKeyHelper) or Git Bash (hooks), and
// only double quotes work in both; Windows paths cannot contain '"', '$' is
// literal in cmd, and forward slashes keep bash from eating backslashes.
// Elsewhere it is a POSIX shell, where single quotes stop all expansion.
// (Found in a live Claude Code run: single quotes made cmd.exe fail.)
func shellQuote(s string) string {
	if goos == "windows" {
		return `"` + strings.ReplaceAll(s, `\`, "/") + `"`
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// goos is runtime.GOOS, a variable so tests can check both quoting styles.
var goos = runtime.GOOS

// ClaudeMCPCommands are the `claude mcp add` invocations that register the
// edge's MCP connectors. The CLI stores headers in the user's local Claude
// config, so the agent key never lands in a project file.
func ClaudeMCPCommands(edgeURL, key string, connectors []string, scope string) [][]string {
	var out [][]string
	for _, c := range connectors {
		out = append(out, []string{"claude", "mcp", "add", "--scope", scope, "--transport", "http",
			"descles-" + c, edgeURL + "/mcp/" + c, "--header", "Authorization: Bearer " + key})
	}
	return out
}

// hookInput is the JSON Claude Code writes to a hook's stdin.
type hookInput struct {
	SessionID    string         `json:"session_id"`
	Event        string         `json:"hook_event_name"`
	ToolName     string         `json:"tool_name"`
	ToolInput    map[string]any `json:"tool_input"`
	ToolResponse any            `json:"tool_response"`
}

// HookResult is what the hook process should print and its exit code.
type HookResult struct {
	Stdout string
	Stderr string
	Code   int
}

// ClaudeHook runs one Claude Code hook invocation against the edge.
//
// Pre: deny -> permissionDecision "deny"; require_approval -> "ask", so the
// human at the keyboard is the approver; allow -> no output, so Claude Code's
// own permission rules still apply (the edge can only tighten them). If the
// edge cannot be reached the call is denied unless failOpen is set.
//
// Post: report the execution. Reporting failures never block the session.
func ClaudeHook(ctx context.Context, e Edge, phase string, stdin io.Reader, failOpen bool) HookResult {
	var in hookInput
	if err := json.NewDecoder(io.LimitReader(stdin, 4<<20)).Decode(&in); err != nil {
		return HookResult{Stderr: "descles: unreadable hook input: " + err.Error(), Code: 1}
	}
	// Tools served by the edge's own MCP connectors are governed when the
	// edge executes them; checking twice would double-count.
	if strings.HasPrefix(in.ToolName, "mcp__descles-") {
		return HookResult{}
	}
	ctx = WithTrace(ctx, in.SessionID)
	switch phase {
	case "pre":
		v, err := e.Check(ctx, "claude-code", in.ToolName, in.ToolInput, in.SessionID)
		if err != nil {
			if failOpen {
				return HookResult{Stderr: "descles: edge unreachable, allowing (fail-open): " + err.Error()}
			}
			return preDecision("deny", "Descles edge unreachable, so the tool was blocked (fail-closed): "+err.Error())
		}
		switch v.Decision {
		case "allow":
			return HookResult{}
		case "require_approval":
			return preDecision("ask", "Descles: "+v.Reason)
		default:
			return preDecision("deny", "Descles: "+v.Reason)
		}
	case "post":
		outcome := "ok"
		if failed(in.ToolResponse) {
			outcome = "error"
		}
		if err := e.Report(ctx, "claude-code", in.ToolName, outcome, in.SessionID); err != nil {
			return HookResult{Stderr: "descles: could not report tool execution: " + err.Error()}
		}
		return HookResult{}
	}
	return HookResult{Stderr: "descles: unknown hook phase " + phase, Code: 1}
}

func preDecision(decision, reason string) HookResult {
	b, _ := json.Marshal(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason,
	}})
	return HookResult{Stdout: string(b)}
}

func failed(resp any) bool {
	m, ok := resp.(map[string]any)
	if !ok {
		return false
	}
	if v, _ := m["is_error"].(bool); v {
		return true
	}
	if v, ok := m["success"].(bool); ok && !v {
		return true
	}
	return false
}

// WriteFileWithBackup writes data to path, keeping the previous version as
// path.bak so a connect can always be undone by hand.
func WriteFileWithBackup(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if old, err := os.ReadFile(path); err == nil {
		if err := os.WriteFile(path+".bak", old, 0o600); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
