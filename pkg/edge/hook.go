package edge

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/policy"
)

// Client-native tools (Claude Code's Bash/Edit, Codex's shell, ...) execute
// on the developer's machine, not through the edge. The harness's own hook
// asks the edge before running one (tool-check) and reports afterwards
// (tool-report), so the same grants, policy and metering cover them.
//
// Names are normalized so one policy covers every harness:
//
//	Bash / shell / exec_command    -> local.bash    args: command
//	Edit / MultiEdit / Write / patch -> local.write args: path
//	Read / Glob / Grep / LS        -> local.read    args: path, pattern
//	WebFetch / WebSearch           -> local.web     args: url, query
//	mcp__<server>__<tool>          -> mcp.<server>.<tool>
//	anything else                  -> local.<lowercased name>
//
// Shell rules are guardrails on what the model asks for, not a sandbox: a
// determined process can obfuscate a command. Pair them with the harness's
// sandbox for hard isolation.

// ToolCheck is what a harness hook sends before running a tool.
type ToolCheck struct {
	Client  string         `json:"client"` // "claude-code", "codex", ...
	Tool    string         `json:"tool"`
	Input   map[string]any `json:"input"`
	Session string         `json:"session,omitempty"`
}

// ToolVerdict is the edge's answer.
type ToolVerdict struct {
	Decision string `json:"decision"` // allow | deny | require_approval
	Tool     string `json:"tool"`     // normalized name the policy saw
	Reason   string `json:"reason,omitempty"`
}

// ToolReport is what a harness hook sends after a tool ran.
type ToolReport struct {
	Client  string `json:"client"`
	Tool    string `json:"tool"`
	Outcome string `json:"outcome"` // ok | error
	Session string `json:"session,omitempty"`
}

// NormalizeTool maps a harness tool call to the policy's tool name and args.
// The original input is kept; normalized fields are added alongside it.
func NormalizeTool(name string, input map[string]any) (string, map[string]any) {
	args := map[string]any{}
	for k, v := range input {
		args[k] = v
	}
	copyField := func(to string, from ...string) {
		if _, ok := args[to]; ok {
			return
		}
		for _, f := range from {
			if v, ok := input[f]; ok {
				args[to] = v
				return
			}
		}
	}
	if strings.HasPrefix(name, "mcp__") {
		parts := strings.SplitN(strings.TrimPrefix(name, "mcp__"), "__", 2)
		if len(parts) == 2 {
			return "mcp." + sanitizeToolPart(parts[0]) + "." + sanitizeToolPart(parts[1]), args
		}
	}
	switch strings.ToLower(name) {
	case "bash", "shell", "exec_command", "local_shell", "terminal":
		if cmd, ok := input["command"].([]any); ok { // Codex passes argv
			parts := make([]string, 0, len(cmd))
			for _, p := range cmd {
				parts = append(parts, argText(p))
			}
			args["command"] = strings.Join(parts, " ")
		}
		copyField("command", "cmd")
		return "local.bash", args
	case "edit", "multiedit", "write", "notebookedit", "apply_patch", "write_file", "patch":
		copyField("path", "file_path", "notebook_path")
		return "local.write", args
	case "read", "glob", "grep", "ls", "read_file", "list_dir", "search_files":
		copyField("path", "file_path", "path")
		return "local.read", args
	case "webfetch", "websearch", "web_search", "fetch":
		return "local.web", args
	}
	return "local." + sanitizeToolPart(strings.ToLower(name)), args
}

func argText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func sanitizeToolPart(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	out := b.String()
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

func (g *MCPGateway) agent(w http.ResponseWriter, r *http.Request) (userID, agentID string, ok bool) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	_, userID, agentID, ok = g.Resolve(token)
	if !ok || agentID == "" {
		http.Error(w, "agent key required", http.StatusUnauthorized)
		return "", "", false
	}
	return userID, agentID, true
}

func readJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 256<<10))
	if err := dec.Decode(into); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

// ServeToolCheck decides a client-native tool call. Only refusals are
// recorded here; an allowed call is recorded when its execution is reported,
// so each executed tool is counted once and "allowed" means "ran".
func (g *MCPGateway) ServeToolCheck(w http.ResponseWriter, r *http.Request) {
	userID, agentID, ok := g.agent(w, r)
	if !ok {
		return
	}
	var in ToolCheck
	if !readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Tool) == "" {
		http.Error(w, "tool required", http.StatusBadRequest)
		return
	}
	tool, args := NormalizeTool(in.Tool, in.Input)
	verdict := ToolVerdict{Tool: tool}
	started := time.Now().UTC()
	switch g.decideLocal(agentID, tool, args) {
	case policy.Allow:
		verdict.Decision = "allow"
	case policy.RequireApproval:
		verdict.Decision = "require_approval"
		verdict.Reason = "organization policy requires a human to approve " + tool
		g.record(r, started, userID, agentID, tool, policy.RequireApproval, "error")
	default:
		verdict.Decision = "deny"
		verdict.Reason = "denied by delegated authority or organization policy (" + tool + ")"
		g.record(r, started, userID, agentID, tool, policy.Deny, "error")
	}
	writeJSONBody(w, verdict)
}

// ServeToolReport records that a client-native tool ran.
func (g *MCPGateway) ServeToolReport(w http.ResponseWriter, r *http.Request) {
	userID, agentID, ok := g.agent(w, r)
	if !ok {
		return
	}
	var in ToolReport
	if !readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Tool) == "" {
		http.Error(w, "tool required", http.StatusBadRequest)
		return
	}
	tool, _ := NormalizeTool(in.Tool, nil)
	status := "ok"
	if in.Outcome == "error" {
		status = "error"
	}
	g.record(r, time.Now().UTC(), userID, agentID, tool, policy.Allow, status)
	w.WriteHeader(http.StatusNoContent)
}

// ServeConnectors lists the MCP connectors an agent may use on this edge, so
// `descles connect` can configure a harness without anyone copying URLs.
func (g *MCPGateway) ServeConnectors(w http.ResponseWriter, r *http.Request) {
	_, agentID, ok := g.agent(w, r)
	if !ok {
		return
	}
	var ids []string
	for _, c := range g.Config.Connectors {
		if g.ConnectorPermitted == nil || g.ConnectorPermitted(agentID, c.ID) {
			ids = append(ids, c.ID)
		}
	}
	sort.Strings(ids)
	var ext []string
	for _, e := range g.Extensions {
		if adminOnly, ok := e.(interface{ AdminOnly() bool }); ok && adminOnly.AdminOnly() {
			continue
		}
		ext = append(ext, e.ID())
	}
	sort.Strings(ext)
	ids = append(ext, ids...)
	writeJSONBody(w, map[string]any{"connectors": ids})
}

// decideLocal applies the grant's tool-name ceiling and the organization
// policy. A grant's resource is not applied to local tools: file paths and
// shell commands are governed by the policy's argument rules instead.
func (g *MCPGateway) decideLocal(agentID, tool string, args map[string]any) policy.Decision {
	if g.ToolPermitted != nil && !g.ToolPermitted(agentID, tool) {
		return policy.Deny
	}
	pol := g.Policy.Get()
	if pol == nil {
		return policy.Deny
	}
	group := ""
	if g.GroupOf != nil {
		group = g.GroupOf(agentID)
	}
	switch d := pol.ToolDecisionInArgs(agentID, group, tool, args); d {
	case policy.Allow, policy.RequireApproval:
		return d
	default:
		return policy.Deny
	}
}

func writeJSONBody(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
