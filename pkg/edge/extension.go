package edge

import (
	"context"
	"errors"
)

// Extensions add capabilities to the edge without changing what the edge is:
// they run in the edge process, are reached only through the edge's own
// authentication, policy and metering, and see nothing the edge does not
// hand them. The open-core edge ships with none.
//
// An Extension is served as an MCP connector at POST /mcp/<ID>. Its access
// control is its own (for example, label clearances); organization policy
// still applies to each tool as "<ID>.<tool>".
type Extension interface {
	ID() string
	Instructions() string
	Tools() []ExtensionTool
	// Call runs one tool for caller. Return ErrNotFound for anything the
	// caller may not know exists; other errors are shown to the agent.
	Call(ctx context.Context, caller Caller, tool string, args map[string]any) (any, error)
}

// ExtensionTool is an MCP tool definition.
type ExtensionTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Caller is the authenticated agent an extension acts for. Clearances come
// from the signed bundle and the edge's local config, never from the agent.
type Caller struct {
	AgentID    string
	UserID     string
	Clearances []string
}

// Observer receives successful governed tool results, on the edge, from one
// background worker fed by a bounded queue, so it never delays the agent's
// response. Delivery is best effort: a full queue drops (and counts)
// observations, and pending ones are drained for a bounded time at shutdown.
// An observer that must not lose data needs its own durable queue.
type Observer interface {
	Observe(ctx context.Context, obs Observation)
}

// Observation is one successful MCP tool call.
type Observation struct {
	Tool    string // connector.tool
	AgentID string
	TraceID string
	Result  []byte // the upstream JSON-RPC response
}

// ErrNotFound lets an extension hide existence from a caller.
var ErrNotFound = errors.New("not found")
