package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// SystemCaller runs a tool call on the edge's own authority, for background
// work the edge administrator configured locally (for example, syncing a
// source system into organization context). It is not an agent: delegated
// grants do not apply, but organization policy does, every call is recorded
// under the principal, and a call that needs a person's approval is refused,
// since nobody is there to approve it.
type SystemCaller interface {
	SystemCall(ctx context.Context, principal, tool string, args map[string]any) (json.RawMessage, error)
}

// SystemStarter is implemented by an extension or observer that runs
// background work on the edge. Start is called once, after the gateway is
// ready, and must return when ctx ends; the edge waits for it before closing
// plugin stores.
type SystemStarter interface {
	Start(ctx context.Context, sys SystemCaller)
}

// ErrSystemCallRefused is returned when policy does not allow a system call.
var ErrSystemCallRefused = errors.New("refused by organization policy")

// SystemCall implements SystemCaller for tools of configured connectors.
func (g *MCPGateway) SystemCall(ctx context.Context, principal, tool string, args map[string]any) (json.RawMessage, error) {
	if !strings.HasPrefix(principal, "system:") || !validID(strings.TrimPrefix(principal, "system:")) {
		return nil, fmt.Errorf("system principal must be system:<name>, not %q", principal)
	}
	connectorID, name, ok := strings.Cut(tool, ".")
	if !ok || name == "" {
		return nil, fmt.Errorf("tool %q is not connector.tool", tool)
	}
	upstream, known := g.connector(connectorID)
	if !known {
		return nil, fmt.Errorf("unknown connector %q", connectorID)
	}
	if args == nil {
		args = map[string]any{}
	}
	started := time.Now().UTC()
	trace := string(tracing.NewTraceID())
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://edge.local/system", nil)
	req.Header.Set("X-Descles-Trace", trace)

	decision := policy.Deny
	if pol := g.Policy.Get(); pol != nil {
		decision = pol.ToolDecisionInArgs(principal, "", tool, args)
	}
	if decision != policy.Allow {
		g.record(req, started, "", principal, tool, decision, "error")
		return nil, fmt.Errorf("%s: %w (%s)", tool, ErrSystemCallRefused, decision)
	}
	g.catalogOnce(ctx, upstream)

	call := rpcCall{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	call.Params.Name, call.Params.Arguments = name, args
	body, _ := json.Marshal(call)
	data, status, _, err := g.forward(ctx, upstream, body, call, http.Header{})
	outcome := "ok"
	if err != nil || status < 200 || status >= 300 || rpcFailed(data) {
		outcome = "error"
	}
	g.record(req, started, "", principal, tool, policy.Allow, outcome)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%s: %w", tool, err)
	case outcome == "error":
		return nil, fmt.Errorf("%s: upstream returned an error (HTTP %d): %s", tool, status, truncate(string(data), 300))
	}
	return data, nil
}

// catalogOnce lists a connector's tools once, so system calls are recorded
// under the names the customer's server declared (as agent calls are after
// an agent lists tools) rather than as <connector>.other.
func (g *MCPGateway) catalogOnce(ctx context.Context, c MCPConnector) {
	g.catalogMu.Lock()
	done := len(g.tools[c.ID]) > 0
	g.catalogMu.Unlock()
	if done {
		return
	}
	call := rpcCall{JSONRPC: "2.0", ID: 1, Method: "tools/list"}
	body, _ := json.Marshal(call)
	data, status, _, err := g.forward(ctx, c, body, call, http.Header{})
	if err != nil || status != http.StatusOK {
		return
	}
	var res struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &res) != nil {
		return
	}
	for _, t := range res.Result.Tools {
		g.catalog(c.ID, t.Name)
	}
}
