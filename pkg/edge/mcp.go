package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/chiatzenw-cur/descles/pkg/mcpwire"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// OrgConnectorID is reserved for the organization-context extension, so a
// configured connector can never shadow it.
const OrgConnectorID = "org"

// MCPConnector is one upstream MCP server reachable from this edge. Its
// credential is read from a local file and never reported anywhere.
type MCPConnector struct {
	ID           string `yaml:"id"`
	URL          string `yaml:"url"`
	TokenFile    string `yaml:"token_file,omitempty"`
	InsecureHTTP bool   `yaml:"insecure_http,omitempty"` // plain HTTP inside the customer network
	token        string
}

// MCPConfig is the edge administrator's local MCP and context configuration.
type MCPConfig struct {
	Connectors []MCPConnector `yaml:"connectors"`
	// Clearances are the organization-context labels each agent (by id) or
	// group may read. They add to any labels the signed bundle grants.
	Clearances struct {
		Agents map[string][]string `yaml:"agents,omitempty"`
		Groups map[string][]string `yaml:"groups,omitempty"`
	} `yaml:"clearances"`
}

var connectorIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)

// LoadMCPConfig reads the config and every connector token file. A connector
// whose token cannot be read fails startup instead of running unauthenticated.
func LoadMCPConfig(file string) (*MCPConfig, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var cfg MCPConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("edge MCP config: %w", err)
	}
	seen := map[string]bool{}
	for i := range cfg.Connectors {
		c := &cfg.Connectors[i]
		if !connectorIDPattern.MatchString(c.ID) || c.ID == OrgConnectorID || seen[c.ID] {
			return nil, fmt.Errorf("connector %q: id must be unique lowercase letters, digits or '-' and not %q", c.ID, OrgConnectorID)
		}
		seen[c.ID] = true
		u, err := url.Parse(c.URL)
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(u.Scheme == "http" && c.InsecureHTTP)) {
			return nil, fmt.Errorf("connector %q: url must be https (or http with insecure_http inside your network)", c.ID)
		}
		if c.TokenFile != "" {
			raw, err := os.ReadFile(c.TokenFile)
			if err != nil {
				return nil, fmt.Errorf("connector %q token: %w", c.ID, err)
			}
			c.token = strings.TrimSpace(string(raw))
		}
	}
	return &cfg, nil
}

// MCPGateway governs MCP tool calls on the customer side: authenticate the
// agent key, check delegated grants and organization policy, execute with a
// locally held credential, record metadata, and learn from the result.
// attrToolLocal keeps the tool name as the client sent it, for the local
// record only; the reported name (tracing.AttrTool) is canonical.
const attrToolLocal = "tool_local"

type MCPGateway struct {
	catalogMu sync.Mutex

	ObserverQueue int // pending-observation bound; 0 means 1000
	obsOnce       sync.Once
	obsMu         sync.RWMutex
	obsClosed     bool
	obsCh         chan Observation
	obsDone       chan struct{}
	obsDropped    atomic.Int64
	tools         map[string]map[string]bool // connector -> tool names the upstream listed

	Config        *MCPConfig
	Resolve       func(key string) (orgID, userID, agentID string, ok bool)
	GroupOf       func(agentID string) string
	ToolAllowed   func(agentID, tool string, args map[string]any) bool // nil: no delegated ceiling (local mode)
	ToolPermitted func(agentID, tool string) bool                      // grant covers the tool name at all
	// ConnectorPermitted reports whether any tool of a connector is granted.
	ConnectorPermitted func(agentID, connector string) bool
	BundleLabel        func(agentID string) []string // context clearances from the signed bundle
	Policy             *policy.Holder
	Spans              interface {
		PutSpan(context.Context, *tracing.Span) error
	}
	Extensions []Extension // served at /mcp/<id>; none in the open-core edge
	Observers  []Observer  // see successful tool results, on the edge
	Client     *http.Client
	Logger     *slog.Logger
}

type rpcCall struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Method  string `json:"method"`
	Params  struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"params"`
}

func (g *MCPGateway) connector(id string) (MCPConnector, bool) {
	for _, c := range g.Config.Connectors {
		if c.ID == id {
			return c, true
		}
	}
	return MCPConnector{}, false
}

func (g *MCPGateway) extension(id string) Extension {
	for _, e := range g.Extensions {
		if e.ID() == id {
			return e
		}
	}
	return nil
}

// Clearances are the context labels an agent holds: the signed bundle's plus
// the edge's local config for the agent and its group.
func (g *MCPGateway) Clearances(agentID string) []string {
	var labels []string
	if g.BundleLabel != nil {
		labels = append(labels, g.BundleLabel(agentID)...)
	}
	if g.Config != nil {
		labels = append(labels, g.Config.Clearances.Agents[agentID]...)
		if g.GroupOf != nil {
			if group := g.GroupOf(agentID); group != "" {
				labels = append(labels, g.Config.Clearances.Groups[group]...)
			}
		}
	}
	return labels
}

func (g *MCPGateway) decide(agentID, connectorID, tool string, args map[string]any) policy.Decision {
	full := connectorID + "." + tool
	// Extensions enforce their own access control (e.g. clearances); every
	// upstream tool must sit under the agent's delegated resource ceiling.
	if g.extension(connectorID) == nil && g.ToolAllowed != nil && !g.ToolAllowed(agentID, full, args) {
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
	switch d := pol.ToolDecisionInArgs(agentID, group, full, args); d {
	case policy.Allow, policy.RequireApproval:
		return d
	default:
		return policy.Deny
	}
}

func (g *MCPGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "MCP POST required", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	_, userID, agentID, ok := g.Resolve(token)
	if !ok || agentID == "" {
		http.Error(w, "agent key required", http.StatusUnauthorized)
		return
	}
	connectorID := r.PathValue("connector")
	upstream, known := g.connector(connectorID)
	ext := g.extension(connectorID)
	if ext == nil && !known {
		http.Error(w, "unknown connector", http.StatusNotFound)
		return
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(buf) > 1<<20 {
		http.Error(w, "MCP request too large", http.StatusRequestEntityTooLarge)
		return
	}
	if buf, err = mcpwire.CanonicalRequest(buf); err != nil {
		writeRPC(w, http.StatusBadRequest, rpcError(nil, -32600, "ambiguous or invalid JSON-RPC request: "+err.Error()))
		return
	}
	var call rpcCall
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.UseNumber()
	if dec.Decode(&call) != nil || call.JSONRPC != "2.0" || call.Method == "" {
		writeRPC(w, http.StatusBadRequest, rpcError(nil, -32600, "invalid JSON-RPC request"))
		return
	}
	switch call.Method {
	case "initialize", "tools/list", "tools/call", "ping", "notifications/initialized":
	default:
		writeRPC(w, http.StatusOK, rpcError(call.ID, -32601, "MCP method is not enabled on this connector"))
		return
	}
	if ext != nil {
		g.serveExtension(w, r, ext, call, userID, agentID)
		return
	}
	started := time.Now().UTC()
	if call.Method == "tools/call" {
		if call.Params.Name == "" {
			writeRPC(w, http.StatusBadRequest, rpcError(call.ID, -32602, "tool name required"))
			return
		}
		if msg, allowed := g.gate(r, started, userID, agentID, connectorID, call); !allowed {
			writeRPC(w, http.StatusOK, toolText(call.ID, msg, true))
			return
		}
	}
	body, status, headers, err := g.forward(r.Context(), upstream, buf, call, r.Header)
	if err != nil {
		if call.Method == "tools/call" {
			// The upstream may or may not have acted: record it as an error,
			// never retry it silently.
			g.record(r, started, userID, agentID, connectorID+"."+call.Params.Name, policy.Allow, "error")
		}
		writeRPC(w, http.StatusBadGateway, rpcError(call.ID, -32000, "upstream unavailable: "+err.Error()))
		return
	}
	if sid := headers.Get("Mcp-Session-Id"); sid != "" {
		w.Header().Set("Mcp-Session-Id", sid)
	}
	switch call.Method {
	case "tools/list":
		if status == http.StatusOK {
			body = g.filterTools(body, agentID, connectorID)
		}
	case "tools/call":
		outcome := "ok"
		if status < 200 || status >= 300 || rpcFailed(body) {
			outcome = "error"
		}
		g.record(r, started, userID, agentID, connectorID+"."+call.Params.Name, policy.Allow, outcome)
		if outcome == "ok" {
			g.observe(r.Context(), agentID, connectorID+"."+call.Params.Name, r.Header.Get("X-Descles-Trace-Id"), body)
		}
	}
	writeRPC(w, status, body)
}

// gate applies grants and policy to one tool call, recording refusals.
func (g *MCPGateway) gate(r *http.Request, started time.Time, userID, agentID, connectorID string, call rpcCall) (string, bool) {
	full := connectorID + "." + call.Params.Name
	switch g.decide(agentID, connectorID, call.Params.Name, call.Params.Arguments) {
	case policy.Allow:
		return "", true
	case policy.RequireApproval:
		// Approvals are not bridged to the edge yet. Fail closed: a call that
		// needs a human must not run because the human is out of reach.
		g.record(r, started, userID, agentID, full, policy.RequireApproval, "error")
		return "Human approval required for " + full + ". Approvals are not yet available on this edge, so the call was not executed.", false
	default:
		g.record(r, started, userID, agentID, full, policy.Deny, "error")
		return "Denied by delegated authority or organization policy", false
	}
}

func (g *MCPGateway) serveExtension(w http.ResponseWriter, r *http.Request, ext Extension, call rpcCall, userID, agentID string) {
	id := ext.ID()
	switch call.Method {
	case "initialize":
		writeRPC(w, http.StatusOK, rpcResult(call.ID, map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "descles-" + id, "version": "1"},
			"instructions":    ext.Instructions(),
		}))
	case "ping":
		writeRPC(w, http.StatusOK, rpcResult(call.ID, map[string]any{}))
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		tools := []ExtensionTool{}
		for _, t := range ext.Tools() {
			if g.decide(agentID, id, t.Name, nil) != policy.Deny {
				tools = append(tools, t)
			}
		}
		writeRPC(w, http.StatusOK, rpcResult(call.ID, map[string]any{"tools": tools}))
	case "tools/call":
		started := time.Now().UTC()
		if msg, allowed := g.gate(r, started, userID, agentID, id, call); !allowed {
			writeRPC(w, http.StatusOK, toolText(call.ID, msg, true))
			return
		}
		args := call.Params.Arguments
		if args == nil {
			args = map[string]any{}
		}
		caller := Caller{AgentID: agentID, UserID: userID, Clearances: g.Clearances(agentID)}
		out, err := ext.Call(r.Context(), caller, call.Params.Name, normalizeNumbers(args).(map[string]any))
		full := id + "." + call.Params.Name
		if err != nil {
			g.record(r, started, userID, agentID, full, policy.Allow, "error")
			msg := err.Error()
			if errors.Is(err, ErrNotFound) {
				msg = "not found"
			}
			writeRPC(w, http.StatusOK, toolText(call.ID, msg, true))
			return
		}
		g.record(r, started, userID, agentID, full, policy.Allow, "ok")
		text, ok := out.(string)
		if !ok {
			b, _ := json.MarshalIndent(out, "", "  ")
			text = string(b)
		}
		writeRPC(w, http.StatusOK, toolText(call.ID, text, false))
	}
}

// normalizeNumbers turns json.Number (from the canonical decoder) into
// float64 so tool arguments look like ordinary decoded JSON.
func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case json.Number:
		f, _ := t.Float64()
		return f
	case map[string]any:
		for k, x := range t {
			t[k] = normalizeNumbers(x)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = normalizeNumbers(x)
		}
		return t
	}
	return v
}

// observe hands a successful result to the observers without delaying the
// agent's response: a bounded queue drained by one background worker. When
// the queue is full the observation is dropped and counted; the tool call
// itself has already happened and is recorded either way. Observers are
// best-effort learners, not part of the execution record.
func (g *MCPGateway) observe(_ context.Context, agentID, tool, traceID string, body []byte) {
	if len(g.Observers) == 0 {
		return
	}
	g.obsOnce.Do(g.startObservers)
	g.obsMu.RLock()
	defer g.obsMu.RUnlock()
	if g.obsClosed {
		return
	}
	select {
	case g.obsCh <- Observation{Tool: tool, AgentID: agentID, TraceID: traceID, Result: body}:
	default:
		if n := g.obsDropped.Add(1); g.Logger != nil && (n == 1 || n%100 == 0) {
			g.Logger.Warn("observer queue full; observation dropped", "tool", g.reportableTool(tool), "dropped_total", n)
		}
	}
}

// defaultObserverQueue bounds pending observations when ObserverQueue is 0.
const defaultObserverQueue = 1000

func (g *MCPGateway) startObservers() {
	size := g.ObserverQueue
	if size <= 0 {
		size = defaultObserverQueue
	}
	g.obsCh = make(chan Observation, size)
	g.obsDone = make(chan struct{})
	go func() {
		defer close(g.obsDone)
		for obs := range g.obsCh {
			for _, o := range g.Observers {
				// Independent of the request: the agent may be long gone.
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				o.Observe(ctx, obs)
				cancel()
			}
		}
	}()
}

// Close stops accepting observations and waits (up to timeout) for queued
// ones to finish, so observers can close their stores safely afterwards.
func (g *MCPGateway) Close(timeout time.Duration) {
	g.obsMu.Lock()
	started := g.obsCh != nil && !g.obsClosed
	g.obsClosed = true
	if started {
		close(g.obsCh)
	}
	g.obsMu.Unlock()
	if !started {
		return
	}
	select {
	case <-g.obsDone:
	case <-time.After(timeout):
		if g.Logger != nil {
			g.Logger.Warn("observers did not drain before shutdown", "pending", len(g.obsCh))
		}
	}
}

// ObservationsDropped reports observations lost to a full queue.
func (g *MCPGateway) ObservationsDropped() int64 { return g.obsDropped.Load() }

// record writes one tool span locally; the metered store also queues its
// metadata (tool name, decision, outcome; never arguments) for the control
// plane.
func (g *MCPGateway) record(r *http.Request, started time.Time, userID, agentID, tool string, decision policy.Decision, status string) {
	if g.Spans == nil {
		return
	}
	traceID := tracing.TraceID(r.Header.Get("X-Descles-Trace-Id"))
	if !validID(string(traceID)) {
		traceID = tracing.NewTraceID()
	}
	span := &tracing.Span{
		SpanID: tracing.NewSpanID(), TraceID: traceID, SpanType: tracing.SpanTypeTool,
		StartedAt: started, EndedAt: time.Now().UTC(), ActorType: "agent", ActorID: agentID,
		AgentID: agentID, UserID: userID, Status: status,
		Attributes: map[string]any{tracing.AttrTool: g.reportableTool(tool), tracing.AttrPolicy: string(decision), attrToolLocal: truncate(tool, 200)},
	}
	if err := g.Spans.PutSpan(r.Context(), span); err != nil && g.Logger != nil {
		g.Logger.Error("tool call metering failed", "tool", g.reportableTool(tool), "err", err)
	}
}

func (g *MCPGateway) forward(ctx context.Context, c MCPConnector, body []byte, call rpcCall, in http.Header) ([]byte, int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for _, h := range []string{"MCP-Protocol-Version", "Mcp-Session-Id"} {
		if v := in.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set("Mcp-Method", call.Method)
	if call.Params.Name != "" {
		req.Header.Set("Mcp-Name", call.Params.Name)
	}
	client := g.Client
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("MCP upstream redirects refused") }}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return nil, 0, nil, err
	}
	if len(data) > 1<<20 {
		return nil, 0, nil, errors.New("upstream MCP response too large")
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		if data, err = mcpwire.DecodeSSE(data); err != nil {
			return nil, 0, nil, err
		}
	}
	if len(data) > 0 && !json.Valid(data) {
		return nil, 0, nil, errors.New("upstream returned non-JSON MCP response")
	}
	return data, resp.StatusCode, resp.Header, nil
}

// filterTools hides tools the agent could never call.
func (g *MCPGateway) filterTools(body []byte, agentID, connectorID string) []byte {
	var v map[string]any
	if json.Unmarshal(body, &v) != nil {
		return body
	}
	result, _ := v["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	if tools == nil {
		return body
	}
	out := []any{}
	for _, item := range tools {
		m, _ := item.(map[string]any)
		name, _ := m["name"].(string)
		if name == "" {
			continue
		}
		g.catalog(connectorID, name)
		// Argument-scoped rules cannot be judged without arguments, so only
		// tools denied outright are hidden; every call is re-checked anyway.
		if g.neverAllowed(agentID, connectorID+"."+name) {
			continue
		}
		out = append(out, item)
	}
	result["tools"] = out
	b, err := json.Marshal(v)
	if err != nil {
		return body
	}
	return b
}

func (g *MCPGateway) neverAllowed(agentID, tool string) bool {
	if g.ToolPermitted != nil && !g.ToolPermitted(agentID, tool) {
		return true
	}
	return g.policyDeniesAlways(agentID, tool)
}

func (g *MCPGateway) policyDeniesAlways(agentID, tool string) bool {
	pol := g.Policy.Get()
	if pol == nil {
		return true
	}
	group := ""
	if g.GroupOf != nil {
		group = g.GroupOf(agentID)
	}
	return pol.ToolDecisionIn(agentID, group, tool) == policy.Deny && !pol.HasArgRulesFor(agentID, group, tool)
}

// rpcFailed reports a JSON-RPC error or an MCP tool result flagged isError.
func rpcFailed(body []byte) bool {
	var msg struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &msg) != nil {
		return true
	}
	return len(msg.Error) > 0 && string(msg.Error) != "null" || msg.Result.IsError
}

func writeRPC(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func rpcError(id any, code int, message string) []byte {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
	return b
}

func rpcResult(id any, result any) []byte {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	return b
}

func toolText(id any, text string, isError bool) []byte {
	return rpcResult(id, map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "isError": isError})
}

// catalog remembers a tool name an upstream MCP server declared in tools/list.
// Declared names come from the customer's own server, not from the agent, so
// they may be reported; names an agent invents are not.
func (g *MCPGateway) catalog(connectorID, tool string) {
	if !validToolName(connectorID + "." + tool) {
		return
	}
	g.catalogMu.Lock()
	defer g.catalogMu.Unlock()
	if g.tools == nil {
		g.tools = map[string]map[string]bool{}
	}
	if g.tools[connectorID] == nil {
		g.tools[connectorID] = map[string]bool{}
	}
	if len(g.tools[connectorID]) < 1000 {
		g.tools[connectorID][tool] = true
	}
}

// reportableTool maps a tool name to one that may leave the edge: an
// extension's own tool, a tool the upstream declared, or one of the
// normalized local tool classes. Anything else becomes "<connector>.other".
func (g *MCPGateway) reportableTool(full string) string {
	prefix, name, ok := strings.Cut(full, ".")
	if !ok {
		return ReportOther
	}
	switch prefix {
	case "local":
		switch name {
		case "bash", "write", "read", "web":
			return full
		}
		return "local.other"
	case "mcp":
		return "mcp.other"
	}
	if ext := g.extension(prefix); ext != nil {
		for _, t := range ext.Tools() {
			if t.Name == name && validToolName(full) {
				return full
			}
		}
		return prefix + ".other"
	}
	if _, known := g.connector(prefix); !known {
		return ReportOther
	}
	g.catalogMu.Lock()
	declared := g.tools[prefix][name]
	g.catalogMu.Unlock()
	if declared {
		return full
	}
	return prefix + ".other"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
