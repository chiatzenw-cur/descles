package edge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// Metadata is the strict wire contract for customer-side metering. It has no
// prompt, completion, tool arguments, upstream URL, or arbitrary attributes.
type Metadata struct {
	EdgeID       string    `json:"edge_id"`
	SpanID       string    `json:"span_id"`
	TraceID      string    `json:"trace_id"`
	Kind         string    `json:"kind,omitempty"` // "" (model call) or "tool"
	Tool         string    `json:"tool,omitempty"` // connector.tool name, never its arguments
	AgentID      string    `json:"agent_id,omitempty"`
	UserID       string    `json:"user_id,omitempty"`
	Model        string    `json:"model,omitempty"`
	Provider     string    `json:"provider,omitempty"`
	Status       string    `json:"status"`
	Policy       string    `json:"policy_decision,omitempty"`
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
	CachedTokens int       `json:"cached_tokens"`
	UsageKnown   bool      `json:"usage_known"`
	ToolCalls    int       `json:"tool_calls_requested"`
	CostUSD      float64   `json:"cost_usd"`
	CostSource   string    `json:"cost_source,omitempty"`
	StartedAt    time.Time `json:"started_at"`
	EndedAt      time.Time `json:"ended_at"`
}

func FromSpan(edgeID string, span *tracing.Span) Metadata {
	if span.SpanType == tracing.SpanTypeTool {
		agentID := span.AgentID
		if strings.HasPrefix(agentID, "system:") {
			// Edge background work (SystemCall) is not an agent of the
			// organization; report it unattributed. The local record keeps it.
			agentID = ""
		}
		return Metadata{
			EdgeID: edgeID, SpanID: string(span.SpanID), TraceID: pseudonym(string(span.TraceID)), Kind: "tool",
			Tool: stringAttr(span, tracing.AttrTool), AgentID: agentID, UserID: span.UserID,
			Status: span.Status, Policy: stringAttr(span, tracing.AttrPolicy),
			StartedAt: span.StartedAt, EndedAt: span.EndedAt,
		}
	}
	return Metadata{
		EdgeID: edgeID, SpanID: string(span.SpanID), TraceID: pseudonym(string(span.TraceID)),
		AgentID: span.AgentID, UserID: span.UserID, Model: stringAttr(span, tracing.AttrModel),
		Provider: stringAttr(span, tracing.AttrProvider), Status: span.Status,
		Policy: stringAttr(span, tracing.AttrPolicy), InputTokens: intAttr(span, tracing.AttrInputToks),
		OutputTokens: intAttr(span, tracing.AttrOutputToks), CachedTokens: intAttr(span, tracing.AttrCachedToks),
		UsageKnown: intAttr(span, tracing.AttrInputToks)+intAttr(span, tracing.AttrOutputToks)+intAttr(span, tracing.AttrCachedToks) > 0 || span.Status == tracing.StatusCancelled,
		ToolCalls:  intAttr(span, tracing.AttrToolCalls), CostUSD: floatAttr(span, tracing.AttrCostUSD),
		CostSource: stringAttr(span, tracing.AttrCostSource), StartedAt: span.StartedAt, EndedAt: span.EndedAt,
	}
}

func (m Metadata) Validate() error {
	if !validID(m.EdgeID) || !validID(m.SpanID) || !validID(m.TraceID) || m.StartedAt.IsZero() || m.EndedAt.IsZero() {
		return fmt.Errorf("missing edge, span, trace or time")
	}
	if len(m.EdgeID) > 120 || len(m.SpanID) > 120 || len(m.TraceID) > 120 || len(m.AgentID) > 120 || len(m.UserID) > 120 || len(m.Model) > 200 || len(m.Provider) > 120 || len(m.CostSource) > 80 {
		return fmt.Errorf("metadata field too long")
	}
	if m.InputTokens < 0 || m.OutputTokens < 0 || m.CachedTokens < 0 || m.ToolCalls < 0 || m.CostUSD < 0 || m.CostUSD > 1_000_000 || math.IsNaN(m.CostUSD) || math.IsInf(m.CostUSD, 0) {
		return fmt.Errorf("invalid usage or cost")
	}
	if !m.UsageKnown && (m.InputTokens != 0 || m.OutputTokens != 0 || m.CachedTokens != 0) {
		return fmt.Errorf("token counts require usage_known")
	}
	if m.EndedAt.Before(m.StartedAt) || m.EndedAt.After(time.Now().Add(5*time.Minute)) {
		return fmt.Errorf("invalid time range")
	}
	switch m.Kind {
	case "":
		if m.Tool != "" {
			return fmt.Errorf("tool name only on tool metadata")
		}
	case "tool":
		if !validToolName(m.Tool) || m.Model != "" || m.Provider != "" || m.UsageKnown || m.ToolCalls != 0 || m.CostUSD != 0 {
			return fmt.Errorf("invalid tool metadata")
		}
	default:
		return fmt.Errorf("invalid metadata kind")
	}
	if !validLabel(m.Status, "ok", "error", "cancelled") || !validLabel(m.Policy, "", "allow", "deny", "require_approval", "rate_limit") {
		return fmt.Errorf("invalid status or policy")
	}
	return nil
}

func validID(id string) bool {
	if id == "" || len(id) > 120 {
		return false
	}
	for _, char := range id {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func ValidEdgeID(id string) bool { return validID(id) }

// validToolName admits connector.tool identifiers only: a free-form field here
// would be a channel for content to leave the customer's network.
func validToolName(name string) bool {
	if name == "" || len(name) > 160 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validLabel(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func stringAttr(span *tracing.Span, key string) string {
	if v, ok := span.Attributes[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func intAttr(span *tracing.Span, key string) int {
	switch v := span.Attributes[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

func floatAttr(span *tracing.Span, key string) float64 {
	switch v := span.Attributes[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	}
	return 0
}

// pseudonym replaces a trace id before it leaves the edge. Trace ids often
// come from the client (a Claude Code session id, a caller's request id) and
// could be joined with records elsewhere; the control plane only needs a
// stable grouping key, so it gets a one-way hash. Local records keep the
// original for the customer's own use.
func pseudonym(traceID string) string {
	if traceID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("descles-trace\x00" + traceID))
	return "t" + hex.EncodeToString(sum[:16])
}
