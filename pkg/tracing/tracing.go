// Package tracing defines the generic trace/span model that Descles uses for
// every observable unit of work.
//
// The model is deliberately OpenTelemetry-compatible in spirit — a Trace
// holds Spans, each with trace_id / span_id / parent_span_id, attributes and
// events — without being a full OTel implementation. v0 only needs spans for
// LLM calls; tool spans (and parent/child relationships) come with the MCP
// gateway milestone.
package tracing

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// SpanID is a 16-hex-digit identifier (8 random bytes), matching OTel width.
type SpanID string

// TraceID is a 32-hex-digit identifier (16 random bytes), matching OTel width.
type TraceID string

// ParentSpanID references the enclosing span; empty for a root span.
type ParentSpanID string

// Span types.
const (
	SpanTypeLLM  = "llm.call"
	SpanTypeTool = "tool.call"
)

// Span statuses.
const (
	StatusOK        = "ok"
	StatusError     = "error"
	StatusCancelled = "cancelled"
)

// Attribute keys used across Descles spans.
const (
	AttrProvider   = "provider"
	AttrModel      = "model"
	AttrInputToks  = "input_tokens"
	AttrOutputToks = "output_tokens"
	AttrCachedToks = "cached_tokens"
	AttrCostUSD    = "cost_usd"
	// AttrCostSource names where the price came from: a tenant override table,
	// the built-in list, or the generic fallback for an unknown model.
	AttrCostSource = "cost_source"
	AttrLatencyMS  = "latency_ms"
	AttrToolCalls  = "tool_calls_requested"
	AttrPolicy     = "policy_decision"
	AttrTool       = "tool_name" // connector.tool for governed tool calls
	AttrPlaybook   = "playbook_version"
	AttrErrorType  = "error_type"
)

// Span is a single named unit of work within a trace.
type Span struct {
	SpanID       SpanID       `json:"span_id"`
	TraceID      TraceID      `json:"trace_id"`
	ParentSpanID ParentSpanID `json:"parent_span_id,omitempty"`
	SpanType     string       `json:"span_type"`
	StartedAt    time.Time    `json:"started_at"`
	EndedAt      time.Time    `json:"ended_at"`
	ActorType    string       `json:"actor_type,omitempty"`
	ActorID      string       `json:"actor_id,omitempty"`
	// UserID and AgentID capture both attribution dimensions explicitly (a
	// task is triggered by a user and executed by an agent).
	UserID  string `json:"user_id,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
	// SessionID / OrganizationID / ProjectID carry the client-supplied
	// attribution (X-Descles-* headers) so the dashboard can pivot on it.
	SessionID      string         `json:"session_id,omitempty"`
	OrganizationID string         `json:"organization_id,omitempty"`
	ProjectID      string         `json:"project_id,omitempty"`
	ResourceType   string         `json:"resource_type,omitempty"`
	ResourceID     string         `json:"resource_id,omitempty"`
	Status         string         `json:"status"`
	ErrorType      string         `json:"error_type,omitempty"`
	Attributes     map[string]any `json:"attributes,omitempty"`

	// Events records notable sub-events (OTel Event concept).
	Events []Event `json:"events,omitempty"`
}

// Event is a timestamped annotation on a span.
type Event struct {
	Name       string         `json:"name"`
	Time       time.Time      `json:"time"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Trace groups spans by trace_id.
type Trace struct {
	TraceID TraceID `json:"trace_id"`
	Spans   []*Span `json:"spans"`
}

// NewTraceID returns a fresh 16-byte OTel-width trace id.
func NewTraceID() TraceID { return TraceID(RandHex(16)) }

// NewSpanID returns a fresh 8-byte OTel-width span id.
func NewSpanID() SpanID { return SpanID(RandHex(8)) }

// RandHex returns n random bytes hex-encoded (2n characters).
func RandHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms; panic is safest.
		panic(err)
	}
	return hex.EncodeToString(b)
}
