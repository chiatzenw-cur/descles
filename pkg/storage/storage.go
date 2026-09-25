// Package storage defines the persistence boundary for Descles spans/traces.
//
// v0 ships an in-memory backend (used by tests and ephemeral runs) and an
// embedded SQLite backend (M1, durable persistence with no external service).
// Postgres is the documented production target — the SQL is portable and a
// driver can be added behind the same Storage interface later.
package storage

import (
	"context"
	"sync"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// SpanFilter narrows a Query; zero-value fields are ignored.
type SpanFilter struct {
	TraceID        string
	SessionID      string
	UserID         string
	AgentID        string
	OrganizationID string
	Model          string
	Provider       string
	Status         string
	From           time.Time
	To             time.Time
	Limit          int
	Offset         int
}

// CostRow is one group of an aggregation over spans.
type CostRow struct {
	Group        string  `json:"group"`
	Requests     int     `json:"requests"`
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	CachedTokens int     `json:"cached_tokens"`
	CostUSD      float64 `json:"cost_usd"`
}

// Storage persists traces and spans and serves the dashboard query views.
type Storage interface {
	PutSpan(ctx context.Context, span *tracing.Span) error
	GetTrace(ctx context.Context, traceID tracing.TraceID) (*tracing.Trace, error)
	ListRecent(ctx context.Context, limit int) ([]*tracing.Span, error)
	Query(ctx context.Context, f SpanFilter) ([]*tracing.Span, error)
	Costs(ctx context.Context, groupBy string, from time.Time, orgID string) ([]CostRow, error)
	Close() error
}

// Options configures the persistence backend.
type Options struct {
	SQLitePath  string
	PostgresDSN string
}

// New returns the storage backend named by kind. Supported: "memory" (default),
// "sqlite", "postgres".
func New(kind string, opts Options) (Storage, error) {
	switch kind {
	case "sqlite":
		return NewSQLite(opts.SQLitePath)
	case "postgres":
		return NewPostgres(opts.PostgresDSN)
	case "memory":
		return NewMemory(), nil
	default:
		return NewMemory(), nil
	}
}

// Memory is a concurrency-safe in-process store.
type Memory struct {
	mu      sync.RWMutex
	all     []*tracing.Span
	byTrace map[tracing.TraceID][]*tracing.Span
}

// NewMemory constructs an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{byTrace: map[tracing.TraceID][]*tracing.Span{}}
}

// PutSpan appends a span in arrival order.
func (m *Memory) PutSpan(_ context.Context, span *tracing.Span) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.all = append(m.all, span)
	m.byTrace[span.TraceID] = append(m.byTrace[span.TraceID], span)
	return nil
}

// GetTrace returns every span recorded for a trace id.
func (m *Memory) GetTrace(_ context.Context, traceID tracing.TraceID) (*tracing.Trace, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	spans := m.byTrace[traceID]
	cp := make([]*tracing.Span, len(spans))
	copy(cp, spans)
	return &tracing.Trace{TraceID: traceID, Spans: cp}, nil
}

// ListRecent returns the most recent `limit` spans, newest first.
func (m *Memory) ListRecent(_ context.Context, limit int) ([]*tracing.Span, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > len(m.all) {
		limit = len(m.all)
	}
	start := len(m.all) - limit
	cp := make([]*tracing.Span, limit)
	copy(cp, m.all[start:])
	// Newest first (matches the SQL backend).
	for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
		cp[i], cp[j] = cp[j], cp[i]
	}
	return cp, nil
}

// Query returns spans matching f, newest first, with offset/limit applied.
func (m *Memory) Query(_ context.Context, f SpanFilter) ([]*tracing.Span, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*tracing.Span, 0)
	for _, s := range m.all {
		if matchesFilter(s, f) {
			out = append(out, s)
		}
	}
	// Newest first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return paginate(out, f.Offset, f.Limit), nil
}

// Costs aggregates matching spans (since `from`) by groupBy, scoped to orgID.
func (m *Memory) Costs(ctx context.Context, groupBy string, from time.Time, orgID string) ([]CostRow, error) {
	spans, err := m.Query(ctx, SpanFilter{From: from, OrganizationID: orgID})
	if err != nil {
		return nil, err
	}
	return AggregateCosts(spans, groupBy), nil
}

// Close is a no-op for memory.
func (m *Memory) Close() error { return nil }

func matchesFilter(s *tracing.Span, f SpanFilter) bool {
	if f.TraceID != "" && string(s.TraceID) != f.TraceID {
		return false
	}
	if f.SessionID != "" && s.SessionID != f.SessionID {
		return false
	}
	if f.Status != "" && s.Status != f.Status {
		return false
	}
	if f.UserID != "" && s.UserID != f.UserID {
		return false
	}
	if f.AgentID != "" && s.AgentID != f.AgentID {
		return false
	}
	if f.OrganizationID != "" && s.OrganizationID != f.OrganizationID {
		return false
	}
	if f.Model != "" && strAttr(s, tracing.AttrModel) != f.Model {
		return false
	}
	if f.Provider != "" && strAttr(s, tracing.AttrProvider) != f.Provider {
		return false
	}
	if !f.From.IsZero() && s.StartedAt.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && s.StartedAt.After(f.To) {
		return false
	}
	return true
}

func paginate(in []*tracing.Span, offset, limit int) []*tracing.Span {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(in) {
		return []*tracing.Span{}
	}
	in = in[offset:]
	if limit > 0 && limit < len(in) {
		in = in[:limit]
	}
	return in
}

func strAttr(s *tracing.Span, key string) string {
	if v, ok := s.Attributes[key].(string); ok {
		return v
	}
	return ""
}
