package edge

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/storage"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

func llmSpan(id, model string, input int) *tracing.Span {
	now := time.Now().UTC()
	return &tracing.Span{SpanID: tracing.SpanID(id), TraceID: "t", SpanType: tracing.SpanTypeLLM, Status: tracing.StatusOK,
		StartedAt: now, EndedAt: now, Attributes: map[string]any{tracing.AttrModel: model, tracing.AttrProvider: "anthropic", tracing.AttrInputToks: input}}
}

// Review 2026-09-26 #1: one request with a bad field must not take the edge
// down for everyone; a real persistence failure still must.
func TestBadRecordDoesNotStopEdgeButStorageFailureDoes(t *testing.T) {
	ctx := context.Background()
	queue, err := OpenOutbox(filepath.Join(t.TempDir(), "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := &MeteredStore{Storage: storage.NewMemory(), Outbox: queue, EdgeID: "e1", Filter: NewReportFilter([]string{"claude-sonnet-4-5"}, []string{"anthropic"})}

	if err := store.PutSpan(ctx, llmSpan("s1", strings.Repeat("m", 201), 5)); err != nil || !store.Ready() {
		t.Fatalf("an oversized model name must be reported as other, not break metering: %v ready=%v", err, store.Ready())
	}
	if err := store.PutSpan(ctx, llmSpan("s2", "claude-sonnet-4-5", -1)); !errors.Is(err, ErrInvalidMetadata) || !store.Ready() {
		t.Fatalf("an invalid record is that call's error only: %v ready=%v", err, store.Ready())
	}
	if err := store.PutSpan(ctx, llmSpan("s3", "claude-sonnet-4-5", 5)); err != nil || !store.Ready() {
		t.Fatalf("later valid calls must keep working: %v", err)
	}
	if n, _ := queue.Count(ctx); n != 2 {
		t.Fatalf("queued %d, want the two valid records", n)
	}
	_ = queue.Close() // the disk goes away
	if err := store.PutSpan(ctx, llmSpan("s4", "claude-sonnet-4-5", 5)); err == nil || store.Ready() {
		t.Fatal("a persistence failure must stop the edge (no unrecorded execution)")
	}
}

// Review 2026-09-26 #2: a field being "metadata" does not keep content out.
// Client-influenced values leave only if an administrator approved them.
func TestReportedFieldsCarryNoClientText(t *testing.T) {
	f := NewReportFilter([]string{"claude-sonnet-4-5", "gpt-*"}, []string{"anthropic"})
	m := f.Apply(Metadata{Model: "customer-secret-in-model", Provider: "evil-provider"})
	if m.Model != ReportOther || m.Provider != ReportOther {
		t.Fatalf("unapproved values left the edge: %+v", m)
	}
	if m := f.Apply(Metadata{Model: "gpt-acme-merger-plan", Provider: "anthropic"}); m.Model != ReportOther || m.Provider != "anthropic" {
		t.Fatalf("a routing wildcard must not approve reporting: %+v", m)
	}
	if m := f.Apply(Metadata{Model: "claude-sonnet-4-5"}); m.Model != "claude-sonnet-4-5" {
		t.Fatalf("approved model: %+v", m)
	}

	g := &MCPGateway{Config: &MCPConfig{Connectors: []MCPConnector{{ID: "stripe"}}}, Policy: policy.NewHolder(policy.AllowAll())}
	g.filterTools([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_customer"}]}}`), "a", "stripe")
	for in, want := range map[string]string{
		"stripe.get_customer":           "stripe.get_customer",
		"stripe.acme_q3_layoffs_list":   "stripe.other",
		"local.bash":                    "local.bash",
		"local.secret_project_codename": "local.other",
		"mcp.evil.exfil-customer-list":  "mcp.other",
		"unknownconnector.anything":     ReportOther,
	} {
		if got := g.reportableTool(in); got != want {
			t.Errorf("%s reported as %s, want %s", in, got, want)
		}
	}
}

// The same guarantee end to end: an agent-invented MCP tool name is recorded
// locally but reported only as connector.other.
func TestInventedToolNameStaysLocal(t *testing.T) {
	rec := &spanLog{}
	g := &MCPGateway{Config: &MCPConfig{Connectors: []MCPConnector{{ID: "stripe"}}}, Policy: policy.NewHolder(policy.AllowAll()), Spans: rec}
	g.record(httptest.NewRequest("POST", "/mcp/stripe", nil), time.Now(), "u", "a", "stripe.project_nightingale_acquisition", policy.Deny, "error")
	s := rec.spans[0]
	if s.Attributes[attrToolLocal] != "stripe.project_nightingale_acquisition" {
		t.Fatal("local record keeps the requested name")
	}
	if m := FromSpan("e1", s); m.Tool != "stripe.other" || m.Validate() != nil {
		t.Fatalf("reported tool %q", m.Tool)
	}
}

type slowObserver struct{ release chan struct{} }

func (s *slowObserver) Observe(ctx context.Context, _ Observation) {
	select {
	case <-s.release:
	case <-ctx.Done():
	}
}

// Review 2026-09-26 #4: a slow learner must not delay tool responses (a
// client timing out and retrying could repeat the side effect), and pending
// work must stay bounded.
func TestSlowObserverNeitherBlocksResponsesNorQueuesWithoutBound(t *testing.T) {
	slow := &slowObserver{release: make(chan struct{})}
	g := &MCPGateway{Observers: []Observer{slow}, ObserverQueue: 2}
	start := time.Now()
	for i := 0; i < 50; i++ {
		g.observe(context.Background(), "a", "stripe.get_customer", "t", []byte(`{}`))
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("observing blocked the response path for %v", elapsed)
	}
	// One in the worker, two queued, the rest dropped and counted.
	if d := g.ObservationsDropped(); d < 47 || d > 48 {
		t.Fatalf("dropped %d of 50 with a queue of 2", d)
	}
	close(slow.release)
	g.Close(5 * time.Second)
	g.observe(context.Background(), "a", "x.y", "t", nil) // after Close: ignored, no panic
}

// Found in a live Hermes run: a streaming client that disconnects as soon as
// the response ends cancels the request context. The audit record must still
// be written, and the edge must not treat the cancellation as a disk failure.
func TestRecordSurvivesClientDisconnect(t *testing.T) {
	queue, err := OpenOutbox(filepath.Join(t.TempDir(), "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	local, err := storage.NewSQLite(filepath.Join(t.TempDir(), "spans.db"))
	if err != nil {
		t.Fatal(err)
	}
	store := &MeteredStore{Storage: local, Outbox: queue, EdgeID: "e1"}
	defer store.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the client already went away
	if err := store.PutSpan(ctx, llmSpan("gone", "claude-sonnet-4-5", 5)); err != nil || !store.Ready() {
		t.Fatalf("record lost on client disconnect: %v ready=%v", err, store.Ready())
	}
	if n, _ := queue.Count(context.Background()); n != 1 {
		t.Fatalf("metadata queued = %d", n)
	}
	trace, err := local.GetTrace(context.Background(), "t")
	if err != nil || len(trace.Spans) != 1 {
		t.Fatalf("local record: %v %v", trace, err)
	}
}
