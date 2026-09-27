package storage_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/storage"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

func mkSpan(trace, spanID, actorType, actorID, model string, in, out int, cost float64, status string) *tracing.Span {
	now := time.Now().UTC()
	s := &tracing.Span{
		SpanID:       tracing.SpanID(spanID),
		TraceID:      tracing.TraceID(trace),
		SpanType:     tracing.SpanTypeLLM,
		StartedAt:    now,
		EndedAt:      now.Add(10 * time.Millisecond),
		ActorType:    actorType,
		ActorID:      actorID,
		SessionID:    "sess-1",
		ProjectID:    "proj-1",
		Status:       status,
		ResourceType: "llm",
		ResourceID:   "https://api.openai.com/v1",
		Attributes: map[string]any{
			tracing.AttrModel:      model,
			tracing.AttrProvider:   "openai",
			tracing.AttrInputToks:  in,
			tracing.AttrOutputToks: out,
			tracing.AttrCostUSD:    cost,
			tracing.AttrToolCalls:  1,
		},
	}
	if actorType == "user" {
		s.UserID = actorID
	}
	if actorType == "agent" {
		s.AgentID = actorID
	}
	return s
}

func mustPut(t *testing.T, s storage.Storage, span *tracing.Span) {
	t.Helper()
	if err := s.PutSpan(context.Background(), span); err != nil {
		t.Fatalf("put span: %v", err)
	}
}

func TestSQLiteRoundTrip(t *testing.T) {
	db := filepath.Join(t.TempDir(), "test.db")
	st, err := storage.NewSQLite(db)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	ctx := context.Background()

	mustPut(t, st, mkSpan("trace-1", "s1", "user", "usr_a", "gpt-4o", 100, 10, 0.01, "ok"))
	mustPut(t, st, mkSpan("trace-1", "s2", "agent", "agent_b", "gpt-4o-mini", 200, 20, 0.001, "ok"))
	mustPut(t, st, mkSpan("trace-2", "s3", "user", "usr_a", "deepseek-chat", 50, 5, 0.001, "error"))

	if recent, _ := st.ListRecent(ctx, 10); len(recent) != 3 {
		t.Fatalf("ListRecent = %d, want 3", len(recent))
	}

	tr, _ := st.GetTrace(ctx, "trace-1")
	if len(tr.Spans) != 2 {
		t.Fatalf("trace-1 spans = %d, want 2", len(tr.Spans))
	}

	if byUser, _ := st.Query(ctx, storage.SpanFilter{UserID: "usr_a"}); len(byUser) != 2 {
		t.Errorf("user query = %d, want 2", len(byUser))
	}
	if byModel, _ := st.Query(ctx, storage.SpanFilter{Model: "gpt-4o"}); len(byModel) != 1 {
		t.Errorf("model query = %d, want 1", len(byModel))
	}
	if byStatus, _ := st.Query(ctx, storage.SpanFilter{Status: "error"}); len(byStatus) != 1 {
		t.Errorf("status query = %d, want 1", len(byStatus))
	}

	costs, _ := st.Costs(ctx, "model", time.Time{}, "")
	if len(costs) != 3 {
		t.Fatalf("cost rows = %d (%+v)", len(costs), costs)
	}
	var found bool
	for _, c := range costs {
		if c.Group == "gpt-4o" {
			found = true
			if c.Requests != 1 || c.CostUSD != 0.01 {
				t.Errorf("gpt-4o row = %+v", c)
			}
		}
	}
	if !found {
		t.Error("missing gpt-4o cost row")
	}

	userCosts, _ := st.Costs(ctx, "user", time.Time{}, "")
	if len(userCosts) != 2 {
		t.Fatalf("user cost rows = %d (%+v)", len(userCosts), userCosts)
	}
}

func TestSQLitePersistsAcrossReopen(t *testing.T) {
	db := filepath.Join(t.TempDir(), "persist.db")
	st, err := storage.NewSQLite(db)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	mustPut(t, st, mkSpan("trace-1", "s1", "user", "usr_a", "gpt-4o", 100, 10, 0.01, "ok"))
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	st2, err := storage.NewSQLite(db)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	if recent, _ := st2.ListRecent(context.Background(), 10); len(recent) != 1 {
		t.Fatalf("after reopen ListRecent = %d, want 1", len(recent))
	}
}

// Concurrent writers wait for each other instead of failing: the edge fails
// closed on a single failed audit write, so SQLITE_BUSY must not surface
// under ordinary load (it did when busy_timeout reached one connection only).
func TestSQLiteConcurrentWritersDoNotFailBusy(t *testing.T) {
	s, err := storage.NewSQLite(filepath.Join(t.TempDir(), "spans.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 400)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if err := s.PutSpan(context.Background(), mkSpan(fmt.Sprintf("t%d", g), fmt.Sprintf("s%d-%d", g, i), "agent", "a", "m", 1, 1, 0, "ok")); err != nil {
					errs <- err
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent write failed: %v", err)
	}
}
