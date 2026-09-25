package storage

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// TestPostgresRoundTrip exercises the Postgres backend end-to-end. It is
// skipped unless DESCLES_TEST_POSTGRES_DSN points at a reachable Postgres server
// (e.g. "postgres://descles:descles@localhost:5432/descles?sslmode=disable"). The DDL
// and queries are portable; this test proves the '?'-placeholder rewriting and
// BIGINT/DOUBLE PRECISION columns work against a real Postgres.
func TestPostgresRoundTrip(t *testing.T) {
	dsn := os.Getenv("DESCLES_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("DESCLES_TEST_POSTGRES_DSN not set; skipping Postgres integration test")
	}
	s, err := New("postgres", Options{PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer s.Close()

	span := &tracing.Span{
		SpanID:     "pg-span-1",
		TraceID:    "pg-trace-1",
		SpanType:   "chat",
		StartedAt:  mustTime(t, "2026-09-05T00:00:00Z"),
		EndedAt:    mustTime(t, "2026-09-05T00:00:01Z"),
		AgentID:    "agt-pg-1",
		UserID:     "alice",
		SessionID:  "sess-pg-1",
		Status:     "ok",
		Attributes: map[string]any{tracing.AttrModel: "claude", tracing.AttrInputToks: 1500, tracing.AttrOutputToks: 200, tracing.AttrCostUSD: 0.0425},
	}
	if err := s.PutSpan(context.Background(), span); err != nil {
		t.Fatalf("put span: %v", err)
	}

	got, err := s.GetTrace(context.Background(), "pg-trace-1")
	if err != nil || len(got.Spans) != 1 {
		t.Fatalf("get trace: spans=%d err=%v", len(got.Spans), err)
	}
	if got.Spans[0].SpanID != "pg-span-1" {
		t.Fatalf("wrong span: %+v", got.Spans[0])
	}

	rows, err := s.Costs(context.Background(), "agent", mustTime(t, "2026-09-01T00:00:00Z"), "org-pg")
	if err != nil || len(rows) != 1 {
		t.Fatalf("costs: rows=%d err=%v", len(rows), err)
	}
	if rows[0].CostUSD != 0.0425 {
		t.Fatalf("cost lost precision: %v", rows[0].CostUSD)
	}
}

func mustTime(t *testing.T, s string) (tm time.Time) {
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// TestPostgresEmptyDSN errors cleanly when no DSN is provided, without
// requiring a live server.
func TestPostgresEmptyDSN(t *testing.T) {
	if _, err := New("postgres", Options{}); err == nil {
		t.Fatal("expected error for empty postgres DSN")
	}
}
