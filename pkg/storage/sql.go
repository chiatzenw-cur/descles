package storage

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver (Postgres)
	_ "modernc.org/sqlite"             // registers the "sqlite" driver (pure Go, no CGO)

	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const spanColumns = `span_id, trace_id, parent_span_id, span_type, started_at, ended_at,
	actor_type, actor_id, user_id, agent_id, session_id, organization_id, project_id,
	resource_type, resource_id, status, error_type,
	model, provider, input_tokens, output_tokens, cached_tokens, cost_usd, tool_calls_requested,
	attributes, events, created_at`

const insertSpanSQL = `INSERT INTO spans (` + spanColumns + `)
	VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

// SQL is a database/sql-backed Storage. Verified against SQLite (modernc,
// pure Go); the DDL and queries use portable types so attaching a PostgreSQL
// driver is a small, contained change.
type SQL struct {
	db *sql.DB
}

// NewSQLite opens a SQLite database at path, applies pragmas, and migrates.
func NewSQLite(path string) (Storage, error) {
	if path == "" {
		path = "descles.db"
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA synchronous=NORMAL;",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("apply pragma: %w", err)
		}
	}
	s := &SQL{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// NewPostgres opens a PostgreSQL database via DSN and migrates it. The DDL and
// queries are portable (see migrations/0001_init.sql) and pgx rewrites the
// '?' placeholders to PostgreSQL's native '$N' form, so the same query strings
// serve both SQLite and Postgres. Requires a reachable Postgres server.
func NewPostgres(dsn string) (Storage, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("postgres backend requires DESCLES_POSTGRES_DSN")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &SQL{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQL) migrate() error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		for _, stmt := range strings.Split(string(b), ";") {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := s.db.Exec(stmt); err != nil {
				return fmt.Errorf("migration %s: %w (stmt: %s)", e.Name(), err, stmt)
			}
		}
	}
	return nil
}

// PutSpan inserts a span, denormalising query-relevant leaf attributes into
// columns so the dashboard can filter and aggregate in SQL.
func (s *SQL) PutSpan(ctx context.Context, span *tracing.Span) error {
	attrs := span.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return fmt.Errorf("marshal attributes: %w", err)
	}
	eventsJSON, err := json.Marshal(span.Events)
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}
	model, provider, tin, tout, tcached, tools, cost := columnsFromAttributes(attrs)

	var ended any
	if !span.EndedAt.IsZero() {
		ended = span.EndedAt.UnixMilli()
	}

	_, err = s.db.ExecContext(ctx, insertSpanSQL,
		string(span.SpanID), string(span.TraceID), string(span.ParentSpanID), span.SpanType,
		span.StartedAt.UnixMilli(), ended,
		span.ActorType, span.ActorID, span.UserID, span.AgentID,
		span.SessionID, span.OrganizationID, span.ProjectID,
		span.ResourceType, span.ResourceID, span.Status, span.ErrorType,
		model, provider, tin, tout, tcached, cost, tools,
		string(attrsJSON), string(eventsJSON), time.Now().UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("insert span: %w", err)
	}
	return nil
}

// Query returns spans matching f, newest first.
func (s *SQL) Query(ctx context.Context, f SpanFilter) ([]*tracing.Span, error) {
	return s.query(ctx, f, "DESC")
}

// GetTrace returns a trace's spans in start order.
func (s *SQL) GetTrace(ctx context.Context, traceID tracing.TraceID) (*tracing.Trace, error) {
	spans, err := s.query(ctx, SpanFilter{TraceID: string(traceID)}, "ASC")
	if err != nil {
		return nil, err
	}
	if spans == nil {
		spans = []*tracing.Span{}
	}
	return &tracing.Trace{TraceID: traceID, Spans: spans}, nil
}

// ListRecent returns the most recent `limit` spans.
func (s *SQL) ListRecent(ctx context.Context, limit int) ([]*tracing.Span, error) {
	spans, err := s.query(ctx, SpanFilter{Limit: limit}, "DESC")
	if err != nil {
		return nil, err
	}
	if spans == nil {
		spans = []*tracing.Span{}
	}
	return spans, nil
}

// Costs aggregates spans since `from` by groupBy, scoped to orgID.
func (s *SQL) Costs(ctx context.Context, groupBy string, from time.Time, orgID string) ([]CostRow, error) {
	spans, err := s.Query(ctx, SpanFilter{From: from, OrganizationID: orgID})
	if err != nil {
		return nil, err
	}
	return AggregateCosts(spans, groupBy), nil
}

// Close closes the underlying database.
func (s *SQL) Close() error { return s.db.Close() }

func (s *SQL) query(ctx context.Context, f SpanFilter, order string) ([]*tracing.Span, error) {
	where, args := buildWhere(f)
	limit := 10000
	offset := 0
	if f.Limit > 0 {
		limit = f.Limit
	}
	if f.Offset > 0 {
		offset = f.Offset
	}
	q := fmt.Sprintf("SELECT %s FROM spans WHERE %s ORDER BY started_at %s LIMIT ? OFFSET ?",
		spanColumns, where, order)
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query spans: %w", err)
	}
	defer rows.Close()

	out := make([]*tracing.Span, 0)
	for rows.Next() {
		sp, err := scanSpan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func buildWhere(f SpanFilter) (string, []any) {
	conds := []string{}
	args := []any{}
	if f.TraceID != "" {
		conds = append(conds, "trace_id=?")
		args = append(args, f.TraceID)
	}
	if f.SessionID != "" {
		conds = append(conds, "session_id=?")
		args = append(args, f.SessionID)
	}
	if f.Status != "" {
		conds = append(conds, "status=?")
		args = append(args, f.Status)
	}
	if f.UserID != "" {
		conds = append(conds, "user_id=?")
		args = append(args, f.UserID)
	}
	if f.AgentID != "" {
		conds = append(conds, "agent_id=?")
		args = append(args, f.AgentID)
	}
	if f.OrganizationID != "" {
		conds = append(conds, "organization_id=?")
		args = append(args, f.OrganizationID)
	}
	if f.Model != "" {
		conds = append(conds, "model=?")
		args = append(args, f.Model)
	}
	if f.Provider != "" {
		conds = append(conds, "provider=?")
		args = append(args, f.Provider)
	}
	if !f.From.IsZero() {
		conds = append(conds, "started_at>=?")
		args = append(args, f.From.UnixMilli())
	}
	if !f.To.IsZero() {
		conds = append(conds, "started_at<=?")
		args = append(args, f.To.UnixMilli())
	}
	if len(conds) == 0 {
		return "1=1", args
	}
	return strings.Join(conds, " AND "), args
}

func scanSpan(row interface{ Scan(...any) error }) (*tracing.Span, error) {
	var (
		sp                        tracing.Span
		parent, ended             sql.NullString
		started                   int64
		actorType, actorID        sql.NullString
		userID, agentID           sql.NullString
		sessionID, orgID, projID  sql.NullString
		resourceType, resourceID  sql.NullString
		status, errorType         sql.NullString
		model, provider           sql.NullString
		tin, tout, tcached, tools int
		cost                      float64
		attrsJSON, eventsJSON     sql.NullString
		createdAt                 int64
	)
	err := row.Scan(
		&sp.SpanID, &sp.TraceID, &parent, &sp.SpanType, &started, &ended,
		&actorType, &actorID, &userID, &agentID, &sessionID, &orgID, &projID, &resourceType, &resourceID,
		&status, &errorType, &model, &provider, &tin, &tout, &tcached, &cost, &tools,
		&attrsJSON, &eventsJSON, &createdAt,
	)
	if err != nil {
		return nil, err
	}
	sp.ParentSpanID = tracing.ParentSpanID(parent.String)
	sp.StartedAt = time.UnixMilli(started).UTC()
	if ended.Valid {
		sp.EndedAt = time.UnixMilli(mustParseInt64(ended.String)).UTC()
	}
	sp.ActorType = actorType.String
	sp.ActorID = actorID.String
	sp.UserID = userID.String
	sp.AgentID = agentID.String
	sp.SessionID = sessionID.String
	sp.OrganizationID = orgID.String
	sp.ProjectID = projID.String
	sp.ResourceType = resourceType.String
	sp.ResourceID = resourceID.String
	sp.Status = status.String
	sp.ErrorType = errorType.String

	sp.Attributes = map[string]any{}
	if attrsJSON.Valid && attrsJSON.String != "" {
		_ = json.Unmarshal([]byte(attrsJSON.String), &sp.Attributes)
	}
	if sp.Attributes == nil {
		sp.Attributes = map[string]any{}
	}
	// Leaf columns always win (they are the denormalised source of truth).
	if model.Valid {
		sp.Attributes[tracing.AttrModel] = model.String
	}
	if provider.Valid {
		sp.Attributes[tracing.AttrProvider] = provider.String
	}
	sp.Attributes[tracing.AttrInputToks] = tin
	sp.Attributes[tracing.AttrOutputToks] = tout
	sp.Attributes[tracing.AttrCachedToks] = tcached
	sp.Attributes[tracing.AttrCostUSD] = cost
	sp.Attributes[tracing.AttrToolCalls] = tools

	if eventsJSON.Valid && eventsJSON.String != "" {
		_ = json.Unmarshal([]byte(eventsJSON.String), &sp.Events)
	}
	return &sp, nil
}

func columnsFromAttributes(a map[string]any) (model, provider string, tin, tout, tcached, tools int, cost float64) {
	if v, ok := a[tracing.AttrModel].(string); ok {
		model = v
	}
	if v, ok := a[tracing.AttrProvider].(string); ok {
		provider = v
	}
	tin = toInt(a[tracing.AttrInputToks])
	tout = toInt(a[tracing.AttrOutputToks])
	tcached = toInt(a[tracing.AttrCachedToks])
	tools = toInt(a[tracing.AttrToolCalls])
	cost = toFloat(a[tracing.AttrCostUSD])
	return
}

func toInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	default:
		return 0
	}
}

func toFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	default:
		return 0
	}
}

func mustParseInt64(s string) int64 {
	var n int64
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}
