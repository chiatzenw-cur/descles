-- 0001_init.sql — Iris span table.
-- Portable types so the same DDL works on both SQLite (local/embedded, M1) and
-- PostgreSQL (production). Epoch-millis timestamps use BIGINT (Postgres INTEGER
-- is 32-bit and overflows at ~2^31 ms). Cost uses DOUBLE PRECISION (Postgres
-- REAL is 32-bit float and loses cents at scale).
CREATE TABLE IF NOT EXISTS spans (
  span_id              TEXT PRIMARY KEY,
  trace_id             TEXT NOT NULL,
  parent_span_id       TEXT,
  span_type            TEXT NOT NULL,
  started_at           BIGINT NOT NULL,    -- unix epoch millis (UTC)
  ended_at             BIGINT,             -- unix epoch millis (UTC), NULL while in-flight
  actor_type           TEXT,
  actor_id             TEXT,
  user_id              TEXT,
  agent_id             TEXT,
  session_id           TEXT,
  organization_id      TEXT,
  project_id           TEXT,
  resource_type        TEXT,
  resource_id          TEXT,
  status               TEXT NOT NULL DEFAULT 'ok',
  error_type           TEXT,
  model                TEXT,
  provider             TEXT,
  input_tokens         BIGINT NOT NULL DEFAULT 0,
  output_tokens        BIGINT NOT NULL DEFAULT 0,
  cached_tokens        BIGINT NOT NULL DEFAULT 0,
  cost_usd             DOUBLE PRECISION NOT NULL DEFAULT 0,
  tool_calls_requested BIGINT NOT NULL DEFAULT 0,
  attributes           TEXT,               -- JSON-encoded span attributes
  events               TEXT,               -- JSON-encoded events
  created_at           BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_spans_trace   ON spans(trace_id);
CREATE INDEX IF NOT EXISTS idx_spans_actor   ON spans(actor_id);
CREATE INDEX IF NOT EXISTS idx_spans_user    ON spans(user_id);
CREATE INDEX IF NOT EXISTS idx_spans_agent   ON spans(agent_id);
CREATE INDEX IF NOT EXISTS idx_spans_session ON spans(session_id);
CREATE INDEX IF NOT EXISTS idx_spans_model   ON spans(model);
CREATE INDEX IF NOT EXISTS idx_spans_provider ON spans(provider);
CREATE INDEX IF NOT EXISTS idx_spans_status  ON spans(status);
CREATE INDEX IF NOT EXISTS idx_spans_started ON spans(started_at);
