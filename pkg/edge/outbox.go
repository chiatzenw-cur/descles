package edge

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"github.com/chiatzenw-cur/descles/pkg/storage"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// Outbox keeps metadata on the customer side until the hosted control plane
// acknowledges it. Provider credentials and request content never enter it.
type Outbox struct{ db *sql.DB }

func OpenOutbox(path string) (*Outbox, error) {
	if path == "" {
		return nil, fmt.Errorf("edge outbox path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS edge_outbox (
		id TEXT PRIMARY KEY, payload BLOB NOT NULL, created_at TEXT NOT NULL
	)`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Outbox{db: db}, nil
}

func (o *Outbox) Close() error { return o.db.Close() }

func (o *Outbox) Enqueue(ctx context.Context, metadata Metadata) error {
	if err := metadata.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMetadata, err)
	}
	payload, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = o.db.ExecContext(ctx, `INSERT OR IGNORE INTO edge_outbox(id,payload,created_at) VALUES(?,?,?)`, metadata.EdgeID+":"+metadata.SpanID, payload, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (o *Outbox) Next(ctx context.Context) (Metadata, bool, error) {
	var payload []byte
	err := o.db.QueryRowContext(ctx, `SELECT payload FROM edge_outbox ORDER BY created_at,id LIMIT 1`).Scan(&payload)
	if err == sql.ErrNoRows {
		return Metadata{}, false, nil
	}
	if err != nil {
		return Metadata{}, false, err
	}
	var m Metadata
	if err := json.Unmarshal(payload, &m); err != nil {
		return Metadata{}, false, err
	}
	return m, true, nil
}

func (o *Outbox) Ack(ctx context.Context, m Metadata) error {
	_, err := o.db.ExecContext(ctx, `DELETE FROM edge_outbox WHERE id=?`, m.EdgeID+":"+m.SpanID)
	return err
}

func (o *Outbox) Count(ctx context.Context) (int, error) {
	var count int
	err := o.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM edge_outbox`).Scan(&count)
	return count, err
}

// MeteredStore records locally and queues the strict metadata contract. A
// write failure blocks subsequent requests instead of silently losing usage.
type MeteredStore struct {
	storage.Storage
	Outbox *Outbox
	EdgeID string
	Filter *ReportFilter // approved model/provider names; nil reports them as "other"
	failed atomic.Bool
}

func (s *MeteredStore) Ready() bool { return !s.failed.Load() }

// PutSpan records locally and, unless the edge is standalone (nil Outbox),
// queues the span's metadata for the control plane.
//
// Only a failure to persist stops the edge (fail closed: no unrecorded
// execution). A record the metadata contract rejects is still kept locally
// and reported as an error for that call alone, so one bad request cannot
// take the edge down for everyone.
func (s *MeteredStore) PutSpan(ctx context.Context, span *tracing.Span) error {
	var invalid error
	if s.Outbox != nil {
		if err := s.Outbox.Enqueue(ctx, s.Filter.Apply(FromSpan(s.EdgeID, span))); errors.Is(err, ErrInvalidMetadata) {
			invalid = err
		} else if err != nil {
			s.failed.Store(true)
			return err
		}
	}
	if err := s.Storage.PutSpan(ctx, span); err != nil {
		s.failed.Store(true)
		return err
	}
	return invalid
}

func (s *MeteredStore) Close() error {
	err := s.Storage.Close()
	if s.Outbox == nil {
		return err
	}
	if closeErr := s.Outbox.Close(); err == nil {
		err = closeErr
	}
	return err
}

type Reporter struct {
	Outbox *Outbox
	URL    string
	Token  string
	Client *http.Client
}

func (r *Reporter) Flush(ctx context.Context, limit int) (int, error) {
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	sent := 0
	for sent < limit {
		m, ok, err := r.Outbox.Next(ctx)
		if err != nil || !ok {
			return sent, err
		}
		body, _ := json.Marshal(m)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, bytes.NewReader(body))
		if err != nil {
			return sent, err
		}
		req.Header.Set("Authorization", "Bearer "+r.Token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return sent, err
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return sent, fmt.Errorf("control plane rejected metadata: HTTP %d", resp.StatusCode)
		}
		if err := r.Outbox.Ack(ctx, m); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}
