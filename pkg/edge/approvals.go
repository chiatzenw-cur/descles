package edge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Approvals are decided on the edge, by people in the customer's network.
// The call's arguments are stored here, locally, only while a human needs to
// see them; once an approval is used, denied or expires they are erased and
// only their digest remains.
//
// An approval authorizes exactly one execution of exactly one call: the same
// agent, the same connector.tool and arguments with the same canonical digest,
// before it expires. Anything else (changed arguments, a second execution, a
// late retry) needs a new approval. Grants and policy are re-checked when the
// approved call runs, so a revocation after approval still stops it.
//
// Retries and repeats: while a call is pending, asking again for the same
// call (same org, edge, agent, tool and digest) returns the same request; a
// unique index makes that hold under concurrency. Once that request is used,
// denied or expired, the same call again is a new action and needs a new
// approval.
//
// Erasure: arguments are set to NULL when an approval closes. Expired
// requests are closed by a sweep at startup and every SweepInterval (default
// 1 minute), so while the edge runs, arguments outlive their expiry by at
// most about one interval; after downtime they are swept at the next start.
// Reads never return arguments past expiry. SQLite secure_delete overwrites
// the erased bytes in the database file. Copies taken earlier (backups,
// snapshots of the data volume) are outside this process and keep what they
// captured.

// Approval states.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDenied   = "denied"
	ApprovalUsed     = "used"
	ApprovalExpired  = "expired"
)

// ErrApprovalNotPending is returned when deciding an approval that is not
// waiting for a decision (already decided, used or expired).
var ErrApprovalNotPending = errors.New("approval is not pending")

// Approval is one request for a human decision.
type Approval struct {
	ID         string          `json:"id"`
	OrgID      string          `json:"org_id"`
	EdgeID     string          `json:"edge_id"`
	AgentID    string          `json:"agent_id"`
	UserID     string          `json:"user_id,omitempty"`
	Tool       string          `json:"tool"`
	ArgsDigest string          `json:"args_digest"`
	Args       json.RawMessage `json:"args,omitempty"` // erased when the approval closes
	State      string          `json:"state"`
	CreatedAt  time.Time       `json:"created_at"`
	ExpiresAt  time.Time       `json:"expires_at"` // pending: decide by; approved: use by
	DecidedBy  string          `json:"decided_by,omitempty"`
	DecidedAt  *time.Time      `json:"decided_at,omitempty"`
	Reason     string          `json:"reason,omitempty"`
}

// ApprovalStore keeps approvals in a local SQLite file.
type ApprovalStore struct {
	db         *sql.DB
	PendingTTL time.Duration // how long a request waits for a decision (default 30m)
	UseWindow  time.Duration // how long an approval may be used (default 15m)
	// SweepInterval bounds how long expired arguments stay in the file while
	// the edge runs (default 1m). See RunSweeper.
	SweepInterval time.Duration
	// OnSweepError is told about every failed sweep (the edge logs it).
	OnSweepError func(error)
	now          func() time.Time

	sweepMu sync.Mutex
	sweep   SweepStatus
}

func OpenApprovals(path string) (*ApprovalStore, error) {
	if path == "" {
		return nil, errors.New("approvals database path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS edge_approvals (
		id TEXT PRIMARY KEY, org_id TEXT NOT NULL, edge_id TEXT NOT NULL,
		agent_id TEXT NOT NULL, user_id TEXT NOT NULL DEFAULT '', tool TEXT NOT NULL,
		args_digest TEXT NOT NULL, args TEXT, state TEXT NOT NULL,
		created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
		decided_by TEXT NOT NULL DEFAULT '', decided_at TEXT, reason TEXT NOT NULL DEFAULT '')`); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Erased arguments are overwritten in the file, not just unlinked.
	if _, err := db.Exec(`PRAGMA secure_delete=ON`); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Before anything compares times in SQL.
	if err := normalizeTimes(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	// One pending request per exact call. Files from before this index may
	// hold duplicates: keep the oldest, close the rest.
	if _, err := db.Exec(`UPDATE edge_approvals SET state=?, args=NULL WHERE state=? AND EXISTS (
		SELECT 1 FROM edge_approvals o WHERE o.state=? AND o.org_id=edge_approvals.org_id AND o.edge_id=edge_approvals.edge_id
		AND o.agent_id=edge_approvals.agent_id AND o.tool=edge_approvals.tool AND o.args_digest=edge_approvals.args_digest
		AND (o.created_at < edge_approvals.created_at OR (o.created_at = edge_approvals.created_at AND o.id < edge_approvals.id)))`,
		ApprovalExpired, ApprovalPending, ApprovalPending); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS edge_approvals_one_pending
		ON edge_approvals(org_id, edge_id, agent_id, tool, args_digest) WHERE state='pending'`); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &ApprovalStore{db: db, PendingTTL: 30 * time.Minute, UseWindow: 15 * time.Minute, SweepInterval: time.Minute, now: func() time.Time { return time.Now().UTC() }}
	// Close whatever expired while the edge was down, before serving anything.
	if err := s.Sweep(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// RunSweeper closes expired approvals, erasing their arguments, every
// SweepInterval until ctx ends, whether or not any request arrives. Failures
// are recorded in SweepStatus and passed to OnSweepError; the next tick
// retries.
func (s *ApprovalStore) RunSweeper(ctx context.Context) {
	t := time.NewTicker(s.sweepEvery())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.Sweep(ctx)
		}
	}
}

func (s *ApprovalStore) Close() error { return s.db.Close() }

// ArgsDigest is the canonical digest an approval binds to: SHA-256 of the
// arguments' JSON with sorted keys and numbers kept as sent.
func ArgsDigest(args map[string]any) (string, json.RawMessage) {
	if args == nil {
		args = map[string]any{}
	}
	b, _ := json.Marshal(args)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), b
}

func approvalID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "apr_" + hex.EncodeToString(b)
}

// approvalTime is fixed width, so SQLite's text comparison orders times
// correctly. RFC3339Nano trims trailing zeros, and "…:05Z" sorts after
// "…:05.5Z" although it is earlier.
const approvalTime = "2006-01-02T15:04:05.000000000Z"

func (s *ApprovalStore) ts(t time.Time) string { return t.UTC().Format(approvalTime) }

// normalizeTimes rewrites times stored by older versions in the fixed-width
// format, so comparisons in SQL are correct for existing rows too.
func normalizeTimes(db *sql.DB) error {
	rows, err := db.Query(`SELECT id, created_at, expires_at, COALESCE(decided_at, '') FROM edge_approvals`)
	if err != nil {
		return err
	}
	type fix struct{ id, created, expires, decided string }
	var fixes []fix
	for rows.Next() {
		var f fix
		if err := rows.Scan(&f.id, &f.created, &f.expires, &f.decided); err != nil {
			rows.Close()
			return err
		}
		changed := false
		for _, p := range []*string{&f.created, &f.expires, &f.decided} {
			if *p == "" {
				continue
			}
			t, err := time.Parse(time.RFC3339Nano, *p)
			if err != nil {
				rows.Close()
				return fmt.Errorf("approval %s: stored time %q: %w", f.id, *p, err)
			}
			if n := t.UTC().Format(approvalTime); n != *p {
				*p, changed = n, true
			}
		}
		if changed {
			fixes = append(fixes, f)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, f := range fixes {
		var decided any
		if f.decided != "" {
			decided = f.decided
		}
		if _, err := db.Exec(`UPDATE edge_approvals SET created_at=?, expires_at=?, decided_at=? WHERE id=?`, f.created, f.expires, decided, f.id); err != nil {
			return err
		}
	}
	return nil
}

// SweepStatus reports the expiry sweep, so a failing erasure is visible
// (in /admin/info and `descles doctor`) instead of silent.
type SweepStatus struct {
	Interval  string    `json:"interval"`
	LastOK    time.Time `json:"last_ok,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	LastErrAt time.Time `json:"last_error_at,omitempty"`
	Failures  int       `json:"consecutive_failures"`
}

// Sweep closes expired approvals and erases their arguments now, recording
// the outcome in SweepStatus and reporting failures to OnSweepError.
func (s *ApprovalStore) Sweep(ctx context.Context) error {
	err := s.expire(ctx)
	s.sweepMu.Lock()
	if err == nil {
		s.sweep.LastOK, s.sweep.Failures = time.Now().UTC(), 0
	} else {
		s.sweep.LastError, s.sweep.LastErrAt = err.Error(), time.Now().UTC()
		s.sweep.Failures++
	}
	s.sweepMu.Unlock()
	if err != nil && s.OnSweepError != nil {
		s.OnSweepError(err)
	}
	return err
}

func (s *ApprovalStore) SweepStatus() SweepStatus {
	s.sweepMu.Lock()
	defer s.sweepMu.Unlock()
	st := s.sweep
	st.Interval = s.sweepEvery().String()
	return st
}

func (s *ApprovalStore) sweepEvery() time.Duration {
	if s.SweepInterval <= 0 {
		return time.Minute
	}
	return s.SweepInterval
}

// expire closes overdue approvals and erases their arguments.
func (s *ApprovalStore) expire(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE edge_approvals SET state=?, args=NULL
		WHERE state IN (?, ?) AND expires_at <= ?`, ApprovalExpired, ApprovalPending, ApprovalApproved, s.ts(s.now()))
	return err
}

// Request returns the pending approval for this exact call, creating one if
// there is none, so an agent retrying while it waits does not flood approvers.
// created reports whether this call opened a new request (and should notify).
func (s *ApprovalStore) Request(ctx context.Context, a Approval, args json.RawMessage) (out Approval, created bool, err error) {
	// The unique index on pending requests makes create-or-reuse atomic: of
	// concurrent identical requests one insert wins and the rest read it. The
	// loop covers that request being decided or expiring in between.
	for attempt := 0; attempt < 3; attempt++ {
		if err := s.expire(ctx); err != nil {
			return Approval{}, false, err
		}
		now := s.now()
		n := a
		n.ID, n.State, n.CreatedAt, n.ExpiresAt = approvalID(), ApprovalPending, now, now.Add(s.PendingTTL)
		res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO edge_approvals(id, org_id, edge_id, agent_id, user_id, tool, args_digest, args, state, created_at, expires_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)`, n.ID, n.OrgID, n.EdgeID, n.AgentID, n.UserID, n.Tool, n.ArgsDigest, string(args), n.State, s.ts(n.CreatedAt), s.ts(n.ExpiresAt))
		if err != nil {
			return Approval{}, false, err
		}
		if k, _ := res.RowsAffected(); k == 1 {
			n.Args = args
			return n, true, nil
		}
		list, err := s.query(ctx, `WHERE org_id=? AND edge_id=? AND agent_id=? AND tool=? AND args_digest=? AND state=?`,
			a.OrgID, a.EdgeID, a.AgentID, a.Tool, a.ArgsDigest, ApprovalPending)
		if err != nil {
			return Approval{}, false, err
		}
		if len(list) == 1 && list[0].State == ApprovalPending {
			return list[0], false, nil
		}
	}
	return Approval{}, false, errors.New("approval request contended; retry")
}

// Decide records a human decision on a pending approval. An approval must
// then be used within UseWindow; a denial erases the arguments at once.
func (s *ApprovalStore) Decide(ctx context.Context, id string, approve bool, by, reason string) (Approval, error) {
	if err := s.expire(ctx); err != nil {
		return Approval{}, err
	}
	if by == "" {
		return Approval{}, errors.New("approver name is required")
	}
	now := s.now()
	var res sql.Result
	var err error
	if approve {
		res, err = s.db.ExecContext(ctx, `UPDATE edge_approvals SET state=?, decided_by=?, decided_at=?, reason=?, expires_at=? WHERE id=? AND state=?`,
			ApprovalApproved, by, s.ts(now), reason, s.ts(now.Add(s.UseWindow)), id, ApprovalPending)
	} else {
		res, err = s.db.ExecContext(ctx, `UPDATE edge_approvals SET state=?, decided_by=?, decided_at=?, reason=?, args=NULL WHERE id=? AND state=?`,
			ApprovalDenied, by, s.ts(now), reason, id, ApprovalPending)
	}
	if err != nil {
		return Approval{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return Approval{}, ErrApprovalNotPending
	}
	return s.Get(ctx, id)
}

// Consume uses the approval for this exact call, if there is one, exactly
// once. It returns the approval's id, or "" when there is nothing to use.
func (s *ApprovalStore) Consume(ctx context.Context, orgID, agentID, tool, digest string) (string, error) {
	if err := s.expire(ctx); err != nil {
		return "", err
	}
	// One statement, so of concurrent identical calls exactly one gets it.
	var id string
	err := s.db.QueryRowContext(ctx, `UPDATE edge_approvals SET state=?, args=NULL WHERE id=(
		SELECT id FROM edge_approvals WHERE org_id=? AND agent_id=? AND tool=? AND args_digest=? AND state=? AND expires_at > ?
		ORDER BY created_at LIMIT 1) AND state=? RETURNING id`,
		ApprovalUsed, orgID, agentID, tool, digest, ApprovalApproved, s.ts(s.now()), ApprovalApproved).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// Get returns one approval.
func (s *ApprovalStore) Get(ctx context.Context, id string) (Approval, error) {
	list, err := s.query(ctx, `WHERE id=?`, id)
	if err != nil {
		return Approval{}, err
	}
	if len(list) == 0 {
		return Approval{}, fmt.Errorf("approval %q not found", id)
	}
	return list[0], nil
}

// List returns approvals in a state ("" for all), newest first.
func (s *ApprovalStore) List(ctx context.Context, state string, limit int) ([]Approval, error) {
	if err := s.expire(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if state == "" {
		return s.query(ctx, `ORDER BY created_at DESC LIMIT ?`, limit)
	}
	return s.query(ctx, `WHERE state=? ORDER BY created_at DESC LIMIT ?`, state, limit)
}

func (s *ApprovalStore) query(ctx context.Context, where string, args ...any) ([]Approval, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, org_id, edge_id, agent_id, user_id, tool, args_digest, args, state, created_at, expires_at, decided_by, decided_at, reason FROM edge_approvals `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := s.now()
	var out []Approval
	for rows.Next() {
		var a Approval
		var argsText, decidedAt sql.NullString
		var created, expires string
		if err := rows.Scan(&a.ID, &a.OrgID, &a.EdgeID, &a.AgentID, &a.UserID, &a.Tool, &a.ArgsDigest, &argsText, &a.State, &created, &expires, &a.DecidedBy, &decidedAt, &a.Reason); err != nil {
			return nil, err
		}
		if argsText.Valid {
			a.Args = json.RawMessage(argsText.String)
		}
		a.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		a.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
		if decidedAt.Valid {
			t, _ := time.Parse(time.RFC3339Nano, decidedAt.String)
			a.DecidedAt = &t
		}
		// Past expiry but not yet swept: report it closed, never its arguments.
		if (a.State == ApprovalPending || a.State == ApprovalApproved) && !a.ExpiresAt.After(now) {
			a.State, a.Args = ApprovalExpired, nil
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
