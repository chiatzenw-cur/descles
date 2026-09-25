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
	now        func() time.Time
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
	return &ApprovalStore{db: db, PendingTTL: 30 * time.Minute, UseWindow: 15 * time.Minute, now: func() time.Time { return time.Now().UTC() }}, nil
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

func (s *ApprovalStore) ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// expire closes overdue approvals and erases their arguments.
func (s *ApprovalStore) expire(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE edge_approvals SET state=?, args=NULL
		WHERE state IN (?, ?) AND expires_at <= ?`, ApprovalExpired, ApprovalPending, ApprovalApproved, s.ts(s.now()))
	return err
}

// Request returns the pending approval for this exact call, creating one if
// there is none, so an agent retrying while it waits does not flood approvers.
func (s *ApprovalStore) Request(ctx context.Context, a Approval, args json.RawMessage) (Approval, error) {
	if err := s.expire(ctx); err != nil {
		return Approval{}, err
	}
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM edge_approvals WHERE org_id=? AND agent_id=? AND tool=? AND args_digest=? AND state=? ORDER BY created_at LIMIT 1`,
		a.OrgID, a.AgentID, a.Tool, a.ArgsDigest, ApprovalPending).Scan(&id)
	if err == nil {
		return s.Get(ctx, id)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Approval{}, err
	}
	now := s.now()
	a.ID, a.State, a.CreatedAt, a.ExpiresAt = approvalID(), ApprovalPending, now, now.Add(s.PendingTTL)
	_, err = s.db.ExecContext(ctx, `INSERT INTO edge_approvals(id, org_id, edge_id, agent_id, user_id, tool, args_digest, args, state, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`, a.ID, a.OrgID, a.EdgeID, a.AgentID, a.UserID, a.Tool, a.ArgsDigest, string(args), a.State, s.ts(a.CreatedAt), s.ts(a.ExpiresAt))
	a.Args = args
	return a, err
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
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM edge_approvals WHERE org_id=? AND agent_id=? AND tool=? AND args_digest=? AND state=? ORDER BY created_at LIMIT 1`,
		orgID, agentID, tool, digest, ApprovalApproved).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE edge_approvals SET state=?, args=NULL WHERE id=? AND state=?`, ApprovalUsed, id, ApprovalApproved)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", nil // lost a race with a concurrent retry: it gets the execution
	}
	return id, nil
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
		out = append(out, a)
	}
	return out, rows.Err()
}
