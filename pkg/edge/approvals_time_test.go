package edge

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func rawState(t *testing.T, s *ApprovalStore, id string) (state string, hasArgs bool) {
	t.Helper()
	var args sql.NullString
	if err := s.db.QueryRow(`SELECT state, args FROM edge_approvals WHERE id=?`, id).Scan(&state, &args); err != nil {
		t.Fatal(err)
	}
	return state, args.Valid
}

// RFC3339Nano trims zeros: "…:00Z" sorted after "…:00.5Z" as text, so within
// the same second expiry ran late or early. Both sides of the boundary.
func TestApprovalExpiryAtSubSecondBoundaries(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name        string
		start, now  string
		wantExpired bool
	}{
		{"expiry on a whole second, checked half a second later", "2026-09-26T12:00:00Z", "2026-09-26T12:30:00.5Z", true},
		{"expiry half a second in, checked on the whole second", "2026-09-26T12:00:00.5Z", "2026-09-26T12:30:00Z", false},
		{"exactly at expiry", "2026-09-26T12:00:00.25Z", "2026-09-26T12:30:00.25Z", true},
		{"one nanosecond before expiry", "2026-09-26T12:00:00.000000001Z", "2026-09-26T12:30:00Z", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, clock, _ := openTestApprovals(t)
			s.PendingTTL = 30 * time.Minute
			clock.t, _ = time.Parse(time.RFC3339Nano, tc.start)
			a, args := refundCall("1")
			req, _, err := s.Request(ctx, a, args)
			if err != nil {
				t.Fatal(err)
			}
			clock.t, _ = time.Parse(time.RFC3339Nano, tc.now)
			if err := s.Sweep(ctx); err != nil {
				t.Fatal(err)
			}
			state, hasArgs := rawState(t, s, req.ID)
			if expired := state == ApprovalExpired; expired != tc.wantExpired || expired == hasArgs {
				t.Fatalf("stored state=%s args=%v, want expired=%v", state, hasArgs, tc.wantExpired)
			}
		})
	}
}

// Rows stored by older edges in the trimmed format are rewritten at open.
func TestOpenNormalizesStoredTimes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.db")
	s, err := OpenApprovals(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO edge_approvals(id, org_id, edge_id, agent_id, tool, args_digest, args, state, created_at, expires_at, decided_at)
		VALUES ('apr_old','o','e','a','t','d','{}','approved','2099-01-01T00:00:00Z','2099-01-01T00:00:00.5Z','2099-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s2, err := OpenApprovals(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var created, expires, decided string
	if err := s2.db.QueryRow(`SELECT created_at, expires_at, decided_at FROM edge_approvals WHERE id='apr_old'`).Scan(&created, &expires, &decided); err != nil {
		t.Fatal(err)
	}
	if created != "2099-01-01T00:00:00.000000000Z" || expires != "2099-01-01T00:00:00.500000000Z" || decided != created {
		t.Fatalf("times not normalized: %s %s %s", created, expires, decided)
	}
}

// Fault injection: a failing sweep is recorded and reported, not dropped.
func TestSweepFailureIsObservable(t *testing.T) {
	s, _, _ := openTestApprovals(t)
	var reported error
	s.OnSweepError = func(err error) { reported = err }
	if st := s.SweepStatus(); st.Failures != 0 || st.LastOK.IsZero() {
		t.Fatalf("after a clean open: %+v", st)
	}
	_ = s.db.Close()
	for i := 0; i < 2; i++ {
		if err := s.Sweep(context.Background()); err == nil {
			t.Fatal("sweep on a closed database succeeded")
		}
	}
	st := s.SweepStatus()
	if st.Failures != 2 || st.LastError == "" || reported == nil {
		t.Fatalf("status %+v, reported %v", st, reported)
	}
}
