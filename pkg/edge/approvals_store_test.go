package edge

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// lockedClock is a test clock safe to read from the sweeper goroutine.
type lockedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *lockedClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *lockedClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func openTestApprovals(t *testing.T) (*ApprovalStore, *lockedClock, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "approvals.db")
	s, err := OpenApprovals(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	clock := &lockedClock{t: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}
	s.now = clock.now
	return s, clock, path
}

func refundCall(amount string) (Approval, []byte) {
	digest, args := ArgsDigest(map[string]any{"amount": amount})
	return Approval{OrgID: "org", EdgeID: "edge", AgentID: "agent", Tool: "stripe.create_refund", ArgsDigest: digest}, args
}

func TestConcurrentRequestsShareOnePendingApproval(t *testing.T) {
	s, _, _ := openTestApprovals(t)
	a, args := refundCall("100")
	const n = 32
	ids := make([]string, n)
	created := make([]bool, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, c, err := s.Request(context.Background(), a, args)
			if err != nil {
				t.Error(err)
				return
			}
			ids[i], created[i] = got.ID, c
		}(i)
	}
	wg.Wait()
	nCreated := 0
	for i := range ids {
		if created[i] {
			nCreated++
		}
		if ids[i] != ids[0] {
			t.Fatalf("request %d got %s, want the shared %s", i, ids[i], ids[0])
		}
	}
	if nCreated != 1 {
		t.Fatalf("%d requests reported creating an approval, want 1 (one notification)", nCreated)
	}
	if list, _ := s.List(context.Background(), ApprovalPending, 0); len(list) != 1 {
		t.Fatalf("%d pending approvals, want 1", len(list))
	}
}

func TestConcurrentConsumeExecutesOnceAndRepeatNeedsNewApproval(t *testing.T) {
	s, _, _ := openTestApprovals(t)
	ctx := context.Background()
	a, args := refundCall("100")
	req, _, err := s.Request(ctx, a, args)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(ctx, req.ID, true, "alice", ""); err != nil {
		t.Fatal(err)
	}
	const n = 32
	got := make(chan string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := s.Consume(ctx, a.OrgID, a.AgentID, a.Tool, a.ArgsDigest)
			if err != nil {
				t.Error(err)
			}
			if id != "" {
				got <- id
			}
		}()
	}
	wg.Wait()
	close(got)
	if len(got) != 1 {
		t.Fatalf("%d executions authorized by one approval, want 1", len(got))
	}
	// The same call after the approval was used is a new action.
	again, created, err := s.Request(ctx, a, args)
	if err != nil || !created || again.ID == req.ID {
		t.Fatalf("repeat after use: id=%s created=%v err=%v, want a new request", again.ID, created, err)
	}
}

func TestExpiredArgumentsErasedWithoutFurtherRequests(t *testing.T) {
	s, clock, path := openTestApprovals(t)
	s.SweepInterval = 10 * time.Millisecond
	a, args := refundCall("4242")
	req, _, err := s.Request(context.Background(), a, args)
	if err != nil {
		t.Fatal(err)
	}
	clock.add(s.PendingTTL + time.Second)

	// Before any sweep, reads already hide the expired arguments.
	got, err := s.Get(context.Background(), req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != ApprovalExpired || got.Args != nil {
		t.Fatalf("read past expiry: state=%s args=%s", got.State, got.Args)
	}

	// No request arrives; the sweeper alone erases them from the file.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.RunSweeper(ctx)
	// A second reader, as a backup tool would be: it waits out the sweeper's
	// writes instead of failing with SQLITE_BUSY.
	raw, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var stored sql.NullString
		var state string
		if err := raw.QueryRow(`SELECT args, state FROM edge_approvals WHERE id=?`, req.ID).Scan(&stored, &state); err != nil {
			t.Fatal(err)
		}
		if !stored.Valid && state == ApprovalExpired {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("arguments still stored after expiry: state=%s", state)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestOpenSweepsApprovalsThatExpiredWhileDown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.db")
	s, err := OpenApprovals(path)
	if err != nil {
		t.Fatal(err)
	}
	a, args := refundCall("7")
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return past }
	if _, _, err := s.Request(context.Background(), a, args); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	// The edge was down past the expiry; opening the file sweeps it.
	s2, err := OpenApprovals(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var n int
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM edge_approvals WHERE args IS NOT NULL OR state != ?`, ApprovalExpired).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d approvals kept arguments or stayed open after restart past expiry", n)
	}
}
