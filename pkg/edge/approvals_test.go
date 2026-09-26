package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

type approvalRig struct {
	t        *testing.T
	g        *MCPGateway
	store    *ApprovalStore
	mux      *http.ServeMux
	executed *atomic.Int32
	spans    *spanLog
	clock    time.Time
}

func newApprovalRig(t *testing.T) *approvalRig {
	t.Helper()
	executed := &atomic.Int32{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcCall
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "tools/call" {
			executed.Add(1)
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"refunded"}]}}`)
	}))
	t.Cleanup(upstream.Close)
	store, err := OpenApprovals(filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rig := &approvalRig{t: t, store: store, executed: executed, spans: &spanLog{}, clock: time.Now().UTC()}
	store.now = func() time.Time { return rig.clock }
	pol, _ := policy.FromJSON(`{"defaults":{"require_approval":["stripe.refund"]}}`)
	rig.g = &MCPGateway{
		Config:  &MCPConfig{Connectors: []MCPConnector{{ID: "stripe", URL: upstream.URL, InsecureHTTP: true}}},
		Resolve: func(k string) (string, string, string, bool) { return "org_1", "user_1", "agent_1", k == "vk" },
		Policy:  policy.NewHolder(pol), Spans: rig.spans, Approvals: store, EdgeID: "edge-1",
	}
	rig.mux = http.NewServeMux()
	rig.mux.Handle("POST /mcp/{connector}", rig.g)
	(&ApprovalAdmin{Store: store, Token: "admin-secret"}).Register(rig.mux)
	return rig
}

// refund calls stripe.refund and returns the tool text and whether it errored.
func (r *approvalRig) refund(amount int) (string, bool) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"refund","arguments":{"charge":"ch_1","amount":` + itoa(amount) + `}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp/stripe", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer vk")
	rec := httptest.NewRecorder()
	r.mux.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return toolResultText(out)
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func (r *approvalRig) admin(method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.mux.ServeHTTP(rec, req)
	return rec
}

var approvalIDPattern = regexp.MustCompile(`apr_[0-9a-f]{32}`)

func (r *approvalRig) requested(text string) string {
	r.t.Helper()
	id := approvalIDPattern.FindString(text)
	if id == "" {
		r.t.Fatalf("expected an approval request, got %q", text)
	}
	return id
}

func TestEdgeApprovalLifecycle(t *testing.T) {
	r := newApprovalRig(t)

	// 1. A call that needs approval does not run; asking again reuses the request.
	text, isErr := r.refund(100)
	id := r.requested(text)
	if !isErr || r.executed.Load() != 0 {
		t.Fatal("unapproved call executed")
	}
	if again, _ := r.refund(100); r.requested(again) != id {
		t.Fatal("a retry while pending must not create a second request")
	}

	// 2. Approvers see the details locally; the admin API needs the edge token.
	if rec := r.admin("GET", "/admin/approvals?state=pending", "wrong", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin API without the token: %d", rec.Code)
	}
	rec := r.admin("GET", "/admin/approvals?state=pending", "admin-secret", "")
	if !strings.Contains(rec.Body.String(), `"amount":100`) || !strings.Contains(rec.Body.String(), id) {
		t.Fatalf("pending list: %s", rec.Body.String())
	}
	if rec := r.admin("POST", "/admin/approvals/"+id+"/approve", "admin-secret", `{"by":""}`); rec.Code != http.StatusBadRequest {
		t.Fatal("an approval must name the approver")
	}
	if rec := r.admin("POST", "/admin/approvals/"+id+"/approve", "admin-secret", `{"by":"alice","reason":"customer ticket 42"}`); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	if rec := r.admin("POST", "/admin/approvals/"+id+"/deny", "admin-secret", `{"by":"mallory"}`); rec.Code != http.StatusConflict {
		t.Fatal("a decided approval cannot be decided again")
	}

	// 3. Changed arguments are a different call: not executed, new request.
	if text, _ := r.refund(9999); r.requested(text) == id || r.executed.Load() != 0 {
		t.Fatal("parameter substitution used the approval")
	}

	// 4. The exact approved call runs once, recorded as approval-gated.
	if text, isErr := r.refund(100); isErr || text != "refunded" || r.executed.Load() != 1 {
		t.Fatalf("approved call: %q err=%v executed=%d", text, isErr, r.executed.Load())
	}
	last := r.spans.spans[len(r.spans.spans)-1]
	if last.Attributes[tracing.AttrPolicy] != string(policy.RequireApproval) || last.Status != "ok" {
		t.Fatalf("execution record: %+v", last.Attributes)
	}
	used, _ := r.store.Get(context.Background(), id)
	if used.State != ApprovalUsed || used.Args != nil || used.ArgsDigest == "" || used.DecidedBy != "alice" {
		t.Fatalf("used approval must keep the digest and approver but erase the arguments: %+v", used)
	}

	// 5. Replay: the approval is spent.
	if text, _ := r.refund(100); r.requested(text) == id || r.executed.Load() != 1 {
		t.Fatal("an approval executed twice")
	}
}

func TestEdgeApprovalDenyExpireAndRevoke(t *testing.T) {
	r := newApprovalRig(t)
	ctx := context.Background()

	// Denied: never runs, arguments erased at once.
	text, _ := r.refund(1)
	id := r.requested(text)
	if _, err := r.store.Decide(ctx, id, false, "bob", "not authorised"); err != nil {
		t.Fatal(err)
	}
	if a, _ := r.store.Get(ctx, id); a.Args != nil || a.State != ApprovalDenied {
		t.Fatalf("denied approval: %+v", a)
	}
	if text, _ := r.refund(1); r.requested(text) == id || r.executed.Load() != 0 {
		t.Fatal("denied call executed")
	}

	// Timeout: an approval not used within the window expires.
	text, _ = r.refund(2)
	id = r.requested(text)
	if _, err := r.store.Decide(ctx, id, true, "bob", ""); err != nil {
		t.Fatal(err)
	}
	r.clock = r.clock.Add(r.store.UseWindow + time.Second)
	if text, _ := r.refund(2); r.requested(text) == id || r.executed.Load() != 0 {
		t.Fatal("expired approval executed")
	}
	if a, _ := r.store.Get(ctx, id); a.State != ApprovalExpired || a.Args != nil {
		t.Fatalf("expired approval: %+v", a)
	}

	// A pending request that nobody decides expires too.
	text, _ = r.refund(3)
	id = r.requested(text)
	r.clock = r.clock.Add(r.store.PendingTTL + time.Second)
	if _, err := r.store.Decide(ctx, id, true, "bob", ""); err != ErrApprovalNotPending {
		t.Fatalf("deciding an expired request: %v", err)
	}

	// Revocation after approval: policy is re-checked at execution.
	text, _ = r.refund(4)
	id = r.requested(text)
	if _, err := r.store.Decide(ctx, id, true, "bob", ""); err != nil {
		t.Fatal(err)
	}
	denyAll, _ := policy.FromJSON(`{"defaults":{"tools":{"stripe.refund":"deny"}}}`)
	r.g.Policy.Set(denyAll)
	if text, isErr := r.refund(4); !isErr || !strings.Contains(text, "Denied") || r.executed.Load() != 0 {
		t.Fatalf("revoked after approval, still ran: %q", text)
	}
}

func TestApprovalsDisabledFailClosed(t *testing.T) {
	r := newApprovalRig(t)
	r.g.Approvals = nil
	if text, isErr := r.refund(1); !isErr || !strings.Contains(text, "not enabled") || r.executed.Load() != 0 {
		t.Fatalf("without an approval store the call must fail closed: %q", text)
	}
	mux := http.NewServeMux()
	(&ApprovalAdmin{Store: r.store}).Register(mux) // no token: routes not served
	req := httptest.NewRequest("GET", "/admin/approvals", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("admin API served without a token: %d", rec.Code)
	}
}

func TestApprovalNotifiesOncePerRequestWithoutArguments(t *testing.T) {
	r := newApprovalRig(t)
	got := make(chan map[string]any, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(req.Body).Decode(&body)
		got <- body
	}))
	defer hook.Close()
	r.g.Notifier = &ApprovalNotifier{URL: hook.URL, AdminURL: "https://descles.internal"}
	text, _ := r.refund(777)
	id := r.requested(text)
	r.refund(777) // retry while pending: same request, no second notice
	var msg map[string]any
	select {
	case msg = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no notification")
	}
	raw, _ := json.Marshal(msg)
	if !strings.Contains(msg["text"].(string), id) || !strings.Contains(string(raw), "https://descles.internal/admin/") || !strings.Contains(string(raw), "stripe.refund") {
		t.Fatalf("notice: %s", raw)
	}
	if strings.Contains(string(raw), "777") || strings.Contains(string(raw), "ch_1") {
		t.Fatalf("arguments must stay on the edge by default: %s", raw)
	}
	select {
	case extra := <-got:
		t.Fatalf("a retry of a pending call notified again: %v", extra)
	case <-time.After(300 * time.Millisecond):
	}
	if err := ValidateWebhook("http://hooks.example.com/x"); err == nil {
		t.Fatal("plain http webhook to a remote host accepted")
	}
	// Opt-in: arguments included.
	r.g.Notifier.IncludeArgs = true
	r.refund(778)
	select {
	case msg = <-got:
		if raw, _ := json.Marshal(msg); !strings.Contains(string(raw), "778") {
			t.Fatalf("IncludeArgs: %s", raw)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no notification")
	}
}
