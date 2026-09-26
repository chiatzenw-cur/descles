package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

type recentLog struct{ spans []*tracing.Span }

func (r *recentLog) ListRecent(_ context.Context, limit int) ([]*tracing.Span, error) {
	if limit < len(r.spans) {
		return r.spans[:limit], nil
	}
	return r.spans, nil
}

func consoleMux(t *testing.T) (*http.ServeMux, string) {
	t.Helper()
	store, err := OpenApprovals(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now().UTC()
	recent := &recentLog{spans: []*tracing.Span{
		{SpanType: tracing.SpanTypeTool, TraceID: "t1", AgentID: "bot", StartedAt: now, Status: "ok",
			Attributes: map[string]any{tracing.AttrPolicy: "allow", attrToolLocal: "github.delete_repository", tracing.AttrTool: "github.delete_repository"}},
		{SpanType: tracing.SpanTypeTool, TraceID: "t2", AgentID: "bot", StartedAt: now, Status: "ok",
			Attributes: map[string]any{tracing.AttrPolicy: "allow", attrToolLocal: "crm.read"}},
		{SpanType: "llm.call", TraceID: "t1", AgentID: "bot", StartedAt: now, Status: "ok",
			Attributes: map[string]any{tracing.AttrModel: "deepseek-flash", tracing.AttrInputToks: 100, tracing.AttrOutputToks: 20, tracing.AttrCostUSD: 0.001}},
	}}
	hosted, _ := policy.FromJSON(`{"defaults":{"tools":{"github.delete_repository":"allow"}}}`)
	floor, _ := policy.FromJSON(`{"defaults":{"tools":{"github.delete_repository":"deny"}}}`)
	admin := &ApprovalAdmin{Store: store, Token: strings.Repeat("t", 32), Recent: recent, Policy: policy.NewHolder(hosted.WithFloor(floor))}
	mux := http.NewServeMux()
	admin.Register(mux)
	return mux, admin.Token
}

func consoleCall(t *testing.T, mux *http.ServeMux, token, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestConsoleRequiresTheAdminToken(t *testing.T) {
	mux, _ := consoleMux(t)
	for _, p := range []string{"/admin/panels", "/admin/activity", "/admin/policy", "/admin/policy/replay"} {
		if code, _ := consoleCall(t, mux, "", "GET", p, ""); code != http.StatusUnauthorized {
			t.Errorf("%s without token: %d", p, code)
		}
	}
	if code, _ := consoleCall(t, mux, "wrong", "POST", "/admin/policy/check", `{"tool":"x.y"}`); code != http.StatusUnauthorized {
		t.Errorf("check with a wrong token: %d", code)
	}
}

func TestConsoleActivityPolicyAndReplay(t *testing.T) {
	mux, tok := consoleMux(t)

	_, panels := consoleCall(t, mux, tok, "GET", "/admin/panels", "")
	if got, _ := json.Marshal(panels["panels"]); !strings.Contains(string(got), `"activity"`) || !strings.Contains(string(got), `"policy"`) {
		t.Fatalf("panels: %s", got)
	}

	_, act := consoleCall(t, mux, tok, "GET", "/admin/activity", "")
	recs := act["records"].([]any)
	if len(recs) != 3 || recs[0].(map[string]any)["name"] != "github.delete_repository" || recs[2].(map[string]any)["input_tokens"].(float64) != 100 {
		t.Fatalf("activity: %v", recs)
	}
	_, onlyModel := consoleCall(t, mux, tok, "GET", "/admin/activity?kind=model", "")
	if len(onlyModel["records"].([]any)) != 1 {
		t.Fatalf("kind filter: %v", onlyModel)
	}

	_, view := consoleCall(t, mux, tok, "GET", "/admin/policy", "")
	if view["rules"] == nil || view["floor"] == nil {
		t.Fatalf("policy view lacks rules or floor: %v", view)
	}

	_, chk := consoleCall(t, mux, tok, "POST", "/admin/policy/check", `{"agent":"bot","tool":"github.delete_repository"}`)
	if chk["decision"] != "deny" || chk["rules"] != "allow" || chk["floor"] != "deny" {
		t.Fatalf("check should show the floor deciding: %v", chk)
	}

	// The delete was allowed when it ran; under today's floor it would be denied.
	_, rp := consoleCall(t, mux, tok, "GET", "/admin/policy/replay", "")
	changed := rp["changed"].([]any)
	if rp["checked"].(float64) != 2 || len(changed) != 1 || changed[0].(map[string]any)["now"] != "deny" {
		t.Fatalf("replay: %v", rp)
	}
}
