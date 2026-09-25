package edge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// docs/DATA-FLOWS.md promises exactly which fields leave a managed edge. This
// keeps the promise and the code from drifting apart.
func TestDataFlowDocListsExactlyTheReportedFields(t *testing.T) {
	doc, err := os.ReadFile("../../docs/DATA-FLOWS.md")
	if err != nil {
		t.Fatal(err)
	}
	block := string(doc)
	start, end := strings.Index(block, "<!-- metadata-fields:begin -->"), strings.Index(block, "<!-- metadata-fields:end -->")
	if start < 0 || end < start {
		t.Fatal("metadata field markers missing from DATA-FLOWS.md")
	}
	// Each bullet names its fields before the colon: "- `a`, `b`: description".
	documented := map[string]bool{}
	names := regexp.MustCompile("`([a-z_]+)`")
	for _, line := range strings.Split(block[start:end], "\n") {
		head, _, ok := strings.Cut(strings.TrimPrefix(line, "- "), ":")
		if !ok || !strings.HasPrefix(line, "- ") {
			continue
		}
		for _, m := range names.FindAllStringSubmatch(head, -1) {
			documented[m[1]] = true
		}
	}
	inCode := map[string]bool{}
	typ := reflect.TypeOf(Metadata{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		inCode[name] = true
		if !documented[name] {
			t.Errorf("field %q is reported but not documented", name)
		}
	}
	for name := range documented {
		if !inCode[name] {
			t.Errorf("documented field %q is not in edge.Metadata", name)
		}
	}
}

func TestDataFlowTraceIDsLeaveOnlyAsPseudonyms(t *testing.T) {
	now := time.Now().UTC()
	span := &tracing.Span{SpanID: "s1", TraceID: "claude-session-7f3a", SpanType: tracing.SpanTypeTool, Status: "ok",
		StartedAt: now, EndedAt: now, Attributes: map[string]any{tracing.AttrTool: "local.bash", tracing.AttrPolicy: "allow"}}
	a, b := FromSpan("e1", span), FromSpan("e1", span)
	if a.TraceID == "claude-session-7f3a" || a.TraceID == "" || a.TraceID != b.TraceID {
		t.Fatalf("trace id must be a stable one-way pseudonym, got %q", a.TraceID)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if string(span.TraceID) != "claude-session-7f3a" {
		t.Fatal("the local record keeps the original trace id")
	}
}

// Harness hooks send full commands and paths for the decision; neither may be
// kept in the local record or reach the metadata queue.
func TestDataFlowToolCheckInputIsNotRecorded(t *testing.T) {
	pol, _ := policy.FromJSON(`{"defaults":{"arg_tools":[{"tool":"local.bash","args":{"command":["*rm -rf*"]},"decision":"deny"}]}}`)
	rec := &spanLog{}
	g := &MCPGateway{
		Config:  &MCPConfig{},
		Resolve: func(string) (string, string, string, bool) { return "o", "u", "a", true },
		Policy:  policy.NewHolder(pol), Spans: rec,
	}
	for _, path := range []string{"/v1/tool-check", "/v1/tool-report"} {
		body := `{"client":"claude-code","tool":"Bash","input":{"command":"rm -rf /srv/customer-data SECRET=hunter2"},"outcome":"ok","session":"sess-1"}`
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer k")
		w := httptest.NewRecorder()
		if path == "/v1/tool-check" {
			g.ServeToolCheck(w, req)
		} else {
			g.ServeToolReport(w, req)
		}
	}
	if len(rec.spans) != 2 {
		t.Fatalf("want a denial and an execution record, got %d", len(rec.spans))
	}
	for _, s := range rec.spans {
		for k := range s.Attributes {
			if k != tracing.AttrTool && k != tracing.AttrPolicy {
				t.Errorf("unexpected local attribute %q", k)
			}
		}
		local, _ := json.Marshal(s)
		reported, _ := json.Marshal(FromSpan("e1", s))
		for _, leak := range []string{"customer-data", "hunter2", "rm -rf"} {
			if bytes.Contains(local, []byte(leak)) || bytes.Contains(reported, []byte(leak)) {
				t.Errorf("tool input %q was recorded", leak)
			}
		}
	}
}
