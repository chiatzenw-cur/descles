package edge

import (
	"context"

	"crypto/subtle"
	"encoding/json"
	"errors"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
	"github.com/chiatzenw-cur/descles/web"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

// ApprovalAdmin serves approvers on the customer's network: an API and a
// small page at /admin/. Details of pending calls are shown from the edge's
// own store and never pass through Descles.
//
// The bootstrap token is an owner recovery credential. Named console tokens
// identify individual administrators and viewers on this customer edge.
type ApprovalAdmin struct {
	Store  *ApprovalStore
	Token  string
	Access *AdminAccess
	// Traces serves GET /admin/traces/{id}: the edge's local record of one
	// trace, for evaluations run by the edge's operator. Optional.
	Traces interface {
		GetTrace(ctx context.Context, id tracing.TraceID) (*tracing.Trace, error)
	}
	// Info serves GET /admin/info (edge id, policy digest, ...). Optional.
	Info func() map[string]any
	// Recent serves the console's Activity and Policy replay. Optional.
	Recent RecentSpans
	// Policy is what the edge enforces, for the console's Policy panel.
	Policy *policy.Holder
	// GroupOf resolves an agent's group, as the gateway does, so checks and
	// replays apply group rules. Optional.
	GroupOf func(agentID string) string
	// Panels are extra console panels from extensions.
	Panels []AdminPanel
	// LocalManagement supplies standalone edge configuration routes. Managed
	// edges keep identity and provider administration on their own control plane.
	LocalManagement interface {
		RegisterAdmin(*http.ServeMux, func(http.Handler) http.Handler)
	}
}

// Register mounts the admin routes. Without a token they are not served.
func (a *ApprovalAdmin) Register(mux *http.ServeMux) {
	if a == nil || a.Token == "" || a.Store == nil {
		return
	}
	mux.HandleFunc("GET /admin/{$}", a.page)
	mux.Handle("GET /admin/me", a.auth(http.HandlerFunc(a.me)))
	mux.Handle("GET /admin/operators", a.auth(http.HandlerFunc(a.operators)))
	if a.Access != nil {
		mux.Handle("POST /admin/operators", a.auth(http.HandlerFunc(a.issueOperator)))
		mux.Handle("DELETE /admin/operators/{id}", a.auth(http.HandlerFunc(a.revokeOperator)))
	}
	mux.Handle("GET /admin/approvals", a.auth(http.HandlerFunc(a.list)))
	mux.Handle("POST /admin/approvals/{id}/{decision}", a.auth(http.HandlerFunc(a.decide)))
	if a.Traces != nil {
		mux.Handle("GET /admin/traces/{id}", a.auth(http.HandlerFunc(a.trace)))
	}
	if a.Info != nil {
		mux.Handle("GET /admin/info", a.auth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { writeJSONBody(w, a.Info()) })))
	}
	mux.Handle("GET /admin/panels", a.auth(http.HandlerFunc(a.panels)))
	if a.Recent != nil {
		mux.Handle("GET /admin/activity", a.auth(http.HandlerFunc(a.activity)))
	}
	if a.Policy != nil {
		mux.Handle("GET /admin/policy", a.auth(http.HandlerFunc(a.policyView)))
		mux.Handle("POST /admin/policy/check", a.auth(http.HandlerFunc(a.policyCheck)))
		if a.Recent != nil {
			mux.Handle("GET /admin/policy/replay", a.auth(http.HandlerFunc(a.policyReplay)))
		}
	}
	for _, p := range a.Panels {
		p.RegisterAdmin(mux, a.auth)
	}
	if a.LocalManagement != nil {
		a.LocalManagement.RegisterAdmin(mux, a.auth)
	}
}

func (a *ApprovalAdmin) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			http.Error(w, "edge admin token required", http.StatusUnauthorized)
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		id := AdminIdentity{}
		if got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(a.Token)) == 1 {
			id = AdminIdentity{ID: "owner", Name: "Bootstrap owner token", Role: "owner", Shared: true}
		} else if a.Access != nil {
			var ok bool
			id, ok = a.Access.Resolve(got)
			if !ok {
				http.Error(w, "edge admin token required", http.StatusUnauthorized)
				return
			}
		} else {
			http.Error(w, "edge admin token required", http.StatusUnauthorized)
			return
		}
		if id.Role == "viewer" && r.Method != http.MethodGet && r.Method != http.MethodHead && !(r.Method == http.MethodPost && r.URL.Path == "/admin/policy/check") {
			http.Error(w, "viewer access is read-only", http.StatusForbidden)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), adminIdentityKey{}, id))
		next.ServeHTTP(w, r)
	})
}

func (a *ApprovalAdmin) list(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	switch state {
	case "", ApprovalPending, ApprovalApproved, ApprovalDenied, ApprovalUsed, ApprovalExpired:
	default:
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}
	list, err := a.Store.List(r.Context(), state, 200)
	if err != nil {
		http.Error(w, "approvals unavailable", http.StatusServiceUnavailable)
		return
	}
	if list == nil {
		list = []Approval{}
	}
	writeJSONBody(w, map[string]any{"approvals": list})
}

func (a *ApprovalAdmin) decide(w http.ResponseWriter, r *http.Request) {
	decision := r.PathValue("decision")
	if decision != "approve" && decision != "deny" {
		http.Error(w, "decision must be approve or deny", http.StatusBadRequest)
		return
	}
	var in struct {
		By     string `json:"by"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in); err != nil {
		http.Error(w, "JSON body with \"by\" required", http.StatusBadRequest)
		return
	}
	in.By, in.Reason = strings.TrimSpace(in.By), strings.TrimSpace(in.Reason)
	if len(in.Reason) > 1000 {
		http.Error(w, "reason up to 1000 chars", http.StatusBadRequest)
		return
	}
	if id, ok := AdminFromContext(r.Context()); ok {
		in.By = id.ID
	}
	out, err := a.Store.Decide(r.Context(), r.PathValue("id"), decision == "approve", in.By, in.Reason)
	switch {
	case errors.Is(err, ErrApprovalNotPending):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(w, "approval not found", http.StatusNotFound)
	default:
		writeJSONBody(w, out)
	}
}

func (a *ApprovalAdmin) page(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	page, err := fs.ReadFile(web.FS(), "edge_admin.html")
	if err != nil {
		http.Error(w, "console unavailable", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(page)
}

// TraceRecord is one locally recorded span as the admin API returns it.
type TraceRecord struct {
	SpanType    string    `json:"span_type"`
	Status      string    `json:"status"`
	StartedAt   time.Time `json:"started_at"`
	EndedAt     time.Time `json:"ended_at"`
	Model       string    `json:"model,omitempty"`
	Tool        string    `json:"tool,omitempty"`       // reported (canonical) name
	ToolLocal   string    `json:"tool_local,omitempty"` // name as the client sent it
	Playbook    string    `json:"playbook_version,omitempty"`
	Decision    string    `json:"policy_decision,omitempty"`
	InputToks   *int      `json:"input_tokens,omitempty"`
	OutputToks  *int      `json:"output_tokens,omitempty"`
	CachedToks  *int      `json:"cached_tokens,omitempty"`
	CostUSD     *float64  `json:"cost_usd,omitempty"`
	ToolCallsIn int       `json:"tool_calls_requested,omitempty"`
	ErrorType   string    `json:"error_type,omitempty"`
}

func (a *ApprovalAdmin) trace(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		http.Error(w, "invalid trace id", http.StatusBadRequest)
		return
	}
	t, err := a.Traces.GetTrace(r.Context(), tracing.TraceID(id))
	if err != nil || t == nil {
		writeJSONBody(w, map[string]any{"trace_id": id, "records": []TraceRecord{}})
		return
	}
	out := make([]TraceRecord, 0, len(t.Spans))
	for _, s := range t.Spans {
		rec := TraceRecord{SpanType: s.SpanType, Status: s.Status, StartedAt: s.StartedAt, EndedAt: s.EndedAt, ErrorType: s.ErrorType,
			Model: stringAttr(s, tracing.AttrModel), Tool: stringAttr(s, tracing.AttrTool), ToolLocal: stringAttr(s, attrToolLocal),
			Decision: stringAttr(s, tracing.AttrPolicy), ToolCallsIn: intAttr(s, tracing.AttrToolCalls), Playbook: stringAttr(s, tracing.AttrPlaybook)}
		// Absent counts stay absent: an unknown cost is not a zero cost.
		if _, ok := s.Attributes[tracing.AttrInputToks]; ok {
			v := intAttr(s, tracing.AttrInputToks)
			rec.InputToks = &v
		}
		if _, ok := s.Attributes[tracing.AttrOutputToks]; ok {
			v := intAttr(s, tracing.AttrOutputToks)
			rec.OutputToks = &v
		}
		if _, ok := s.Attributes[tracing.AttrCachedToks]; ok {
			v := intAttr(s, tracing.AttrCachedToks)
			rec.CachedToks = &v
		}
		if _, ok := s.Attributes[tracing.AttrCostUSD]; ok {
			v := floatAttr(s, tracing.AttrCostUSD)
			rec.CostUSD = &v
		}
		out = append(out, rec)
	}
	writeJSONBody(w, map[string]any{"trace_id": id, "records": out})
}
