package edge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// The edge's local console: what can only be looked at inside the customer's
// network. Activity shows the edge's own records; Policy shows what is in
// force (the control plane's rules and the local floor) and checks calls
// against it. Everything here is served by the edge and read with the edge
// admin token; none of it passes through Descles.

// AdminPanel lets an extension (for example organization context on the
// enterprise edge) add a panel to the local console: an id the page shows as
// a tab, and routes mounted behind the admin token.
type AdminPanel interface {
	AdminPanel() (id, title string)
	RegisterAdmin(mux *http.ServeMux, auth func(http.Handler) http.Handler)
}

// RecentSpans is the part of the edge's local store the console reads.
type RecentSpans interface {
	ListRecent(ctx context.Context, limit int) ([]*tracing.Span, error)
}

// ActivityRow is one recorded call as the console shows it.
type ActivityRow struct {
	At        time.Time `json:"at"`
	Trace     string    `json:"trace"`
	Agent     string    `json:"agent"`
	User      string    `json:"user,omitempty"`
	Kind      string    `json:"kind"` // model | tool
	Name      string    `json:"name"` // model, or connector.tool as called
	Decision  string    `json:"decision,omitempty"`
	Status    string    `json:"status"`
	InputTok  int       `json:"input_tokens,omitempty"`
	OutputTok int       `json:"output_tokens,omitempty"`
	CostUSD   float64   `json:"cost_usd,omitempty"`
	Playbook  string    `json:"playbook,omitempty"`
}

func activityRow(s *tracing.Span) ActivityRow {
	r := ActivityRow{At: s.StartedAt, Trace: string(s.TraceID), Agent: s.AgentID, User: s.UserID, Status: s.Status,
		Decision: stringAttr(s, tracing.AttrPolicy), Playbook: stringAttr(s, tracing.AttrPlaybook)}
	if s.SpanType == tracing.SpanTypeTool {
		r.Kind = "tool"
		r.Name = stringAttr(s, attrToolLocal)
		if r.Name == "" {
			r.Name = stringAttr(s, tracing.AttrTool)
		}
		return r
	}
	r.Kind, r.Name = "model", stringAttr(s, tracing.AttrModel)
	r.InputTok, r.OutputTok = intAttr(s, tracing.AttrInputToks), intAttr(s, tracing.AttrOutputToks)
	r.CostUSD = floatAttr(s, tracing.AttrCostUSD)
	return r
}

func queryLimit(r *http.Request, def, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func (a *ApprovalAdmin) activity(w http.ResponseWriter, r *http.Request) {
	spans, err := a.Recent.ListRecent(r.Context(), queryLimit(r, 100, 500))
	if err != nil {
		http.Error(w, "records unavailable", http.StatusServiceUnavailable)
		return
	}
	agent, kind := r.URL.Query().Get("agent"), r.URL.Query().Get("kind")
	rows := []ActivityRow{}
	for _, s := range spans {
		if !a.allowsAgent(r, s.AgentID) {
			continue
		}
		row := activityRow(s)
		if (agent != "" && row.Agent != agent) || (kind != "" && row.Kind != kind) {
			continue
		}
		rows = append(rows, row)
	}
	writeJSONBody(w, map[string]any{"records": rows})
}

type usageDay struct {
	Day    string  `json:"day"`
	Input  int     `json:"input_tokens"`
	Output int     `json:"output_tokens"`
	Calls  int     `json:"calls"`
	Cost   float64 `json:"cost_usd"`
}

func (a *ApprovalAdmin) usage(w http.ResponseWriter, r *http.Request) {
	days := 14
	if value := r.URL.Query().Get("days"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 30 {
			http.Error(w, "days must be 1 to 30", http.StatusBadRequest)
			return
		}
		days = parsed
	}
	const cap = 10000
	spans, err := a.Recent.ListRecent(r.Context(), cap)
	if err != nil {
		http.Error(w, "usage unavailable", http.StatusServiceUnavailable)
		return
	}
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1-days)
	series := make([]usageDay, days)
	for i := range series {
		series[i].Day = start.AddDate(0, 0, i).Format("2006-01-02")
	}
	for _, s := range spans {
		if s.SpanType != tracing.SpanTypeLLM || !a.allowsAgent(r, s.AgentID) {
			continue
		}
		day := s.StartedAt.UTC().Format("2006-01-02")
		idx := int(s.StartedAt.UTC().Sub(start).Hours() / 24)
		if idx < 0 || idx >= days || series[idx].Day != day {
			continue
		}
		series[idx].Calls++
		series[idx].Input += intAttr(s, tracing.AttrInputToks)
		series[idx].Output += intAttr(s, tracing.AttrOutputToks)
		series[idx].Cost += floatAttr(s, tracing.AttrCostUSD)
	}
	writeJSONBody(w, map[string]any{"days": series, "limited": len(spans) == cap})
}

// policyView is what is in force: the control plane's rules (or, standalone,
// the local file) and, in managed mode, the local floor under them.
func (a *ApprovalAdmin) policyView(w http.ResponseWriter, _ *http.Request) {
	p := a.Policy.Get()
	out := map[string]any{"rules": nil, "floor": nil}
	if p != nil {
		out["rules"] = p.Snapshot()
		if f := p.Floor(); f != nil {
			out["floor"] = f.Snapshot()
		}
	}
	writeJSONBody(w, out)
}

type checkRequest struct {
	Agent string         `json:"agent"`
	Group string         `json:"group"`
	Tool  string         `json:"tool"`
	Args  map[string]any `json:"args"`
}

// policyCheck answers "what would happen to this call now", and which side
// decided it.
func (a *ApprovalAdmin) policyCheck(w http.ResponseWriter, r *http.Request) {
	var in checkRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil || strings.TrimSpace(in.Tool) == "" {
		http.Error(w, `JSON body with "tool" required`, http.StatusBadRequest)
		return
	}
	p := a.Policy.Get()
	if p == nil {
		p = policy.AllowAll()
	}
	if in.Group == "" && a.GroupOf != nil {
		in.Group = a.GroupOf(in.Agent)
	}
	own, floor, hasFloor := p.DecisionParts(in.Agent, in.Group, in.Tool, in.Args)
	out := map[string]any{"decision": p.ToolDecisionInArgs(in.Agent, in.Group, in.Tool, in.Args), "rules": own, "group": in.Group}
	if hasFloor {
		out["floor"] = floor
	}
	writeJSONBody(w, out)
}

// policyReplay re-decides recent tool calls under the policy in force now
// and lists those that would be decided differently. Arguments are not
// recorded, so argument-scoped rules are evaluated without them.
func (a *ApprovalAdmin) policyReplay(w http.ResponseWriter, r *http.Request) {
	spans, err := a.Recent.ListRecent(r.Context(), queryLimit(r, 200, 1000))
	if err != nil {
		http.Error(w, "records unavailable", http.StatusServiceUnavailable)
		return
	}
	p := a.Policy.Get()
	if p == nil {
		p = policy.AllowAll()
	}
	type change struct {
		At       time.Time `json:"at"`
		Agent    string    `json:"agent"`
		Tool     string    `json:"tool"`
		Recorded string    `json:"recorded"`
		Now      string    `json:"now"`
	}
	changes, checked := []change{}, 0
	for _, s := range spans {
		if s.SpanType != tracing.SpanTypeTool {
			continue
		}
		row := activityRow(s)
		if row.Decision == "" || row.Name == "" {
			continue
		}
		checked++
		group := ""
		if a.GroupOf != nil {
			group = a.GroupOf(row.Agent)
		}
		now := string(p.ToolDecisionInArgs(row.Agent, group, row.Name, nil))
		if now != row.Decision {
			changes = append(changes, change{At: row.At, Agent: row.Agent, Tool: row.Name, Recorded: row.Decision, Now: now})
		}
	}
	writeJSONBody(w, map[string]any{"checked": checked, "changed": changes})
}

func (a *ApprovalAdmin) panels(w http.ResponseWriter, _ *http.Request) {
	type panel struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	}
	out := []panel{{"approvals", "Approvals"}}
	if a.Recent != nil {
		out = append(out, panel{"activity", "Activity"})
	}
	if a.Policy != nil {
		out = append(out, panel{"policy", "Policy"})
	}
	for _, p := range a.Panels {
		id, title := p.AdminPanel()
		out = append(out, panel{id, title})
	}
	out = append(out, panel{"plans", "Plans"})
	writeJSONBody(w, map[string]any{"panels": out})
}
