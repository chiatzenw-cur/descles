package policy

import "testing"

func mustPolicy(t *testing.T, raw string) *Policy {
	t.Helper()
	p, err := FromJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFloorOnlyMakesDecisionsStricter(t *testing.T) {
	// The control plane's policy tries to loosen what the edge's floor holds.
	hosted := mustPolicy(t, `{
		"defaults": {"tools": {"github.delete_repository": "allow", "stripe.refund": "allow", "crm.read": "deny"}},
		"agents": {"bot": {"tools": {"local.bash": "allow"}}}}`)
	floor := mustPolicy(t, `{
		"defaults": {
			"tools": {"github.delete_repository": "deny", "crm.read": "allow"},
			"require_approval": ["stripe.refund"],
			"arg_tools": [{"tool": "local.bash", "args": {"command": ["*rm -rf*"]}, "decision": "deny"}]}}`)
	p := hosted.WithFloor(floor)

	for _, c := range []struct {
		agent, tool string
		args        map[string]any
		want        Decision
	}{
		{"a", "github.delete_repository", nil, Deny},                       // floor deny beats hosted allow
		{"a", "stripe.refund", nil, RequireApproval},                       // floor approval beats hosted allow
		{"a", "crm.read", nil, Deny},                                       // floor allow does not loosen hosted deny
		{"bot", "local.bash", map[string]any{"command": "rm -rf /"}, Deny}, // agent-level allow upstairs cannot override the floor
		{"bot", "local.bash", map[string]any{"command": "ls"}, Allow},
		{"a", "unlisted.tool", nil, Allow},
	} {
		if got := p.ToolDecisionInArgs(c.agent, "", c.tool, c.args); got != c.want {
			t.Errorf("%s %s %v: %s, want %s", c.agent, c.tool, c.args, got, c.want)
		}
	}
	if !p.HasToolRules() || !p.HasArgRulesFor("bot", "", "local.bash") {
		t.Error("floor rules are invisible to streaming relays")
	}
	if st := p.ToolStatus("github.delete_repository"); st.Decision != Deny {
		t.Errorf("status %+v", st)
	}
}

func TestFloorBudgetsTakeTheLowerCap(t *testing.T) {
	hosted := mustPolicy(t, `{"defaults": {"budget": {"daily_usd": 50}}, "agents": {"big": {"budget": {"daily_usd": 500, "daily_tokens": 9000000}}}}`)
	floor := mustPolicy(t, `{"defaults": {"budget": {"daily_usd": 20, "daily_tokens": 1000000}}}`)
	p := hosted.WithFloor(floor)
	if v, ok := p.BudgetFor("big"); !ok || v != 20 {
		t.Errorf("USD cap %v %v, want 20", v, ok)
	}
	if v, ok := p.TokenBudgetFor("big"); !ok || v != 1000000 {
		t.Errorf("token cap %v %v, want 1000000", v, ok)
	}
	// A floor without a cap does not remove or raise the hosted one.
	p = hosted.WithFloor(mustPolicy(t, `{}`))
	if v, ok := p.BudgetFor("x"); !ok || v != 50 {
		t.Errorf("hosted cap lost: %v %v", v, ok)
	}
	if AllowAll().WithFloor(nil).Floor() != nil {
		t.Error("nil floor should leave the policy unchanged")
	}
}
