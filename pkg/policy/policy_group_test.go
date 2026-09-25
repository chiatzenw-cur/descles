package policy

import "testing"

func TestGroupRuleLayerBetweenAgentAndDefaults(t *testing.T) {
	pol, err := FromJSON(`{
	  "defaults": {"tools": {"shell.rm": "deny"}},
	  "groups": {
	    "backend": {"tools": {"deploy_to_prod": "deny", "shell.rm": "allow"}, "require_approval": ["get_weather"]},
	    "sre": {"tools": {"kubectl.delete": "require_approval"}}
	  },
	  "agents": {
	    "ci-bot": {"tools": {"deploy_to_prod": "allow"}}
	  }
	}`)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		agent, group, tool string
		want               Decision
	}{
		// agent-specific allow overrides the group deny.
		{"ci-bot", "backend", "deploy_to_prod", Allow},
		// group rule applies to an ordinary group member.
		{"dev1", "backend", "deploy_to_prod", Deny},
		// group "allow" overrides defaults deny (explicit layer override).
		{"dev1", "backend", "shell.rm", Allow},
		// member outside the group falls back to defaults.
		{"dev2", "sre", "shell.rm", Deny},
		// group require_approval.
		{"dev1", "backend", "get_weather", RequireApproval},
		{"dev1", "sre", "kubectl.delete", RequireApproval},
		// unlisted tool allowed.
		{"dev1", "backend", "list_files", Allow},
	}
	for _, c := range cases {
		got := pol.ToolDecisionIn(c.agent, c.group, c.tool)
		if got != c.want {
			t.Errorf("ToolDecisionIn(%q,%q,%q)=%v want %v", c.agent, c.group, c.tool, got, c.want)
		}
	}
	// Legacy single-arg decision still resolves defaults (no group).
	if got := pol.ToolDecision("dev2", "shell.rm"); got != Deny {
		t.Errorf("ToolDecision without group should hit defaults, got %v", got)
	}
	if !pol.HasToolRules() {
		t.Error("HasToolRules must see group rules")
	}
}
