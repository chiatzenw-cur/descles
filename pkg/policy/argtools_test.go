package policy

import "testing"

func argPolicy(t *testing.T) *Policy {
	p, err := FromJSON(`{
  "defaults": {
    "tools": { "terminal": "require_approval", "read_file": "allow", "execute_code": "deny" },
    "arg_tools": [
      { "tool": "read_file", "args": { "path": ["**/.env", "/etc/**"] }, "decision": "deny" },
      { "tool": "terminal", "args": { "command": ["*rm*"] }, "decision": "require_approval" }
    ]
  },
  "agents": {
    "deploy-bot": {
      "arg_tools": [
        { "tool": "terminal", "args": { "command": ["git push*"] }, "decision": "allow" }
      ]
    }
  }
}`)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestArgDenyStructuredPath(t *testing.T) {
	p := argPolicy(t)
	cases := []struct {
		path string
		want Decision
	}{
		{"/etc/passwd", Deny},
		{"/etc/ssh/sshd_config", Deny},
		{"/home/dev/app/.env", Deny},
		{".env", Deny}, // leading "**/" must also match bare .env
		{"/home/dev/app/src/main.ts", Allow},
		{"/var/log/app.log", Allow},
	}
	for _, c := range cases {
		if got := p.ToolDecisionInArgs("dev", "eng", "read_file", map[string]any{"path": c.path}); got != c.want {
			t.Errorf("read_file %s = %s, want %s", c.path, got, c.want)
		}
	}
}

func TestArgRulesBeatPlainAndLayers(t *testing.T) {
	p := argPolicy(t)
	// Finer grain within defaults: rm matches the arg rule (approval), and the
	// plain tool rule would say the same — but a rule that only rm matches and
	// plain deny exist must let the arg rule decide.
	if got := p.ToolDecisionInArgs("dev", "eng", "terminal", map[string]any{"command": "rm -rf /tmp/x"}); got != RequireApproval {
		t.Errorf("rm call = %s, want require_approval", got)
	}
	// Agent-layer arg allow overrides defaults approval (finest grain, highest layer).
	if got := p.ToolDecisionInArgs("deploy-bot", "eng", "terminal", map[string]any{"command": "git push origin main"}); got != Allow {
		t.Errorf("bot git push = %s, want allow", got)
	}
	// Other commands on the bot fall back to defaults approval.
	if got := p.ToolDecisionInArgs("deploy-bot", "eng", "terminal", map[string]any{"command": "ls"}); got != RequireApproval {
		t.Errorf("bot ls = %s, want require_approval", got)
	}
	// Argument rules require the specified key; missing key = no match.
	if got := p.ToolDecisionInArgs("dev", "eng", "terminal", map[string]any{}); got != RequireApproval {
		t.Errorf("terminal no-args = %s, want require_approval (plain rule)", got)
	}
}

func TestArgRulesMostSpecificAmongMatches(t *testing.T) {
	p, err := FromJSON(`{"defaults":{"arg_tools":[
	  {"tool":"write_file","args":{"path":["**/config/**"]},"decision":"require_approval"},
	  {"tool":"write_file","args":{"path":["**/config/prod.yaml"]},"decision":"deny"}
	]}}`)
	if err != nil {
		t.Fatal(err)
	}
	// deny beats require_approval when both arg rules match.
	if got := p.ToolDecisionInArgs("dev", "", "write_file", map[string]any{"path": "/srv/config/prod.yaml"}); got != Deny {
		t.Errorf("prod.yaml = %s, want deny", got)
	}
	if got := p.ToolDecisionInArgs("dev", "", "write_file", map[string]any{"path": "/srv/config/stage.yaml"}); got != RequireApproval {
		t.Errorf("stage.yaml = %s, want require_approval", got)
	}
}

func TestArgRuleInvalidDecisionFailsClosed(t *testing.T) {
	p, err := FromJSON(`{"defaults":{"arg_tools":[
	  {"tool":"web_search","args":{"query":["*secret*"]},"decision":"definitely"}
	]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ToolDecisionInArgs("dev", "", "web_search", map[string]any{"query": "my secret key"}); got != Deny {
		t.Errorf("invalid decision = %s, want deny (fail closed)", got)
	}
}

func TestArgRulesNonStringArgsMatchJSON(t *testing.T) {
	p, err := FromJSON(`{"defaults":{"arg_tools":[
	  {"tool":"file_edit","args":{"path":["**/package.json"]},"decision":"deny"}
	]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ToolDecisionInArgs("dev", "", "file_edit", map[string]any{"path": "repo/package.json", "mode": 644}); got != Deny {
		t.Errorf("non-string sibling arg = %s, want deny", got)
	}
}
