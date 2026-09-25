package policy

import "testing"

func TestFromJSONAndDecisions(t *testing.T) {
	p, err := FromJSON(`{
	  "defaults":{"budget":{"daily_usd":10},"tools":{"github.delete_repository":"deny","shell.*":"deny"}},
	  "agents":{"coding-agent":{"budget":{"daily_usd":0.05},"require_approval":["shell.execute"]}}
	}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if d, ok := p.BudgetFor("coding-agent"); !ok || d != 0.05 {
		t.Errorf("coding-agent budget = %v/%v", d, ok)
	}
	if d, ok := p.BudgetFor("other-agent"); !ok || d != 10 {
		t.Errorf("default budget = %v/%v", d, ok)
	}
	if p.ToolDecision("coding-agent", "shell.execute") != RequireApproval {
		t.Error("shell.execute should require approval")
	}
	if p.ToolDecision("coding-agent", "other") != Allow {
		t.Error("unlisted tool should be allow")
	}
	if p.ToolDecision("nobody", "github.delete_repository") != Deny {
		t.Error("default github.delete_repository tool deny should apply")
	}
	if p.ToolDecision("nobody", "shell.execute") != Deny {
		t.Error("default shell.* wildcard deny should apply")
	}
}

func TestAllowAll(t *testing.T) {
	p := AllowAll()
	if _, ok := p.BudgetFor("x"); ok {
		t.Error("AllowAll should have no budget")
	}
	if p.ToolDecision("x", "shell.execute") != Allow {
		t.Error("AllowAll should allow all tools")
	}
}

func TestBudgetForUser(t *testing.T) {
	p, err := FromJSON(`{
	  "defaults":{"budget":{"daily_usd":10}},
	  "users":{"alice":{"budget":{"daily_usd":2.50}}}
	}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d, ok := p.BudgetForUser("alice"); !ok || d != 2.50 {
		t.Errorf("alice budget = %v/%v", d, ok)
	}
	if d, ok := p.BudgetForUser("bob"); !ok || d != 10 {
		t.Errorf("default budget = %v/%v", d, ok)
	}
}

func TestToolNameNormalization(t *testing.T) {
	// Policy rules conventionally use dot names (shell.rm); OpenAI function
	// names forbid '.', so runtimes send underscores (shell_rm). Both must
	// match the same rule.
	p, err := FromJSON(`{"defaults":{"tools":{"shell.rm":"deny","github.create_issue":"require_approval"}}}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.ToolDecision("x", "shell_rm") != Deny {
		t.Error("dot rule shell.rm should match underscore tool shell_rm")
	}
	if p.ToolDecision("x", "shell.rm") != Deny {
		t.Error("dot rule shell.rm should match dot tool shell.rm")
	}
	if p.ToolDecision("x", "github_create_issue") != RequireApproval {
		t.Error("dot rule github.create_issue should match underscore tool github_create_issue")
	}
	if p.ToolDecision("x", "shell_r") != Allow {
		t.Error("partial underscore name should NOT match shell.rm (no wildcard)")
	}
	if p.ToolDecision("x", "get_weather") != Allow {
		t.Error("unlisted tool should still be allow")
	}
}
