package policy

import "testing"

func TestBudgetEditorPreservesPolicyAndInheritance(t *testing.T) {
	p, e := FromJSON(`{"defaults":{"budget":{"daily_usd":20},"tools":{"delete":"deny"}},"users":{"alice":{"tools":{"send":"require_approval"}}},"agents":{"worker":{"tools":{"shell":"deny"}}}}`)
	if e != nil {
		t.Fatal(e)
	}
	amount := 5.0
	q, e := p.WithBudget("employee", "alice", &amount, nil)
	if e != nil {
		t.Fatal(e)
	}
	if n, _ := q.BudgetForUser("alice"); n != 5 {
		t.Fatal(n)
	}
	if n, _ := p.BudgetForUser("alice"); n != 20 {
		t.Fatal("mutated original")
	}
	if q.Snapshot().Users["alice"].Tools["send"] != "require_approval" || q.ToolDecision("worker", "shell") != Deny {
		t.Fatal("lost tool rules")
	}
	q, e = q.WithBudget("employee", "alice", nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	if n, _ := q.BudgetForUser("alice"); n != 20 {
		t.Fatal("did not restore inheritance")
	}
	amount = -1
	if _, e = q.WithBudget("agent", "worker", &amount, nil); e == nil {
		t.Fatal("negative budget accepted")
	}
	amount = 0
	q, e = q.WithBudget("agent", "worker", &amount, nil)
	if e != nil {
		t.Fatal(e)
	}
	if n, ok := q.BudgetFor("worker"); !ok || n != 0 {
		t.Fatal("zero must remain explicit")
	}
}

func TestTokenBudgetEditor(t *testing.T) {
	p, e := FromJSON(`{"defaults":{"budget":{"daily_usd":10,"daily_tokens":100000}}}`)
	if e != nil {
		t.Fatal(e)
	}
	if n, ok := p.BudgetFor("any"); !ok || n != 10 {
		t.Fatal("usd cap lost")
	}
	if n, ok := p.TokenBudgetFor("any"); !ok || n != 100000 {
		t.Fatal("default token cap", n, ok)
	}
	tok := int64(5000)
	q, e := p.WithBudget("agent", "worker", nil, &tok)
	if e != nil {
		t.Fatal(e)
	}
	if n, ok := q.TokenBudgetFor("worker"); !ok || n != 5000 {
		t.Fatal("token override", n, ok)
	}
	// A token-only override means USD is not the governing unit for worker.
	if _, ok := q.BudgetFor("worker"); ok {
		t.Fatal("token-only budget still reported a USD cap")
	}
	// An explicit zero token cap is not a cap (tokens: 0 = unset).
	zero := int64(0)
	q, e = q.WithBudget("agent", "worker", nil, &zero)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := q.TokenBudgetFor("worker"); ok {
		t.Fatal("zero token cap treated as configured")
	}
	// Clearing the override restores the default token cap.
	q, e = q.WithBudget("agent", "worker", nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	if n, ok := q.TokenBudgetFor("worker"); !ok || n != 100000 {
		t.Fatal("inherit after remove", n, ok)
	}
	neg := int64(-1)
	if _, e = q.WithBudget("agent", "worker", nil, &neg); e == nil {
		t.Fatal("negative token budget accepted")
	}
}
