package policy

// A floor is a second policy that can only make decisions stricter. The edge
// uses one in managed mode: the control plane's policy arrives in the signed
// bundle, and the edge administrator's local policy file is the floor, so the
// hosted side can grant and tighten but never loosen what the edge's own
// policy denies, holds for approval or caps.

// WithFloor returns p with floor applied: every tool decision is the stricter
// of the two, and every budget the lower cap. A nil floor returns p unchanged.
func (p *Policy) WithFloor(floor *Policy) *Policy {
	if floor == nil {
		return p
	}
	if p == nil {
		p = AllowAll()
	}
	cp := *p
	cp.floor = floor
	return &cp
}

// Floor is the policy that bounds p, if any.
func (p *Policy) Floor() *Policy { return p.floor }

var strictness = map[Decision]int{Allow: 0, RateLimit: 1, RequireApproval: 2, Deny: 3}

// Stricter returns the more restrictive of two decisions.
func Stricter(a, b Decision) Decision {
	if strictness[b] > strictness[a] {
		return b
	}
	return a
}

func (p *Policy) ToolDecisionInArgs(agent, group, tool string, args map[string]any) Decision {
	d := p.ownToolDecisionInArgs(agent, group, tool, args)
	if p.floor != nil {
		d = Stricter(d, p.floor.ToolDecisionInArgs(agent, group, tool, args))
	}
	return d
}

func (p *Policy) HasArgRulesFor(agent, group, tool string) bool {
	return p.ownHasArgRulesFor(agent, group, tool) || (p.floor != nil && p.floor.HasArgRulesFor(agent, group, tool))
}

func (p *Policy) HasToolRules() bool {
	return p.ownHasToolRules() || (p.floor != nil && p.floor.HasToolRules())
}

func (p *Policy) ToolStatus(tool string) ToolStatus {
	st := p.ownToolStatus(tool)
	if p.floor != nil {
		f := p.floor.ToolStatus(tool)
		st.Decision = Stricter(st.Decision, f.Decision)
		st.HasArgRules = st.HasArgRules || f.HasArgRules
	}
	return st
}

func (p *Policy) BudgetFor(agent string) (float64, bool) {
	v, ok := p.ownBudgetFor(agent)
	if p.floor != nil {
		v, ok = lowerUSD(v, ok)(p.floor.BudgetFor(agent))
	}
	return v, ok
}

func (p *Policy) BudgetForUser(user string) (float64, bool) {
	v, ok := p.ownBudgetForUser(user)
	if p.floor != nil {
		v, ok = lowerUSD(v, ok)(p.floor.BudgetForUser(user))
	}
	return v, ok
}

func (p *Policy) TokenBudgetFor(agent string) (int64, bool) {
	v, ok := p.ownTokenBudgetFor(agent)
	if p.floor != nil {
		v, ok = lowerTokens(v, ok)(p.floor.TokenBudgetFor(agent))
	}
	return v, ok
}

func (p *Policy) TokenBudgetForUser(user string) (int64, bool) {
	v, ok := p.ownTokenBudgetForUser(user)
	if p.floor != nil {
		v, ok = lowerTokens(v, ok)(p.floor.TokenBudgetForUser(user))
	}
	return v, ok
}

// lowerUSD returns a function taking the other cap and giving the lower of
// two caps; a missing cap does not lower anything.
func lowerUSD(a float64, aok bool) func(float64, bool) (float64, bool) {
	return func(b float64, bok bool) (float64, bool) {
		switch {
		case !bok:
			return a, aok
		case !aok || b < a:
			return b, true
		}
		return a, true
	}
}

func lowerTokens(a int64, aok bool) func(int64, bool) (int64, bool) {
	return func(b int64, bok bool) (int64, bool) {
		switch {
		case !bok:
			return a, aok
		case !aok || b < a:
			return b, true
		}
		return a, true
	}
}
