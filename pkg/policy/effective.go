package policy

// EffectivePermissions intersects a skill's requested capabilities with the
// agent's policy. The agent's policy is a hard ceiling: a skill can only
// narrow it, never expand it. This is the code behind the "install a skill"
// → "what did I actually grant?" view, and behind the invariant that skills
// cannot expand agent authority.
//
// requested maps a capability to the skill's declared decision ("allow",
// "deny", "require_approval"). agentDecide returns the agent's own policy
// decision for a capability.
func EffectivePermissions(requested map[string]string, agentDecide func(capability string) Decision) map[string]Decision {
	out := make(map[string]Decision, len(requested))
	for cap, want := range requested {
		agent := agentDecide(cap)
		eff := agent
		switch want {
		case "deny":
			eff = Deny
		case "require_approval":
			eff = tighter(agent, RequireApproval)
		case "allow":
			// no-op: a skill's "allow" never expands the agent's policy.
			eff = agent
		default:
			eff = agent
		}
		out[cap] = eff
	}
	return out
}
