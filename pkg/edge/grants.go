package edge

import "strings"

func (s *BundleState) ToolAllowed(agentID, tool string, args map[string]any) bool {
	grant, ok := s.AgentGrant(agentID)
	if !ok || !permissionCovers(grant.Permission, tool) {
		return false
	}
	if grant.Resource == "*" {
		return true
	}
	matched := false
	for _, field := range []string{"resource", "target", "path", "url", "repo"} {
		if raw, present := args[field]; present {
			value, ok := raw.(string)
			if !ok || value != grant.Resource {
				return false
			}
			matched = true
		}
	}
	return matched
}

// ToolPermitted reports whether the agent's grant covers tool by name,
// before any resource check. It decides what a tool listing may show.
func (s *BundleState) ToolPermitted(agentID, tool string) bool {
	grant, ok := s.AgentGrant(agentID)
	return ok && permissionCovers(grant.Permission, tool)
}

// ConnectorPermitted reports whether the grant covers any tool of connector.
func (s *BundleState) ConnectorPermitted(agentID, connector string) bool {
	grant, ok := s.AgentGrant(agentID)
	if !ok {
		return false
	}
	held := strings.TrimSpace(grant.Permission)
	return held == "*" || strings.HasPrefix(held, connector+".")
}

// ContextLabels are the organization-context clearances the control plane
// granted this agent.
func (s *BundleState) ContextLabels(agentID string) []string {
	grant, ok := s.AgentGrant(agentID)
	if !ok {
		return nil
	}
	return grant.ContextLabels
}

func (s *BundleState) ProviderAllowed(agentID, providerName string) bool {
	grant, ok := s.AgentGrant(agentID)
	if !ok {
		return false
	}
	if len(grant.AllowedProviders) == 0 {
		return grant.Permission == "*"
	}
	for _, allowed := range grant.AllowedProviders {
		if allowed == providerName {
			return true
		}
	}
	return false
}

func permissionCovers(held, want string) bool {
	held, want = strings.TrimSpace(held), strings.TrimSpace(want)
	if want == "" {
		return false
	}
	if held == "*" || held == want {
		return true
	}
	return strings.HasSuffix(held, ".*") && strings.HasPrefix(want, strings.TrimSuffix(held, "*"))
}
