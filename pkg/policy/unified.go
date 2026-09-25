package policy

import (
	"encoding/json"
	"strings"
)

// ModelPolicy is a per-model rule.
type ModelPolicy struct {
	Allow         bool    `json:"allow,omitempty"`
	MaxCostPerRun float64 `json:"max_cost_per_run,omitempty"`
}

// ResourcePolicy is the per-resource rule: capabilities allowed on a resource.
type ResourcePolicy struct {
	Read  string `json:"read,omitempty"`
	Write string `json:"write,omitempty"`
}

// AgentRules is the unified per-agent policy across model/capability/resource.
type AgentRules struct {
	Models       map[string]ModelPolicy    `json:"models,omitempty"`
	Capabilities map[string]string         `json:"capabilities,omitempty"`
	Resources    map[string]ResourcePolicy `json:"resources,omitempty"`
	Budget       *Budget                   `json:"budget,omitempty"`
}

// UnifiedConfig is the raw unified policy document.
type UnifiedConfig struct {
	Defaults AgentRules            `json:"defaults,omitempty"`
	Agents   map[string]AgentRules `json:"agents,omitempty"`
}

// Unified is a compiled unified policy. It answers one question across all
// three layers: may this identity use this model, perform this capability,
// on this resource, under this verb?
type Unified struct {
	cfg UnifiedConfig
}

// ParseUnified parses a unified policy. Empty input yields allow-all.
func ParseUnified(raw string) (*Unified, error) {
	if strings.TrimSpace(raw) == "" {
		return &Unified{}, nil
	}
	var cfg UnifiedConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, err
	}
	return &Unified{cfg: cfg}, nil
}

// DecisionRequest is one evaluation across all three layers. Verb is "read" or
// "write" when a resource is in scope; empty otherwise.
type DecisionRequest struct {
	Agent      string
	Model      string
	Capability string
	Resource   string
	Verb       string
}

// Decide evaluates the unified policy. Most-restrictive wins: deny >
// require_approval > allow. Context (e.g. a low-trust knowledge crossing) can
// only raise a decision later, never lower it.
func (u *Unified) Decide(req DecisionRequest) Decision {
	d := Allow
	_, hasAgent := u.cfg.Agents[req.Agent]

	// Model dimension — an explicit denial is absolute.
	if mp, ok := u.modelRule(req.Agent, req.Model, hasAgent); ok && !mp.Allow {
		return Deny
	}
	// Capability dimension.
	d = tighter(d, u.capDecision(req.Agent, req.Capability, hasAgent))
	// Resource dimension.
	if req.Resource != "" && req.Verb != "" {
		rp := u.resourceRule(req.Agent, req.Resource, hasAgent)
		switch req.Verb {
		case "read":
			d = tighter(d, Decision(rp.Read))
		case "write":
			d = tighter(d, Decision(rp.Write))
		}
	}
	return d
}

func (u *Unified) modelRule(agent, model string, hasAgent bool) (ModelPolicy, bool) {
	if hasAgent {
		if mp, ok := u.cfg.Agents[agent].Models[model]; ok {
			return mp, true
		}
	}
	if mp, ok := u.cfg.Defaults.Models[model]; ok {
		return mp, true
	}
	return ModelPolicy{}, false
}

func (u *Unified) capDecision(agent, capability string, hasAgent bool) Decision {
	if hasAgent {
		if v, ok := u.cfg.Agents[agent].Capabilities[capability]; ok {
			return normalize(v)
		}
	}
	if v, ok := u.cfg.Defaults.Capabilities[capability]; ok {
		return normalize(v)
	}
	return Allow
}

func (u *Unified) resourceRule(agent, resource string, hasAgent bool) ResourcePolicy {
	if hasAgent {
		if rp, ok := u.cfg.Agents[agent].Resources[resource]; ok {
			return rp
		}
	}
	if rp, ok := u.cfg.Defaults.Resources[resource]; ok {
		return rp
	}
	return ResourcePolicy{}
}

func normalize(v string) Decision {
	switch v {
	case "deny":
		return Deny
	case "require_approval":
		return RequireApproval
	case "rate_limit":
		return RateLimit
	default:
		return Allow
	}
}

func tighter(a, b Decision) Decision {
	rank := map[Decision]int{Allow: 0, RequireApproval: 1, RateLimit: 2, Deny: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
