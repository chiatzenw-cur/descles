package policy

import (
	"encoding/json"
	"errors"
	"math"
)

// Snapshot returns a detached configuration suitable for console inspection.
func (p *Policy) Snapshot() Config {
	b, _ := json.Marshal(p.cfg)
	var c Config
	_ = json.Unmarshal(b, &c)
	return c
}

// WithBudget changes only a budget; tool rules and all other identities survive.
// A nil dailyUSD AND a nil dailyTokens removes the override (restoring the
// default when one exists). When exactly one field is set, the other cap on an
// existing override is preserved — a caller edits the cap it sends and leaves
// the sibling alone.
func (p *Policy) WithBudget(scope, id string, dailyUSD *float64, dailyTokens *int64) (*Policy, error) {
	if dailyUSD != nil && (math.IsNaN(*dailyUSD) || math.IsInf(*dailyUSD, 0) || *dailyUSD < 0) {
		return nil, errors.New("daily_usd must be a finite non-negative number")
	}
	if dailyTokens != nil && *dailyTokens < 0 {
		return nil, errors.New("daily_tokens must be a non-negative integer")
	}
	c := p.Snapshot()
	var b *Budget
	if dailyUSD != nil || dailyTokens != nil {
		var existing *Budget
		switch scope {
		case "default":
			existing = c.Defaults.Budget
		case "employee":
			existing = c.Users[id].Budget
		case "agent":
			existing = c.Agents[id].Budget
		}
		b = &Budget{}
		if existing != nil {
			b.DailyUSD = existing.DailyUSD
			b.DailyTokens = existing.DailyTokens
		}
		if dailyUSD != nil {
			b.DailyUSD = *dailyUSD
		}
		if dailyTokens != nil {
			b.DailyTokens = *dailyTokens
		}
	}
	switch scope {
	case "default":
		c.Defaults.Budget = b
	case "employee", "agent":
		if id == "" {
			return nil, errors.New("identity required")
		}
		if scope == "employee" {
			if c.Users == nil {
				c.Users = map[string]AgentPolicy{}
			}
			a := c.Users[id]
			a.Budget = b
			c.Users[id] = a
		} else {
			if c.Agents == nil {
				c.Agents = map[string]AgentPolicy{}
			}
			a := c.Agents[id]
			a.Budget = b
			c.Agents[id] = a
		}
	default:
		return nil, errors.New("unknown budget scope")
	}
	return &Policy{cfg: c}, nil
}
