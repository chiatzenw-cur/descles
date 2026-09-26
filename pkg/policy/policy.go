// Package policy evaluates the per-agent rules that decide whether a request
// or action should be allowed (M4). Input is a JSON/DESCLES_POLICY config:
//
//	{"agents":{"coding-agent":{"budget":{"daily_usd":5},"tools":{"shell.execute":"deny"}}},"defaults":{}}
//
// A decision is recorded on every span as the policy_decision attribute, and
// policy events are surfaced in the audit view. Budget enforcement is applied
// at the gateway now; tool execution gating becomes live once the MCP gateway
// (M3) ships.
package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Decision is the outcome of evaluating a rule.
type Decision string

const (
	Allow           Decision = "allow"
	Deny            Decision = "deny"
	RequireApproval Decision = "require_approval"
	RateLimit       Decision = "rate_limit"
)

// Budget is a daily limit. DailyUSD is enforced when the budget carries a
// positive USD cap OR no token cap at all (preserving the legacy meaning that
// a zero USD override blocks the next request). When DailyTokens is positive
// it is enforced too; a token-only budget (USD 0 + tokens > 0) disables the
// USD gate for that subject so a token cap can stand alone.
type Budget struct {
	DailyUSD    float64 `json:"daily_usd"`
	DailyTokens int64   `json:"daily_tokens,omitempty"`
}

// AgentPolicy holds the rules for one agent.
type AgentPolicy struct {
	Budget          *Budget           `json:"budget,omitempty"`
	Tools           map[string]string `json:"tools,omitempty"`            // tool -> decision
	RequireApproval []string          `json:"require_approval,omitempty"` // tools needing approval
	ArgTools        []ToolRule        `json:"arg_tools,omitempty"`        // argument-scoped rules (finest granularity)
}

// Config is the raw parsed policy.
type Config struct {
	Defaults AgentPolicy            `json:"defaults,omitempty"`
	Agents   map[string]AgentPolicy `json:"agents,omitempty"`
	// Groups maps a group (workspace) name to rules shared by every agent in
	// that group — the middle layer of the unified model (agent > group >
	// defaults). Group names are the workspace names from the control plane.
	Groups map[string]AgentPolicy `json:"groups,omitempty"`
	Users  map[string]AgentPolicy `json:"users,omitempty"` // deprecated (unified model); kept for reads
}

// HasToolRules reports whether the policy configures any tool decisions
// (deny/require_approval) anywhere a decision can come from. Streaming relay only
// needs buffering when this is true, and the decision layer honours groups
// (agent > group > defaults), so groups must be inspected too: a rule configured
// only on a group otherwise let tools stream through unenforced.
func (p *Policy) ownHasToolRules() bool {
	if hasRules(p.cfg.Defaults) {
		return true
	}
	for _, a := range p.cfg.Agents {
		if hasRules(a) {
			return true
		}
	}
	for _, g := range p.cfg.Groups {
		if hasRules(g) {
			return true
		}
	}
	for _, u := range p.cfg.Users {
		if hasRules(u) {
			return true
		}
	}
	return false
}

func hasRules(a AgentPolicy) bool {
	return len(a.Tools) > 0 || len(a.RequireApproval) > 0 || len(a.ArgTools) > 0
}

// Policy is an immutable compiled policy.
type Policy struct {
	cfg Config
	// floor, when set, can only make decisions stricter (see WithFloor).
	floor *Policy
}

// FromJSON parses a policy from a JSON string. Empty input yields an all-allow
// policy.
func FromJSON(raw string) (*Policy, error) {
	if strings.TrimSpace(raw) == "" {
		return &Policy{}, nil
	}
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, err
	}
	return &Policy{cfg: cfg}, nil
}

// AllowAll returns an empty policy that allows everything (no budgets, no
// tool denials). Useful for tests and as a safe default.
func AllowAll() *Policy { return &Policy{} }

// BudgetFor returns the daily USD budget for an agent (agent-specific first,
// then defaults). ok is false when no USD cap is in force: nothing configured,
// or a token-only budget where USD is not the governing unit.
func (p *Policy) ownBudgetFor(agent string) (dailyUSD float64, ok bool) {
	return budgetUSD(p.budgetForAgent(agent))
}

// TokenBudgetFor returns the daily token budget for an agent (agent-specific
// first, then defaults). ok is false when no token cap is configured.
func (p *Policy) ownTokenBudgetFor(agent string) (dailyTokens int64, ok bool) {
	return budgetTokens(p.budgetForAgent(agent))
}

// BudgetForUser returns the daily USD budget for an employee (user-specific
// first, then defaults) — legacy user dimension.
func (p *Policy) ownBudgetForUser(user string) (dailyUSD float64, ok bool) {
	return budgetUSD(p.budgetForUser(user))
}

// TokenBudgetForUser returns the daily token budget for an employee.
func (p *Policy) ownTokenBudgetForUser(user string) (dailyTokens int64, ok bool) {
	return budgetTokens(p.budgetForUser(user))
}

func (p *Policy) budgetForAgent(agent string) *Budget {
	if a, found := p.cfg.Agents[agent]; found && a.Budget != nil {
		return a.Budget
	}
	return p.cfg.Defaults.Budget
}

func (p *Policy) budgetForUser(user string) *Budget {
	if u, found := p.cfg.Users[user]; found && u.Budget != nil {
		return u.Budget
	}
	return p.cfg.Defaults.Budget
}

// budgetUSD reports the effective USD cap. A configured budget always governs
// in USD unless it carries a token cap and no positive USD cap (token-only).
func budgetUSD(b *Budget) (float64, bool) {
	if b == nil {
		return 0, false
	}
	if b.DailyTokens == 0 || b.DailyUSD > 0 {
		return b.DailyUSD, true
	}
	return 0, false
}

// budgetTokens reports the effective token cap. Zero or absent is "no cap".
func budgetTokens(b *Budget) (int64, bool) {
	if b == nil || b.DailyTokens <= 0 {
		return 0, false
	}
	return b.DailyTokens, true
}

// ToolRule refines a tool decision by argument globs. A rule matches a call
// when Tool matches the tool name (same wildcard rules as plain tools) and,
// when Args is non-empty, every listed arg key matches at least one glob
// against the string form of that argument. '*' matches any run of characters.
// Rules are evaluated before plain tool rules within a layer (finest
// granularity wins); among matching rules deny > require_approval > allow.
type ToolRule struct {
	Tool     string              `json:"tool"`
	Args     map[string][]string `json:"args,omitempty"`
	Decision string              `json:"decision"`
}

// ToolDecision returns the decision for a tool call requested by an agent
// (agent rules, then defaults). Prefer ToolDecisionIn when the agent's group
// is known so group rules apply between agent and defaults.
func (p *Policy) ToolDecision(agent, tool string) Decision {
	return p.ToolDecisionInArgs(agent, "", tool, nil)
}

// ToolDecisionIn resolves a tool call with the full unified chain:
// agent-specific rules win, then the agent's group rules, then defaults.
// Unlisted tools are allowed. deny anywhere in a matched layer wins inside
// that layer; an explicit agent/group "allow" still overrides a lower-layer
// rule (layer ordering is the override mechanism).
func (p *Policy) ToolDecisionIn(agent, group, tool string) Decision {
	return p.ToolDecisionInArgs(agent, group, tool, nil)
}

// ToolDecisionInArgs resolves a tool call together with its arguments,
// walking the unified chain agent > group > defaults. Within a layer,
// argument-scoped rules (ArgTools) are evaluated first — finest granularity
// wins — and among matching arg rules deny > require_approval > allow. When
// no arg rule matches, the plain tool rules / legacy RequireApproval decide.
// The first layer that yields any matching rule wins, so an explicit allow at
// a higher layer overrides a lower layer's deny. args may be nil when unknown;
// only arg rules with an empty Args spec match then.
func (p *Policy) ownToolDecisionInArgs(agent, group, tool string, args map[string]any) Decision {
	if d, ok := decisionForLayer(p.cfg.Agents[agent], tool, args); ok {
		return d
	}
	if group != "" {
		if d, ok := decisionForLayer(p.cfg.Groups[group], tool, args); ok {
			return d
		}
	}
	if d, ok := decisionForLayer(p.cfg.Defaults, tool, args); ok {
		return d
	}
	return Allow
}

// decisionForLayer resolves one AgentPolicy layer. Argument rules decide
// first; their strongest matched decision returns. Otherwise plain rules.
func decisionForLayer(ap AgentPolicy, tool string, args map[string]any) (Decision, bool) {
	if d, ok := argRulesDecision(ap.ArgTools, tool, args); ok {
		return d, true
	}
	return decisionFor(ap, tool)
}

// HasArgRulesFor reports whether any scope layer defines an argument-scoped
// rule that could match this tool. Streaming relays use it to defer a
// name-only "allow" until arguments are known, because a relayed function call
// cannot be retracted once emitted.
func (p *Policy) ownHasArgRulesFor(agent, group, tool string) bool {
	aps := []AgentPolicy{p.cfg.Agents[agent], p.cfg.Defaults}
	if group != "" {
		aps = append(aps, p.cfg.Groups[group])
	}
	for _, ap := range aps {
		for _, rule := range ap.ArgTools {
			if len(rule.Args) > 0 && matchToolPattern(rule.Tool, tool) {
				return true
			}
		}
	}
	return false
}

func argRulesDecision(rules []ToolRule, tool string, args map[string]any) (Decision, bool) {
	var best Decision
	bestRank := -1
	for _, rule := range rules {
		if !matchToolPattern(rule.Tool, tool) || !ruleArgsMatch(rule, args) {
			continue
		}
		d := normalizeDecision(rule.Decision)
		if rank := decisionRank(d); rank > bestRank {
			best, bestRank = d, rank
		}
	}
	if best == "" {
		return Allow, false
	}
	return best, true
}

// decisionRank orders deny > require_approval > allow. An invalid decision in
// an arg rule is treated as deny (same fail-safe as plain tool maps).
func decisionRank(d Decision) int {
	switch d {
	case Deny:
		return 3
	case RequireApproval:
		return 2
	case Allow:
		return 1
	default:
		return 3
	}
}

func normalizeDecision(s string) Decision {
	switch s {
	case "allow":
		return Allow
	case "deny":
		return Deny
	case "require_approval":
		return RequireApproval
	default:
		return Deny
	}
}

// ruleArgsMatch reports whether every arg key of the rule matches at least one
// glob against the string form of the call's argument. An empty Args spec
// matches any call (acts like a plain rule at the arg layer). When args are
// unknown (nil) and the rule specifies keys, it cannot match.
func ruleArgsMatch(rule ToolRule, args map[string]any) bool {
	if len(rule.Args) == 0 {
		return true
	}
	for key, patterns := range rule.Args {
		value, present := args[key]
		if !present || !anyPatternMatches(patterns, argString(value)) {
			return false
		}
	}
	return true
}

func anyPatternMatches(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if globMatch(pattern, value) {
			return true
		}
	}
	return false
}

// globMatch matches a '*' glob against value, treating "**/" as an optional
// leading directory run. All other characters match literally.
func globMatch(pattern, value string) bool {
	re, err := globRegexp(pattern)
	if err != nil {
		return pattern == value
	}
	return re.MatchString(value)
}

// argString renders an argument value for glob matching: strings pass
// through, anything else gets its compact JSON form.
func argString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
		return fmt.Sprint(v)
	}
}

// globRegexp compiles a '*' glob to an anchored regexp. A leading "**/" is
// treated as an optional directory run ("**/.env" also matches ".env").
func globRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	if strings.HasPrefix(pattern, "**/") {
		b.WriteString("(?:.*/)?")
		pattern = pattern[3:]
	}
	for _, r := range pattern {
		if r == '*' {
			b.WriteString(".*")
		} else {
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

func decisionFor(ap AgentPolicy, tool string) (Decision, bool) {
	if d, ok := matchToolDecision(ap.Tools, tool); ok && d != "" {
		return Decision(d), true
	}
	for _, t := range ap.RequireApproval {
		if matchToolPattern(t, tool) {
			return RequireApproval, true
		}
	}
	return Allow, false
}

// ToolStatus describes the org-wide (defaults-layer) disposition of one tool
// for inventory labelling. Decision is allow / require_approval / deny;
// HasArgRules marks that argument-scoped rules refine it (a tool may be
// allow + arg-deny on .env, i.e. "partial").
type ToolStatus struct {
	Decision    Decision `json:"decision"`
	HasArgRules bool     `json:"has_arg_rules"`
}

func (p *Policy) ownToolStatus(tool string) ToolStatus {
	var st ToolStatus
	ap := p.cfg.Defaults
	for _, rule := range ap.ArgTools {
		if len(rule.Args) > 0 && matchToolPattern(rule.Tool, tool) {
			st.HasArgRules = true
			break
		}
	}
	d, ok := decisionFor(ap, tool)
	if !ok || d == "" {
		d = Allow
	}
	st.Decision = d
	return st
}

func matchToolDecision(patterns map[string]string, tool string) (string, bool) {
	result := ""
	for pat, d := range patterns {
		if matchToolPattern(pat, tool) {
			if d != "allow" && d != "deny" && d != "require_approval" {
				return "deny", true
			}
			if d == "deny" {
				return d, true
			}
			if result == "" || d == "require_approval" {
				result = d
			}
		}
	}
	if result != "" {
		return result, true
	}

	return "", false
}

// normalizeToolName treats '.' and '_' as the same namespace separator.
// Policy files conventionally write namespaced tools as "shell.rm", but OpenAI
// function names forbid '.' (must match ^[a-zA-Z0-9_-]+$), so runtimes send
// "shell_rm". Normalizing both sides lets one rule match either spelling —
// the policy written for the action path (dot names) also governs LLM tool
// calls (underscore names) without duplicating every rule.
func normalizeToolName(s string) string {
	return strings.ReplaceAll(s, ".", "_")
}

func matchToolPattern(pattern, tool string) bool {
	pattern = normalizeToolName(pattern)
	tool = normalizeToolName(tool)
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(tool, strings.TrimSuffix(pattern, "*"))
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(tool, strings.TrimPrefix(pattern, "*"))
	}
	return pattern == tool
}
