// Package trajectory holds the canonical agent-run model that our pipeline
// consumes. We OWN this schema; any runtime (TrueForge, Hermes, Claude Code,
// a browser recorder for human runs, ...) is just an adapter into it.
//
// shape:  Agent -> Session -> Turn -> Action (ordered), subagents get their
// own Turn/Session so delegation stays reconstructable.
package trajectory

import (
	"fmt"
	"math/rand"
	"time"
)

// Action is one policy-relevant step a run performed.
type Action struct {
	Type             string         `json:"type"` // "tool.response" | "model.message" | "shell" | ...
	Name             string         `json:"name"` // tool name, e.g. "process_refund"
	Args             map[string]any `json:"args,omitempty"`
	Result           string         `json:"result,omitempty"`
	Outcome          string         `json:"outcome,omitempty"`           // "ok" | "error" | "timeout"
	ApprovalRequired bool           `json:"approval_required,omitempty"` // enforce-fanout
	Approved         bool           `json:"approved,omitempty"`
	Timestamp        time.Time      `json:"timestamp"`
}

// Turn groups a set of ordered actions (a subagent gets its own Turn).
type Turn struct {
	TurnID  string   `json:"turn_id"`
	Index   int      `json:"index"`
	Actions []Action `json:"actions"`
}

// Trajectory is a complete normalized run.
type Trajectory struct {
	ID        string        `json:"id"`
	AgentID   string        `json:"agent_id"`
	UserID    string        `json:"user_id"`
	SessionID string        `json:"session_id"`
	Turns     []Turn        `json:"turns"`
	Outcome   string        `json:"outcome"` // "success" | "failure" | "timeout"
	Success   bool          `json:"success"`
	Duration  time.Duration `json:"duration"`
	Cost      float64       `json:"cost"`
	StartedAt time.Time     `json:"started_at"`
	EndedAt   time.Time     `json:"ended_at"`
}

// Actions flattens all turns' actions in execution order.
func (t *Trajectory) Actions() []Action {
	var out []Action
	for _, turn := range t.Turns {
		out = append(out, turn.Actions...)
	}
	return out
}

// StepNames returns ordered action names.
func (t *Trajectory) StepNames() []string {
	names := make([]string, 0)
	for _, a := range t.Actions() {
		names = append(names, a.Name)
	}
	return names
}

// randSeq is a small deterministic PRNG for synthetic runs.
func randSeq(seed int64) *rand.Rand { return rand.New(rand.NewSource(seed)) }

// SyntheticRefundRuns builds n varied "customer refund request" runs with
// structure:
//
//	lookup_customer -> lookup_order -> inspect_refund_policy
//	    -> [deteminate_eligibility] -> process_refund(APPROVAL) -> notify_customer
//	    (ineligible -> escalate branch; occasionally skipped determine_eligibility)
//
// This is the fixture the demo/tests run through the discovery pipeline.
func SyntheticRefundRuns(n int, seed int64) []*Trajectory {
	rng := randSeq(seed)
	out := make([]*Trajectory, 0, n)
	for i := 0; i < n; i++ {
		runID := fmt.Sprintf("run-%03d", i)

		cust := fmt.Sprintf("cust-%06d", rng.Intn(999999))
		order := fmt.Sprintf("ord-%07d", rng.Intn(9999999))
		reason := []string{"wrong_item", "duplicate_charge", "damaged", "late_delivery"}[rng.Intn(4)]
		pay := []string{"card", "paypal", "bank_transfer"}[rng.Intn(3)]
		amount := float64(20 + rng.Intn(180))
		elig := rng.Intn(10) < 8            // 80% eligible
		approvalPending := rng.Intn(10) < 9 // 90% require + get approval

		actions := []Action{
			{Type: "tool.response", Name: "lookup_customer", Args: map[string]any{"customer_id": cust}, Outcome: "ok"},
			{Type: "tool.response", Name: "lookup_order", Args: map[string]any{"order_id": order}, Outcome: "ok"},
			{Type: "tool.response", Name: "inspect_refund_policy", Args: map[string]any{"reason": reason, "amount": amount}, Outcome: "ok"},
		}

		if rng.Intn(10) != 0 { // usually run eligibility
			actions = append(actions, Action{Type: "tool.response", Name: "determine_eligibility", Args: map[string]any{"eligible": elig, "reason": reason}, Outcome: "ok"})
		}

		if elig {
			actions = append(actions, Action{
				Type: "tool.response", Name: "process_refund",
				Args:             map[string]any{"amount": amount, "refund_id": fmt.Sprintf("rf-%08d", rng.Intn(99999999)), "payment_method": pay},
				ApprovalRequired: true, Approved: approvalPending, Outcome: "ok",
			})
			actions = append(actions, Action{Type: "tool.response", Name: "notify_customer", Args: map[string]any{"channel": "email"}, Outcome: "ok"})
		} else {
			actions = append(actions, Action{Type: "tool.response", Name: "escalate_to_manager", Args: map[string]any{"reason": reason}, Outcome: "ok"})
			actions = append(actions, Action{Type: "tool.response", Name: "notify_customer", Args: map[string]any{"channel": "email"}, Outcome: "ok"})
		}

		success := rng.Intn(10) < 9
		if !success {
			// a failure run usually times out at process_refund
			p := &actions[len(actions)-2]
			p.Outcome = "timeout"
		}

		start := time.Now().UTC().Add(-time.Duration(rng.Intn(50)+10) * time.Minute)
		out = append(out, &Trajectory{
			ID: runID, AgentID: "refund-agent", UserID: "ursula", SessionID: fmt.Sprintf("sess-%04d", i),
			Turns:   []Turn{{TurnID: fmt.Sprintf("t-%03d", i), Index: 0, Actions: actions}},
			Outcome: outcomeStr(success), Success: success,
			Duration:  time.Duration(3+rng.Intn(25)) * time.Minute,
			Cost:      float64(10+rng.Intn(90)) / 100.0,
			StartedAt: start, EndedAt: start.Add(time.Duration(3+rng.Intn(25)) * time.Minute),
		})
	}
	return out
}

func outcomeStr(s bool) string {
	if s {
		return "success"
	}
	return "failure"
}
