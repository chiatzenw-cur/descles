package trajectory

import (
	"sort"
	"time"
)

// TrueForgeEvent mirrors the event types a TrueForge runtime emits
// (turn.created, model.message, tool.response, tool.approval_required,
// turn.done, thread.done). This is our adapter #1 — we own the canonical
// schema, TrueForge is just one source feeding it.
type TrueForgeEvent struct {
	Type      string         `json:"type"`
	EventID   string         `json:"id"`
	ThreadID  string         `json:"thread_id"`
	TurnID    string         `json:"turn_id"`
	Seq       int            `json:"sequence"`
	Timestamp time.Time      `json:"timestamp"`
	Name      string         `json:"name"`
	Payload   map[string]any `json:"payload,omitempty"`
}

// IngestTrueForge rebuilds a canonical Trajectory from a TrueForge event
// stream. Events are applied in sequence order; each thread_id becomes a Turn
// (so subagents with their own thread stay reconstructable).
func IngestTrueForge(agentID, userID, sessionID string, evs []TrueForgeEvent) *Trajectory {
	sorted := append([]TrueForgeEvent(nil), evs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Seq != sorted[j].Seq {
			return sorted[i].Seq < sorted[j].Seq
		}
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	type turnBuilder struct {
		idx    int
		action *Action // currently-open approval-gated action
	}
	byTurn := map[string]*turnBuilder{}
	var turnOrder []string

	for _, ev := range sorted {
		turnID := ev.TurnID
		if turnID == "" {
			turnID = ev.ThreadID
		}
		tb, ok := byTurn[turnID]
		if !ok {
			tb = &turnBuilder{idx: len(turnOrder)}
			byTurn[turnID] = tb
			turnOrder = append(turnOrder, turnID)
		}
		ts := ev.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		switch ev.Type {
		case "tool.response":
			a := Action{
				Type:      "tool.response",
				Name:      ev.Name,
				Args:      ev.Payload,
				Outcome:   strOr(ev.Payload, "outcome", "ok"),
				Timestamp: ts,
			}
			tb.action = &a
			byTurn[turnID] = tb
			// attach to turn at build time via a pending stack
			_ = tb
			_ = a
		case "tool.approval_required":
			if tb.action != nil {
				tb.action.ApprovalRequired = true
				// approval events come after the tool response; we tag
				// the last recorded action and leave onward.
				byTurn[turnID] = tb
			}
		case "model.message":
			// recorded but not a side-effecting action
		}
	}

	// Rebuild turns in observed order. Because approval events may arrive
	// after their response, we rebuild by tracking actions in order via a
	// simpler pass (actions list per turn).
	actionsByTurn := map[string][]Action{}
	for _, ev := range sorted {
		turnID := ev.TurnID
		if turnID == "" {
			turnID = ev.ThreadID
		}
		if ev.Type != "tool.response" {
			continue
		}
		ts := ev.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		actionsByTurn[turnID] = append(actionsByTurn[turnID], Action{
			Type:      "tool.response",
			Name:      ev.Name,
			Args:      ev.Payload,
			Result:    strOr(ev.Payload, "result", ""),
			Outcome:   strOr(ev.Payload, "outcome", "ok"),
			Timestamp: ts,
		})
	}
	// apply approval flags
	for _, ev := range sorted {
		if ev.Type != "tool.approval_required" {
			continue
		}
		turnID := ev.TurnID
		if turnID == "" {
			turnID = ev.ThreadID
		}
		al := actionsByTurn[turnID]
		if len(al) > 0 {
			al[len(al)-1].ApprovalRequired = true
			actionsByTurn[turnID] = al
		}
	}

	var turns []Turn
	for _, turnID := range turnOrder {
		turns = append(turns, Turn{TurnID: turnID, Index: len(turns), Actions: actionsByTurn[turnID]})
	}

	t := &Trajectory{
		ID: sessionID, AgentID: agentID, UserID: userID, SessionID: sessionID,
		Turns: turns, StartedAt: time.Now().UTC(), EndedAt: time.Now().UTC(),
	}
	// outcome: failure if any action errored/timeout
	t.Success = true
	t.Outcome = "success"
	for _, a := range t.Actions() {
		if a.Outcome != "ok" {
			t.Success = false
			t.Outcome = a.Outcome
			break
		}
	}
	return t
}

func strOr(m map[string]any, key, def string) string {
	if m == nil {
		return def
	}
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return def
}
