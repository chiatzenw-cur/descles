package storage

import (
	"sort"

	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// AggregateCosts groups spans by groupBy ("user", "agent", "project", "model",
// "provider", "day", or "total") and sums tokens and cost. Rows are sorted by
// cost descending.
func AggregateCosts(spans []*tracing.Span, groupBy string) []CostRow {
	if groupBy == "" {
		groupBy = "total"
	}
	agg := map[string]*CostRow{}
	for _, s := range spans {
		key := groupKey(s, groupBy)
		r := agg[key]
		if r == nil {
			r = &CostRow{Group: key}
			agg[key] = r
		}
		r.Requests++
		r.InputTokens += intAttr(s, tracing.AttrInputToks)
		r.OutputTokens += intAttr(s, tracing.AttrOutputToks)
		r.CachedTokens += intAttr(s, tracing.AttrCachedToks)
		r.CostUSD += floatAttr(s, tracing.AttrCostUSD)
	}
	rows := make([]CostRow, 0, len(agg))
	for _, r := range agg {
		rows = append(rows, *r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CostUSD != rows[j].CostUSD {
			return rows[i].CostUSD > rows[j].CostUSD
		}
		return rows[i].Group < rows[j].Group
	})
	return rows
}

func groupKey(s *tracing.Span, groupBy string) string {
	switch groupBy {
	case "user":
		if s.UserID != "" {
			return s.UserID
		}
		return "(unknown)"
	case "agent":
		if s.AgentID != "" {
			return s.AgentID
		}
		return "(unknown)"
	case "project":
		if s.ProjectID != "" {
			return s.ProjectID
		}
		return "(unknown)"
	case "model":
		if v := strAttr(s, tracing.AttrModel); v != "" {
			return v
		}
		return "(unknown)"
	case "provider":
		if v := strAttr(s, tracing.AttrProvider); v != "" {
			return v
		}
		return "(unknown)"
	case "day":
		return s.StartedAt.UTC().Format("2006-01-02")
	default:
		return "total"
	}
}

func intAttr(s *tracing.Span, key string) int {
	switch v := s.Attributes[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	default:
		return 0
	}
}

func floatAttr(s *tracing.Span, key string) float64 {
	switch v := s.Attributes[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	default:
		return 0
	}
}
