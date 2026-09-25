package edge

import (
	"errors"
	"strings"
)

// ReportOther replaces any value an administrator has not approved for
// reporting. The original value stays in the edge's local record.
const ReportOther = "other"

// ErrInvalidMetadata marks a record the metadata contract rejects. It is a
// bug or bad input for that one record, never a reason to stop the edge;
// only a failure to persist a valid record is.
var ErrInvalidMetadata = errors.New("invalid metadata")

// ReportFilter decides which client-influenced values may leave the edge.
// Field names alone do not keep content out: a client can put anything into
// a model name. So model and provider names are reported only when they are
// on an approved list, and everything else is reported as "other".
//
// Approved models come from the edge administrator: exact model names in the
// provider config (wildcards approve routing, not reporting) and
// DESCLES_EDGE_REPORT_MODELS. Tool names are made reportable where they are
// recorded (see MCPGateway.reportableTool).
type ReportFilter struct {
	Models    map[string]bool
	Providers map[string]bool
}

// NewReportFilter builds a filter from admin-approved names.
func NewReportFilter(models, providers []string) *ReportFilter {
	f := &ReportFilter{Models: map[string]bool{}, Providers: map[string]bool{}}
	for _, m := range models {
		if m = strings.TrimSpace(m); m != "" && !strings.Contains(m, "*") {
			f.Models[m] = true
		}
	}
	for _, p := range providers {
		if p = strings.TrimSpace(p); p != "" {
			f.Providers[p] = true
		}
	}
	return f
}

// Apply maps a record's client-influenced fields to reportable values. A nil
// filter approves nothing.
func (f *ReportFilter) Apply(m Metadata) Metadata {
	if m.Model != "" && (f == nil || !f.Models[m.Model]) {
		m.Model = ReportOther
	}
	if m.Provider != "" && (f == nil || !f.Providers[m.Provider]) {
		m.Provider = ReportOther
	}
	if m.Tool != "" && !validToolName(m.Tool) {
		m.Tool = ReportOther
	}
	return m
}
