package proxy

import (
	"encoding/json"
	"sort"
	"strings"
)

// Model discovery. A client that only ever sees the upstream's own catalogue
// cannot discover the names this gateway accepts: with a model map configured,
// the alias is a first-class name for the client, and it is invisible upstream.
// /v1/models therefore merges the tenant slot's aliases into whatever the
// upstream returned, rendered in the shape the slot's wire implies.

type catalogModel struct {
	ID       string
	OwnedBy  string
	Upstream string
}

// slotCatalog returns the tenant slot's model map, default model and wire.
func (h *Handler) slotCatalog(orgID, slot string) (aliases map[string]string, def, wire string, ok bool) {
	if h.OrgSlotConfig == nil || orgID == "" || slot == "" {
		return nil, "", "", false
	}
	wire, models, def, ok := h.OrgSlotConfig(orgID, slot)
	return models, def, wire, ok
}

// mergeModelCatalog appends the gateway's aliases to an upstream catalogue.
// Returns the original bytes when there is nothing to add or the body is not a
// recognisable catalogue — a broken upstream response must not be replaced by a
// reassuring empty list.
func mergeModelCatalog(upstreamBody []byte, wire string, aliases map[string]string, def, providerName string) []byte {
	if len(aliases) == 0 && def == "" {
		return upstreamBody
	}
	upstreamModels := parseCatalog(upstreamBody)
	seen := map[string]bool{}
	merged := make([]catalogModel, 0, len(upstreamModels)+len(aliases)+1)
	for _, m := range upstreamModels {
		if m.ID == "" || seen[m.ID] {
			continue
		}
		seen[m.ID] = true
		if m.OwnedBy == "" {
			m.OwnedBy = providerName
		}
		merged = append(merged, m)
	}
	if def != "" && !seen[def] {
		seen[def] = true
		merged = append(merged, catalogModel{ID: def, OwnedBy: providerName, Upstream: def})
	}
	names := make([]string, 0, len(aliases))
	for name := range aliases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		merged = append(merged, catalogModel{ID: name, OwnedBy: providerName, Upstream: aliases[name]})
	}
	if len(merged) == 0 {
		return upstreamBody
	}
	if wire == wireAnthropic {
		return renderAnthropicCatalog(merged)
	}
	return renderOpenAICatalog(merged)
}

// parseCatalog accepts the OpenAI shape ({"data":[{"id":…}]}), the Anthropic
// shape (same envelope, different fields) and a bare array.
func parseCatalog(body []byte) []catalogModel {
	var envelope struct {
		Data []struct {
			ID          string `json:"id"`
			OwnedBy     string `json:"owned_by"`
			DisplayName string `json:"display_name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && len(envelope.Data) > 0 {
		out := make([]catalogModel, 0, len(envelope.Data))
		for _, m := range envelope.Data {
			owned := m.OwnedBy
			if owned == "" {
				owned = m.DisplayName
			}
			out = append(out, catalogModel{ID: strings.TrimSpace(m.ID), OwnedBy: owned})
		}
		return out
	}
	var arr []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &arr); err == nil && len(arr) > 0 {
		out := make([]catalogModel, 0, len(arr))
		for _, m := range arr {
			out = append(out, catalogModel{ID: strings.TrimSpace(m.ID)})
		}
		return out
	}
	return nil
}

func renderOpenAICatalog(models []catalogModel) []byte {
	data := make([]map[string]any, 0, len(models))
	for _, m := range models {
		entry := map[string]any{"id": m.ID, "object": "model", "owned_by": m.OwnedBy}
		if m.Upstream != "" {
			// Additive: OpenAI clients ignore it, our console shows it, and it
			// answers the only question an alias raises - what does it hit?
			entry["descles_upstream_model"] = m.Upstream
		}
		data = append(data, entry)
	}
	out, err := json.Marshal(map[string]any{"object": "list", "data": data})
	if err != nil {
		return nil
	}
	return out
}

func renderAnthropicCatalog(models []catalogModel) []byte {
	data := make([]map[string]any, 0, len(models))
	ids := make([]string, 0, len(models))
	for _, m := range models {
		display := m.ID
		if m.Upstream != "" && m.Upstream != m.ID {
			display = m.ID + " (→ " + m.Upstream + ")"
		}
		entry := map[string]any{"type": "model", "id": m.ID, "display_name": display, "created_at": "2026-01-01T00:00:00Z"}
		if m.Upstream != "" {
			entry["descles_upstream_model"] = m.Upstream
		}
		data = append(data, entry)
		ids = append(ids, m.ID)
	}
	first, last := "", ""
	if len(ids) > 0 {
		first, last = ids[0], ids[len(ids)-1]
	}
	out, err := json.Marshal(map[string]any{
		"data": data, "has_more": false, "first_id": first, "last_id": last,
	})
	if err != nil {
		return nil
	}
	return out
}
