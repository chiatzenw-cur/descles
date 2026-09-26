package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// handleAnthropicMessages is the Anthropic Messages drop-in: an agent points
// ANTHROPIC_BASE_URL at Descles and keeps the Anthropic SDK untouched. Descles
// authenticates the client's x-api-key (an descles project key) and forwards the
// Messages request upstream with the real provider credential — the client key
// is never forwarded. Non-stream responses are recorded as an llm.call span.
func (h *Handler) handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAnthropicError(w, http.StatusMethodNotAllowed, "invalid_request_error", "method not allowed")
		return
	}
	// The client credential arrives as x-api-key from a native Anthropic SDK, or
	// as Authorization: Bearer from a Descles token (Claude Code's documented
	// gateway setup uses ANTHROPIC_AUTH_TOKEN). Requiring x-api-key rejected
	// every Bearer-only client with 401 before the upstream was ever considered.
	if desclesClientKey(r) == "" {
		writeAnthropicError(w, http.StatusUnauthorized, "authentication_error", "missing x-api-key or Authorization bearer token")
		return
	}
	base := h.Cfg.AnthropicBaseURL
	if base == "" {
		base = "https://api.anthropic.com"
	}
	providerKey := h.Cfg.AnthropicAPIKey

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "could not read request body")
		return
	}
	var dto struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(body, &dto); err != nil || strings.TrimSpace(dto.Model) == "" {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "request body must be valid JSON with a model")
		return
	}

	meta := h.beginMeta(r)
	personalCredential := strings.TrimSpace(r.Header.Get("X-Descles-Provider-Key")) != ""
	// Upstream routing mirrors the OpenAI-compatible plane: a provider
	// subdomain (anthropic.gw.descles.com), per-request X-Descles-Provider-Base-URL,
	// or the org's configured BYOK endpoint win over the static
	// DESCLES_ANTHROPIC_* config. Registry model routing never applies here.
	slotName := ""
	if up, slot, routed := h.resolveUpstream(r, dto.Model, meta.identity.OrganizationID); routed && up != nil {
		slotName = slot
		if h.EgressCheck != nil {
			if err := h.EgressCheck(meta.identity.OrganizationID, up.BaseURL); err != nil {
				writeAnthropicError(w, http.StatusForbidden, "permission_error", "egress blocked by org firewall: "+err.Error())
				return
			}
		}
		if up.BaseURL != "" {
			base = up.BaseURL
		}
		if up.APIKey != "" {
			providerKey = up.APIKey
		}
	}
	if meta.identity.AgentID != "" && !personalCredential && h.HostedProviderAllowed != nil {
		if slotName == "" {
			slotName = "anthropic"
		}
		if !h.HostedProviderAllowed(meta.identity.AgentID, slotName) {
			writeAnthropicError(w, http.StatusForbidden, "permission_error", "agent has no grant for company provider "+slotName)
			return
		}
	}
	// A bare X-Descles-Provider-Key (no base-url / org endpoint) still supplies
	// the upstream credential against the configured/default Anthropic base.
	if pk := strings.TrimSpace(r.Header.Get("X-Descles-Provider-Key")); pk != "" {
		providerKey = pk
	}
	r.Header.Del("X-Descles-Provider-Key")
	if providerKey == "" {
		writeAnthropicError(w, http.StatusBadGateway, "api_error", "no upstream Anthropic credential configured (set an org provider, X-Descles-Provider-Key, or DESCLES_ANTHROPIC_API_KEY)")
		return
	}
	// A slot declared (or inferred) as OpenAI-wire is translated; everything else
	// keeps the byte-for-byte passthrough this endpoint started as, so an
	// existing api.anthropic.com or /anthropic endpoint is untouched.
	if h.slotWire(meta.identity.OrganizationID, slotName, base) == wireOpenAI {
		h.handleAnthropicTranslated(w, r, meta, slotName, base, providerKey, body, dto.Model, dto.Stream)
		return
	}
	ver := r.Header.Get("anthropic-version")
	if ver == "" {
		ver = "2023-06-01"
	}

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, strings.TrimRight(base, "/")+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		writeAnthropicError(w, http.StatusBadGateway, "api_error", "build upstream: "+err.Error())
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("anthropic-version", ver)
	copyHeader(upReq.Header, r.Header, "anthropic-beta")
	upReq.Header.Set("x-api-key", providerKey) // real provider key, never the Descles client key

	span := &tracing.Span{
		SpanID:         meta.spanID,
		TraceID:        meta.traceID,
		SpanType:       tracing.SpanTypeLLM,
		StartedAt:      time.Now().UTC(),
		ActorType:      actorType(meta.identity),
		ActorID:        actorID(meta.identity),
		UserID:         meta.identity.UserID,
		AgentID:        meta.identity.AgentID,
		SessionID:      meta.sessionID,
		OrganizationID: meta.identity.OrganizationID,
		ProjectID:      meta.identity.ProjectID,
		ResourceType:   "llm",
		ResourceID:     base,
		Attributes:     map[string]any{tracing.AttrProvider: "anthropic", tracing.AttrModel: dto.Model, tracing.AttrPlaybook: meta.identity.PlaybookVersion},
	}
	if ev := h.evidence(extractToolEvidenceAnthropic(body)); len(ev) > 0 {
		span.Attributes["tool_evidence"] = ev
	}
	if h.Observe != nil && meta.identity.OrganizationID != "" {
		for _, name := range declaredToolNames(body) {
			h.Observe(meta.identity.OrganizationID, name)
		}
	}

	upResp, err := provider.NoRedirectClient(h.Cfg.UpstreamTimeout).Do(upReq)
	if err != nil {
		h.fail(span, "upstream_unreachable", err)
		writeAnthropicError(w, http.StatusBadGateway, "api_error", "upstream unreachable: "+err.Error())
		return
	}
	defer upResp.Body.Close()
	setIDHeaders(w, meta)

	if dto.Stream && upResp.StatusCode < http.StatusBadRequest {
		orgPol := h.policyFor(meta.identity.OrganizationID)
		if h.Cfg.DenyEnforce && orgPol.HasToolRules() {
			h.relayAnthropicStreamWithPolicy(r.Context(), w, span, upResp, meta.identity.OrganizationID, meta.identity.AgentID, orgPol)
			return
		}
		h.relayStream(w, r, span, upResp)
		return
	}

	buf, err := io.ReadAll(upResp.Body)
	if err != nil {
		h.fail(span, "read_upstream_body", err)
		writeAnthropicError(w, http.StatusBadGateway, "api_error", "read upstream body: "+err.Error())
		return
	}

	var ar struct {
		Model string `json:"model"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(buf, &ar)
	cost := h.estimate(span, meta.identity.OrganizationID, ar.Model, ar.Usage.InputTokens, ar.Usage.OutputTokens, 0)
	finalizeSpan(span, ar.Model, provider.Usage{InputTokens: ar.Usage.InputTokens, OutputTokens: ar.Usage.OutputTokens}, 0, cost, upResp.StatusCode)
	span.Attributes[tracing.AttrPolicy] = "allow"
	// Durable tool trace for Anthropic tool_use blocks too.
	if h.ToolCall != nil {
		for _, note := range proposedAnthropicToolCalls(buf, meta.identity.AgentID, h.groupOf(meta.identity.AgentID), h.policyFor(meta.identity.OrganizationID), h.DelegatedToolAllowed) {
			h.ToolCall(meta.identity.OrganizationID, meta.identity.AgentID, note.name, string(note.decision), note.args)
		}
	}
	// G1 rewrite (Anthropic tool_use blocks): strip denied, park approvals.
	if h.Cfg.DenyEnforce {
		if rewritten, st := rewriteDeniedToolCallsAnthropic(buf, meta.identity.AgentID, h.groupOf(meta.identity.AgentID), h.policyFor(meta.identity.OrganizationID), h.ApprovalSuspender, h.ApprovalResumer, h.ApprovalBlocker, h.DelegatedToolAllowed); st.denied > 0 || st.suspended > 0 {
			buf = rewritten
			span.Attributes[tracing.AttrPolicy] = "deny"
			if st.denied > 0 {
				span.Attributes["policy_denied_tools"] = st.denied
			}
			if st.suspended > 0 {
				span.Attributes[tracing.AttrPolicy] = "require_approval"
				span.Attributes["policy_suspended_tools"] = st.suspended
			}
		}
	}
	if err := h.Store.PutSpan(r.Context(), span); err != nil {
		h.Logger.Error("store span", "err", err)
	}

	w.Header().Set("Content-Type", contentType(upResp))
	copyUpstreamResponseHeaders(w.Header(), upResp.Header)
	w.WriteHeader(upResp.StatusCode)
	_, _ = w.Write(buf)
}

// proposedAnthropicToolCalls extracts tool_use blocks from a non-streaming
// Anthropic Messages response with the decision their input would earn.
func proposedAnthropicToolCalls(buf []byte, agent, group string, pol *policy.Policy, guard ...func(string, string, map[string]any) bool) []toolDecisionNote {
	var resp struct {
		Content []struct {
			Type  string         `json:"type"`
			Name  string         `json:"name"`
			Input map[string]any `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil
	}
	var out []toolDecisionNote
	for _, block := range resp.Content {
		if block.Type != "tool_use" || block.Name == "" {
			continue
		}
		out = append(out, toolDecisionNote{name: block.Name, decision: delegatedToolDecision(pol, agent, group, block.Name, block.Input, guard), args: compactJSON(block.Input)})
	}
	return out
}

// rewriteDeniedToolCallsAnthropic strips denied tool_use blocks from an
// Anthropic Messages non-streaming response, replacing each with a text note.
func rewriteDeniedToolCallsAnthropic(buf []byte, agent, group string, pol *policy.Policy, suspend approvalSuspender, resume approvalResumer, blocker approvalBlocker, guard ...func(string, string, map[string]any) bool) ([]byte, rewriteStats) {
	var resp map[string]any
	if err := json.Unmarshal(buf, &resp); err != nil {
		return buf, rewriteStats{}
	}
	content, ok := resp["content"].([]any)
	if !ok {
		return buf, rewriteStats{}
	}
	var st rewriteStats
	kept := make([]any, 0, len(content))
	for _, ci := range content {
		block, ok := ci.(map[string]any)
		if !ok {
			kept = append(kept, ci)
			continue
		}
		if block["type"] == "tool_use" {
			name, _ := block["name"].(string)
			args, _ := block["input"].(map[string]any)
			switch delegatedToolDecision(pol, agent, group, name, args, guard) {
			case policy.Deny:
				st.denied++
				kept = append(kept, map[string]any{"type": "text", "text": "[blocked by Descles policy: " + name + "]"})
				continue
			case policy.RequireApproval:
				switch dec, id := decideSuspendedCall(suspend, resume, blocker, agent, name, args); dec {
				case policy.Allow:
					kept = append(kept, ci)
					continue
				case policy.Deny:
					st.denied++
					kept = append(kept, map[string]any{"type": "text", "text": "[denied by human approval: " + name + "]"})
					continue
				default:
					st.suspended++
					note := "[requires human approval before execution: " + name + "]"
					if id != "" {
						note = "[pending human approval: " + name + " (approval " + id + ")]"
					}
					kept = append(kept, map[string]any{"type": "text", "text": note})
					continue
				}
			}
		}
		kept = append(kept, ci)
	}
	if st.denied == 0 && st.suspended == 0 {
		return buf, st
	}
	resp["content"] = kept
	out, err := json.Marshal(resp)
	if err != nil {
		return buf, st
	}
	return out, st
}

// writeAnthropicError writes an Anthropic Messages error envelope.
func writeAnthropicError(w http.ResponseWriter, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":  "error",
		"error": map[string]any{"type": typ, "message": msg},
	})
}
