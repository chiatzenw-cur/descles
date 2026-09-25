package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
	"github.com/chiatzenw-cur/descles/pkg/translate"
)

// This file implements the Anthropic plane against an upstream that speaks the
// OpenAI wire. The translation happens FIRST, then the existing Anthropic
// policy/tracing code runs unchanged on the translated bytes — so deny,
// require_approval, tool evidence and spans behave identically to a native
// Anthropic upstream instead of silently degrading on the translated path.

// Wire names for a routed upstream slot.
const (
	wireAnthropic = "anthropic"
	wireOpenAI    = "openai"
)

// slotWire decides which wire a routed upstream speaks. Explicit tenant config
// wins; otherwise the URL is inspected, and the gateway's own configured
// Anthropic upstream (DESCLES_ANTHROPIC_BASE_URL, default api.anthropic.com) is
// never translated — existing passthrough setups must keep working untouched.
func (h *Handler) slotWire(orgID, slot string, base string) string {
	// Single-tenant / dev mode (no resolved org) keeps the historical
	// passthrough semantics: there is no tenant slot to declare a wire on, and
	// silently translating here would change behaviour for pooled setups.
	if orgID == "" {
		return wireAnthropic
	}
	if h.OrgSlotConfig != nil && slot != "" {
		if wire, _, _, ok := h.OrgSlotConfig(orgID, slot); ok && wire != "" {
			if strings.EqualFold(wire, wireAnthropic) {
				return wireAnthropic
			}
			return wireOpenAI
		}
	}
	lower := strings.ToLower(base)
	if strings.Contains(lower, "api.anthropic.com") || strings.Contains(lower, "/anthropic") {
		return wireAnthropic
	}
	if base == "" || base == h.Cfg.AnthropicBaseURL {
		return wireAnthropic
	}
	// Tenant BYOK slots are OpenAI-compatible by default: that is what the
	// console's provider form stores (base_url + key, no wire question).
	return wireOpenAI
}

// resolveSlotModel maps the name the client asked for onto the name the upstream
// knows. Precedence: exact alias → wildcard alias → slot default → the client's
// name verbatim (an upstream that accepts claude-* names keeps working with no
// configuration at all).
func (h *Handler) resolveSlotModel(orgID, slot, requested string) string {
	if h.OrgSlotConfig == nil || orgID == "" || slot == "" || requested == "" {
		return requested
	}
	_, models, def, ok := h.OrgSlotConfig(orgID, slot)
	if !ok {
		return requested
	}
	if mapped, found := models[requested]; found && mapped != "" {
		return mapped
	}
	for pattern, mapped := range models {
		if mapped == "" || !strings.Contains(pattern, "*") {
			continue
		}
		if wildcardMatch(pattern, requested) {
			return mapped
		}
	}
	if def != "" {
		return def
	}
	return requested
}

// wildcardMatch matches a single pattern with at most a leading and trailing '*'.
func wildcardMatch(pattern, s string) bool {
	pattern = strings.ToLower(pattern)
	s = strings.ToLower(s)
	if pattern == "*" {
		return true
	}
	prefix, suffix := "", ""
	if i := strings.Index(pattern, "*"); i >= 0 {
		prefix = pattern[:i]
		suffix = pattern[i+1:]
		if strings.Contains(suffix, "*") {
			suffix = suffix[:strings.Index(suffix, "*")]
		}
	} else {
		return pattern == s
	}
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	return len(s)-len(prefix) >= len(suffix) && strings.HasSuffix(s, suffix)
}

// openAIChatURL builds the chat/completions URL for a stored base. The console
// stores an origin only (no path), and an origin needs the /v1 segment that
// OpenAI-shaped providers expect; a base that already carries a path is used as
// given. DeepSeek happens to accept both forms, api.openai.com does not.
func openAIChatURL(base string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(base), "/")
	if i := strings.Index(trimmed, "://"); i >= 0 {
		rest := trimmed[i+3:]
		if !strings.Contains(rest, "/") {
			return trimmed + "/v1/chat/completions"
		}
		return trimmed + "/chat/completions"
	}
	return trimmed + "/v1/chat/completions"
}

// translatedStreamReader turns an OpenAI SSE body into Anthropic SSE frames as it
// is read, so the existing Anthropic stream relay — which parses Anthropic
// events — can consume a translated upstream without knowing about the
// translation at all.
type translatedStreamReader struct {
	src    *bufio.Reader
	tr     *translate.StreamTranslator
	out    bytes.Buffer
	closed bool
}

func newTranslatedStreamReader(src io.Reader, requestedModel string) *translatedStreamReader {
	return &translatedStreamReader{
		src: bufio.NewReaderSize(src, 1<<16),
		tr:  translate.NewStreamTranslator(requestedModel),
	}
}

func (r *translatedStreamReader) Read(p []byte) (int, error) {
	for r.out.Len() == 0 {
		if r.closed {
			return 0, io.EOF
		}
		line, err := r.src.ReadBytes('\n')
		trimmed := strings.TrimSpace(string(line))
		if strings.HasPrefix(trimmed, "data:") {
			payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
			for _, frame := range r.tr.Feed([]byte(payload)) {
				r.out.Write(frame)
			}
		}
		if err != nil {
			for _, frame := range r.tr.Finish() {
				r.out.Write(frame)
			}
			r.closed = true
			if r.out.Len() == 0 {
				return 0, io.EOF
			}
		}
	}
	return r.out.Read(p)
}

// Usage reports what the translated stream accounted for. Call it after the
// relay drained the reader.
func (r *translatedStreamReader) Usage() (input, output, cached int) { return r.tr.Usage() }

// ToolNames lists the tools the upstream model asked to call.
func (r *translatedStreamReader) ToolNames() []string { return r.tr.ToolNames() }

// translateAnthropicRequestBody builds the upstream OpenAI body from an inbound
// Anthropic body, applying the slot's model mapping.
func (h *Handler) translateAnthropicRequestBody(orgID, slot string, body []byte, stream bool) ([]byte, string, error) {
	var probe struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &probe)
	mapped := h.resolveSlotModel(orgID, slot, probe.Model)
	tr, err := translate.AnthropicToOpenAI(body, mapped)
	if err != nil {
		return nil, "", err
	}
	if !stream {
		// The client asked for a stream but the relay path is non-streaming (or
		// vice versa): the translated body must carry the flag the caller uses.
		var obj map[string]any
		if err := json.Unmarshal(tr.Body, &obj); err == nil {
			obj["stream"] = stream
			if !stream {
				delete(obj, "stream_options")
			}
			if encoded, err := json.Marshal(obj); err == nil {
				return encoded, mapped, nil
			}
		}
	}
	return tr.Body, mapped, nil
}

// callOpenAIUpstream posts the translated body and returns the raw response.
func (h *Handler) callOpenAIUpstream(ctx context.Context, r *http.Request, base, providerKey string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openAIChatURL(base), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if providerKey != "" {
		req.Header.Set("Authorization", "Bearer "+providerKey)
	}
	return provider.NoRedirectClient(h.Cfg.UpstreamTimeout).Do(req)
}

// finalizeTranslatedAnthropicBody runs the same tool-evidence and policy rewrite
// the native Anthropic path runs, on an already-translated response.
func (h *Handler) finalizeTranslatedAnthropicBody(ctx context.Context, span *tracing.Span, meta requestMeta, buf []byte) []byte {
	if h.ToolCall != nil {
		for _, note := range proposedAnthropicToolCalls(buf, meta.identity.AgentID, h.groupOf(meta.identity.AgentID), h.policyFor(meta.identity.OrganizationID)) {
			h.ToolCall(meta.identity.OrganizationID, meta.identity.AgentID, note.name, string(note.decision), note.args)
		}
	}
	if !h.Cfg.DenyEnforce {
		return buf
	}
	rewritten, st := rewriteDeniedToolCallsAnthropic(buf, meta.identity.AgentID, h.groupOf(meta.identity.AgentID), h.policyFor(meta.identity.OrganizationID), h.ApprovalSuspender, h.ApprovalResumer, h.ApprovalBlocker, h.DelegatedToolAllowed)
	if st.denied > 0 || st.suspended > 0 {
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
	return buf
}

// writeAnthropicUpstreamError renders an upstream failure in the caller's wire
// format, preserving the status code.
func writeAnthropicUpstreamError(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(translate.AnthropicErrorFromUpstream(status, body))
}

// newAnthropicSpan builds the span both planes record for an Anthropic call.
func (h *Handler) newAnthropicSpan(meta requestMeta, base, model string) *tracing.Span {
	return &tracing.Span{
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
		Attributes:     map[string]any{tracing.AttrProvider: "anthropic", tracing.AttrModel: model},
	}
}

// streamTranslated relays a translated stream through the Anthropic policy relay,
// so governance on the translated path is the same code as on the native path.
func (h *Handler) streamTranslated(ctx context.Context, w http.ResponseWriter, r *http.Request, span *tracing.Span, upResp *http.Response, requestedModel, base string) {
	reader := newTranslatedStreamReader(upResp.Body, requestedModel)
	synthetic := &http.Response{
		StatusCode: upResp.StatusCode,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}, "Cache-Control": []string{"no-cache"}},
		Body:       io.NopCloser(reader),
	}
	orgPol := h.policyFor(span.OrganizationID)
	if h.Cfg.DenyEnforce && orgPol.HasToolRules() {
		if err := h.relayAnthropicStreamWithPolicy(ctx, w, span, synthetic, span.OrganizationID, span.AgentID, orgPol); err != nil {
			h.Logger.Warn("translated stream relay", "err", err)
		}
	} else {
		h.relayStream(w, r, span, synthetic)
	}
	// Deliberately nothing after this point: the relay has already finalised and
	// stored the span, and the in-memory store keeps the span pointer, so
	// mutating it here would look correct in tests and be silently dropped by
	// SQLite. Usage, cost and policy attributes must be settled before storage.
}

// ExportOpenAIChatURL exposes the URL builder to the external test package.
func ExportOpenAIChatURL(base string) string { return openAIChatURL(base) }

// handleAnthropicTranslated serves an Anthropic Messages call by translating it
// to the OpenAI wire, calling the upstream, and translating the answer back.
// body is the request body handleAnthropicMessages already read.
func (h *Handler) handleAnthropicTranslated(
	w http.ResponseWriter,
	r *http.Request,
	meta requestMeta,
	slot, base, providerKey string,
	body []byte,
	requestedModel string,
	stream bool,
) {
	translated, mapped, err := h.translateAnthropicRequestBody(meta.identity.OrganizationID, slot, body, stream)
	if err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "translate request: "+err.Error())
		return
	}
	span := h.newAnthropicSpan(meta, base, requestedModel)
	span.Attributes["translated_wire"] = "openai"
	span.Attributes["upstream_model"] = mapped
	// Set before the relay stores the span: the in-memory store keeps the span
	// pointer while SQLite serialises at PutSpan, so anything written afterwards
	// survives in tests and vanishes in production.
	if declared := declaredToolNames(body); len(declared) > 0 {
		span.Attributes["tools_declared"] = declared
	}

	upResp, err := h.callOpenAIUpstream(r.Context(), r, base, providerKey, translated)
	if err != nil {
		h.fail(span, "upstream_unreachable", err)
		writeAnthropicError(w, http.StatusBadGateway, "api_error", "upstream unreachable: "+err.Error())
		return
	}
	defer upResp.Body.Close()
	setIDHeaders(w, meta)

	if upResp.StatusCode >= http.StatusBadRequest {
		buf, _ := io.ReadAll(io.LimitReader(upResp.Body, 1<<20))
		h.fail(span, "upstream_error", fmt.Errorf("upstream status %d", upResp.StatusCode))
		_ = h.Store.PutSpan(r.Context(), span)
		writeAnthropicUpstreamError(w, upResp.StatusCode, buf)
		return
	}

	if stream {
		h.streamTranslated(r.Context(), w, r, span, upResp, requestedModel, base)
		return
	}

	buf, err := io.ReadAll(upResp.Body)
	if err != nil {
		h.fail(span, "read_upstream_body", err)
		writeAnthropicError(w, http.StatusBadGateway, "api_error", "read upstream body: "+err.Error())
		return
	}
	out, err := translate.OpenAIToAnthropic(buf, requestedModel)
	if err != nil {
		h.fail(span, "translate_response", err)
		writeAnthropicError(w, http.StatusBadGateway, "api_error", "translate response: "+err.Error())
		return
	}
	// Policy and tool evidence run on the translated bytes through the same
	// helpers the native Anthropic path uses — no second implementation.
	out = h.finalizeTranslatedAnthropicBody(r.Context(), span, meta, out)

	var ar struct {
		Model string `json:"model"`
		Usage struct {
			InputTokens     int `json:"input_tokens"`
			OutputTokens    int `json:"output_tokens"`
			CacheReadTokens int `json:"cache_read_input_tokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(out, &ar)
	// Price by the model that actually served the call: the response echoes the
	// client's alias, which would price a deepseek-v4-pro answer at Claude rates.
	costModel := mapped
	if costModel == "" {
		costModel = ar.Model
	}
	// Cache reads are a separate (much cheaper) line: dropping them billed the
	// cached prefix at the full input rate, and left cached_tokens at 0 in the
	// ledger while the client was told otherwise.
	usage := provider.Usage{
		InputTokens:  ar.Usage.InputTokens,
		OutputTokens: ar.Usage.OutputTokens,
		CachedTokens: ar.Usage.CacheReadTokens,
	}
	cost := h.estimate(span, meta.identity.OrganizationID, costModel, usage.InputTokens, usage.OutputTokens, usage.CachedTokens)
	finalizeSpan(span, ar.Model, usage, 0, cost, http.StatusOK)
	if _, present := span.Attributes[tracing.AttrPolicy]; !present {
		span.Attributes[tracing.AttrPolicy] = "allow"
	}
	if err := h.Store.PutSpan(r.Context(), span); err != nil {
		h.Logger.Error("store span", "err", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}
