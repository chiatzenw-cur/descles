// Package proxy implements the OpenAI-compatible endpoints that sit between
// an agent and an LLM provider. Each request is forwarded upstream, the usage
// and attribution are recorded as an llm.call span, and the provider response
// (including streaming) is passed through verbatim.
//
// The critical modelling rule from project.md is honoured here: a model may
// *request* a tool call, but Descles never records that as an executed action.
// Tool execution observability arrives with the MCP gateway milestone.
package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/config"
	"github.com/chiatzenw-cur/descles/pkg/identity"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/pricing"
	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/storage"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
	"github.com/chiatzenw-cur/descles/web"
)

// Handler serves the proxy endpoints.
type Handler struct {
	Cfg      config.Config
	Registry *provider.Registry
	Policy   *policy.Holder
	Store    storage.Storage
	Logger   *slog.Logger

	// KeyResolver maps a data-plane key (plaintext) to its tenant identity.
	// When nil, org/user attribution falls back to the X-Descles-* headers
	// (metadata-only / single-tenant mode).
	KeyResolver func(plaintext string) (orgID, employeeID, agentID string, ok bool)
	// GroupOfAgent resolves an agent's group (workspace) NAME for policy group
	// rules; "" when unset (no group layer in the decision chain).
	GroupOfAgent func(agentID string) string
	// DelegatedToolAllowed is an additional, fail-closed ceiling for sub-agent
	// tool calls. It never turns an org policy denial into an allow.
	DelegatedToolAllowed func(agentID, tool string, args map[string]any) bool
	DelegatedDailyBudget func(agentID string) (usd float64, ok bool)
	// OrgPolicy returns the org-scoped policy holder when the org has its own
	// policy; nil means the org inherits the global Policy holder.
	OrgPolicy func(orgID string) *policy.Holder
	// Observe, when set, receives every tool name an agent proposes (allowed,
	// denied or suspended alike). The console derives its tool inventory from
	// this instead of span attribute round-trips.
	Observe func(orgID, tool string)
	// ToolCall, when set, durably records every tool decision the gateway made
	// (allow / deny / require_approval) so the console can render a full tool
	// trace — not just the approval-shaped subset. args is the compact JSON of
	// the proposed arguments ("" when unavailable).
	ToolCall func(orgID, agentID, tool, decision, args string)
	// EgressCheck, when set, is the org's upstream egress firewall: it returns
	// a non-nil error when the org may not forward to the resolved upstream
	// base URL. Checked after resolveUpstream on every proxied call.
	EgressCheck func(orgID, baseURL string) error
	// ApprovalBlocker, when set, turns require_approval into a BLOCKING gate:
	// the gateway holds the response briefly (default ~2 min) for a human
	// decision, so an approved call is delivered to the agent in the SAME turn.
	// On timeout it degrades to the durable pending-note + resume path.
	ApprovalBlocker approvalBlocker
	// QuotaGate reserves one request for limited launch keys. It is called only
	// after KeyResolver authenticates the key. Unlimited keys return ok=true.
	QuotaGate func(plaintext string) (remaining int64, limited, ok bool)
	// KeyPolicy returns the BYOK and request-size envelope carried by a limited
	// key. Unlimited keys return limited=false and keep normal proxy behaviour.
	KeyPolicy func(plaintext string) (maxRequestBytes int64, requireBYOK, limited bool)

	// ApprovalSuspender opens a pending human approval for an LLM-generated
	// tool call that policy marks require_approval during response rewriting.
	// When nil (or the approval fails), the call is still stripped — the
	// runtime is told it needs approval, so it never executes unapproved.
	ApprovalSuspender approvalSuspender
	// ApprovalResumer, when set, is consulted before parking a
	// require_approval tool call: if an approved approval already authorizes
	// this exact (agent, tool, args) re-issue, the call is allowed through
	// (single-use) instead of being suspended again. This closes the resume
	// loop after a human approves a previously suspended call.
	ApprovalResumer approvalResumer

	// OrgUpstream transparently replaces the routed upstream with a tenant's
	// own BYOK endpoint: called with (orgID, providerName) after model routing.
	// A non-empty baseURL swaps host + credential to the tenant's provider;
	// ok=false keeps the gateway's pooled upstream. Nil in single-tenant mode.
	OrgUpstream func(orgID, providerName string) (baseURL, apiKey string, ok bool)
	// HostedProviderAllowed controls whether this agent may use a company-held
	// credential. Personal per-request provider credentials remain separate.
	HostedProviderAllowed func(agentID, providerName string) bool

	// OrgPrices supplies a tenant's own price table (model → USD per 1M tokens),
	// layered over the built-in list prices. Nil or ok=false uses the built-in
	// table only. This is how a tenant prices a model the curated table does not
	// know, or corrects it for a negotiated rate.
	OrgPrices func(orgID string) (map[string]pricing.Price, bool)

	// OrgSlotConfig describes a tenant provider slot: its wire format and its
	// model mapping. Wire selects translation ("openai") or byte-for-byte
	// passthrough ("anthropic"); models maps a client-facing alias onto the
	// upstream's model name, def is the fallback for unmapped names. Nil or
	// ok=false falls back to URL inspection.
	OrgSlotConfig func(orgID, slot string) (wire string, models map[string]string, def string, ok bool)

	// OrgFallback resolves the org's single saved provider credential by name,
	// used when a hostname-routed request names a slot the tenant never saved
	// ("anthropic.gw…" reached by a tenant whose only credential is "deepseek").
	// ok=false when the org has zero or several providers — several candidates
	// are ambiguous, so the request must fail rather than guess. Nil disables
	// the fallback entirely.
	OrgFallback func(orgID string) (providerName, baseURL, apiKey string, ok bool)
}

// New wires a Handler.
func New(cfg config.Config, reg *provider.Registry, pol *policy.Holder, store storage.Storage, log *slog.Logger) *Handler {
	if pol == nil {
		pol = policy.NewHolder(policy.AllowAll())
	}
	return &Handler{Cfg: cfg, Registry: reg, Policy: pol, Store: store, Logger: log}
}

// Routes returns the fully-wired HTTP handler.
func (h *Handler) Routes() http.Handler {
	// LLM endpoints are behind data-plane auth.
	llm := http.NewServeMux()
	llm.HandleFunc("/v1/chat/completions", h.handleChatCompletions)
	llm.HandleFunc("/v1/responses", h.handleResponses)
	llm.HandleFunc("/v1/models", h.handleModels)
	// Native Anthropic clients append /v1/messages to ANTHROPIC_BASE_URL.
	// Keep the namespaced route for backwards compatibility and expose this
	// canonical alias so anthropic.gw.descles.com needs no path rewrite.
	llm.HandleFunc("/v1/messages", h.handleAnthropicMessages)
	llm.HandleFunc("/anthropic/v1/messages", h.handleAnthropicMessages)

	mux := http.NewServeMux()
	mux.Handle("/v1/", h.requireDataToken(llm))
	mux.Handle("/anthropic/v1/", h.requireDataToken(llm))
	mux.HandleFunc("/healthz", h.handleHealth)
	mux.HandleFunc("/api/spans", h.handleListSpans)
	mux.HandleFunc("/api/traces/", h.handleGetTrace)
	mux.HandleFunc("/api/requests", h.handleRequests)
	mux.HandleFunc("/api/costs", h.handleCosts)
	mux.HandleFunc("/api/policy-events", h.handlePolicyEvents)
	mux.Handle("/", web.Handler())
	return h.withMiddleware(mux)
}

// requireDataToken guards the LLM endpoints. A request is accepted when its
// Authorization is the configured data/admin token, OR a resolvable key (an
// org/employee token via KeyResolver). When no token AND no resolver are set
// the data plane stays open (dev mode).
func (h *Handler) requireDataToken(next http.Handler) http.Handler {
	token := h.Cfg.DataToken
	if token == "" {
		token = h.Cfg.AdminToken
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		clientKey := desclesClientKey(r)
		// Configured data/admin token → pass.
		if token != "" && (subtle.ConstantTimeCompare([]byte(auth), []byte("Bearer "+token)) == 1 || subtle.ConstantTimeCompare([]byte(clientKey), []byte(token)) == 1) {
			next.ServeHTTP(w, r)
			return
		}
		// A resolvable key (org/employee token) → pass.
		if h.KeyResolver != nil {
			if key := clientKey; key != "" {
				if orgID, _, _, ok := h.KeyResolver(key); ok {
					if err := h.enforceLimitedKeyPolicy(r, key, orgID); err != nil {
						writeError(w, http.StatusBadRequest, err.Error())
						return
					}
					if h.QuotaGate != nil {
						remaining, limited, allowed := h.QuotaGate(key)
						if !allowed {
							w.Header().Set("Retry-After", "0")
							writeError(w, http.StatusTooManyRequests, "test launch request quota exhausted")
							return
						}
						if limited {
							w.Header().Set("X-Descles-Requests-Remaining", strconv.FormatInt(remaining, 10))
						}
					}
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		// Neither configured token nor resolvable key, and no resolver wired → open.
		if token == "" && h.KeyResolver == nil {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid data token")
	})
}

func (h *Handler) enforceLimitedKeyPolicy(r *http.Request, key, orgID string) error {
	if h.KeyPolicy == nil {
		return nil
	}
	maxBytes, requireBYOK, limited := h.KeyPolicy(key)
	if !limited {
		return nil
	}
	if r.Method == http.MethodGet {
		return nil
	}
	if maxBytes <= 0 {
		return errors.New("test launch request size policy is unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return errors.New("could not read request body")
	}
	if int64(len(body)) > maxBytes {
		return fmt.Errorf("test launch request body exceeds %d bytes", maxBytes)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return errors.New("request body must be valid JSON")
	}
	model, _ := payload["model"].(string)
	if strings.TrimSpace(model) == "" {
		return errors.New("test launch request requires a model")
	}
	if !strings.HasPrefix(r.URL.Path, "/anthropic/v1/") && h.providerFromHost(r) == "" {
		if h.Registry == nil {
			return errors.New("model routing is unavailable")
		}
		if _, ok := h.Registry.ResolveMatch(model); !ok {
			return fmt.Errorf("no provider is configured for model %q", model)
		}
	}
	if requireBYOK && strings.TrimSpace(r.Header.Get("X-Descles-Provider-Key")) == "" {
		providerName := h.providerFromHost(r)
		if providerName == "" && (r.URL.Path == "/v1/messages" || strings.HasPrefix(r.URL.Path, "/anthropic/v1/")) {
			providerName = "anthropic"
		}
		if providerName == "" && h.Registry != nil {
			if selected, ok := h.Registry.ResolveMatch(model); ok {
				providerName = selected.Name
			}
		}
		if h.OrgUpstream == nil || providerName == "" {
			return errors.New("test launch request requires a provider credential")
		}
		_, providerKey, ok := h.OrgUpstream(orgID, providerName)
		if !ok || strings.TrimSpace(providerKey) == "" {
			return errors.New("test launch request requires a provider credential")
		}
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	r.ContentLength = int64(len(body))
	return nil
}

// ---------- Middleware ----------

type statusWriter struct {
	http.ResponseWriter
	status int
}

// Flush preserves streaming semantics through the logging wrapper.
func (w *statusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (h *Handler) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if rec := recover(); rec != nil {
				h.Logger.Error("panic", "err", rec, "path", r.URL.Path)
				if sw.status == http.StatusOK {
					http.Error(sw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}
			h.Logger.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"trace_id", r.Header.Get("X-Descles-Trace"),
				"dur_ms", time.Since(start).Milliseconds(),
			)
		}()
		next.ServeHTTP(sw, r)
	})
}

// ---------- OpenAI-compatible endpoints ----------

// declaredToolNames extracts the tool names a client declares in a request
// body. Covers chat/tool-call style (tools[].function.name) plus Responses and
// Anthropic Messages style (tools[].name). Best-effort: parse failures return
// nothing and the request is still forwarded unchanged.
func declaredToolNames(body []byte) []string {
	var req struct {
		Tools []struct {
			Name     string `json:"name"`
			Function *struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}
	var out []string
	for _, t := range req.Tools {
		name := t.Name
		if t.Function != nil && t.Function.Name != "" {
			name = t.Function.Name
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// compactJSON renders v as compact JSON; empty maps/strings become "".
func compactJSON(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case map[string]any:
		if len(t) == 0 {
			return ""
		}
	}
	b, err := json.Marshal(v)
	if err != nil || string(b) == "{}" || string(b) == "null" {
		return ""
	}
	return string(b)
}

func (h *Handler) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	h.forwardLLMCall(w, r, "/chat/completions", provider.ParseChatCompletion)
}

type toolDecisionNote struct {
	name     string
	decision policy.Decision
	args     string
}

// proposedToolCalls extracts each tool call the model proposed in a
// non-streaming response body together with the decision its arguments earn.
// Mirror of the rewrite path, used only for durable tool-trace recording.
func proposedToolCalls(buf []byte, agent, group string, pol *policy.Policy, guard ...func(string, string, map[string]any) bool) []toolDecisionNote {
	var resp struct {
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil
	}
	var out []toolDecisionNote
	for _, c := range resp.Choices {
		for _, tc := range c.Message.ToolCalls {
			name := tc.Function.Name
			if name == "" {
				continue
			}
			args := map[string]any{}
			if tc.Function.Arguments != "" {
				_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
			}
			out = append(out, toolDecisionNote{name: name, decision: delegatedToolDecision(pol, agent, group, name, args, guard), args: compactJSON(args)})
		}
	}
	return out
}

func (h *Handler) handleResponses(w http.ResponseWriter, r *http.Request) {
	h.forwardLLMCall(w, r, "/responses", provider.ParseResponses)
}

// providerFromHost returns the tenant's provider selector encoded in the
// request Host when hostname routing is enabled. E.g. with
// DESCLES_GATEWAY_DOMAIN=gw.descles.com, "deepseek.gw.descles.com" -> "deepseek".
// The bare apex or any unrelated host returns "" (registry model routing).
func (h *Handler) providerFromHost(r *http.Request) string {
	d := h.Cfg.GatewayDomain
	if d == "" {
		return ""
	}
	host := r.Host
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.HasSuffix(host, "]") {
		host = host[:i] // strip port
	}
	host = strings.ToLower(strings.TrimSpace(host))
	suffix := "." + d
	if !strings.HasSuffix(host, suffix) {
		return ""
	}
	p := strings.TrimSuffix(host, suffix)
	if p == "" || strings.Contains(p, ".") {
		return ""
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return ""
		}
	}
	return p
}

// resolveUpstream picks the forwarding target. Hostname-routed tenants
// ("<provider>.gw.descles.com") are served purely from the tenant's own BYOK
// configuration — no model registry involved. Otherwise the registry routes
// by model and a tenant BYOK endpoint for that slot transparently replaces the
// pooled upstream. A per-request X-Descles-Provider-Key always wins for the
// credential. Returns up=nil when no target resolves; providerName names the
// desired slot (useful for the caller's error message).
func (h *Handler) resolveUpstream(r *http.Request, model, orgID string) (up *provider.Upstream, providerName string, ok bool) {
	// 0. Per-request transparent passthrough: the client names the exact
	// upstream endpoint in X-Descles-Provider-Base-URL (BYOK quick-start —
	// no org provider pre-configuration needed). The credential comes from
	// X-Descles-Provider-Key or the routed org's BYOK key below.
	if bu := strings.TrimSpace(r.Header.Get("X-Descles-Provider-Base-URL")); bu != "" {
		if !strings.HasPrefix(bu, "http://") && !strings.HasPrefix(bu, "https://") {
			return nil, bu, false
		}
		u := &provider.Upstream{BaseURL: bu}
		if pk := strings.TrimSpace(r.Header.Get("X-Descles-Provider-Key")); pk != "" {
			u.APIKey = pk
		}
		r.Header.Del("X-Descles-Provider-Base-URL")
		r.Header.Del("X-Descles-Provider-Key")
		return u, provider.ProviderName(bu), true
	}
	// 1. Hostname routing: tenant BYOK config is the single source of truth.
	if p := h.providerFromHost(r); p != "" {
		if h.OrgUpstream == nil || orgID == "" {
			return nil, p, false
		}
		bURL, k, found := h.OrgUpstream(orgID, p)
		if (!found || bURL == "") && h.OrgFallback != nil {
			// The host names a slot the tenant never saved ("anthropic.gw…" with
			// only a "deepseek" credential). A single saved provider is
			// unambiguous, so route there instead of failing the request.
			if fname, fbase, fkey, ok := h.OrgFallback(orgID); ok && fbase != "" {
				p, bURL, k, found = fname, fbase, fkey, true
			}
		}
		if !found || bURL == "" {
			return nil, p, false
		}
		u := &provider.Upstream{BaseURL: bURL, APIKey: k}
		if pk := strings.TrimSpace(r.Header.Get("X-Descles-Provider-Key")); pk != "" {
			clone := *u
			clone.APIKey = pk
			u = &clone
		}
		r.Header.Del("X-Descles-Provider-Key")
		return u, p, true
	}
	// 2. Registry model routing (pooled / demo / single-tenant).
	if h.Registry == nil {
		return nil, model, false
	}
	prov, matched := h.Registry.ResolveMatch(model)
	if !matched {
		return nil, model, false
	}
	u := prov.Upstream
	pname := prov.Name
	if pname == "" {
		pname = provider.ProviderName(u.BaseURL)
	}
	// 2b. Tenant BYOK endpoint override for the routed slot.
	if h.OrgUpstream != nil && orgID != "" {
		if bURL, k, found := h.OrgUpstream(orgID, pname); found && bURL != "" {
			clone := *u
			clone.BaseURL = bURL
			if k != "" {
				clone.APIKey = k
			}
			u = &clone
		}
	}
	if pk := strings.TrimSpace(r.Header.Get("X-Descles-Provider-Key")); pk != "" {
		clone := *u
		clone.APIKey = pk
		u = &clone
	}
	r.Header.Del("X-Descles-Provider-Key")
	return u, pname, true
}

func (h *Handler) forwardLLMCall(
	w http.ResponseWriter,
	r *http.Request,
	path string,
	parse func([]byte) (provider.ChatResult, error),
) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed: must be POST")
		return
	}

	meta := h.beginMeta(r)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}

	var reqDTO struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	_ = json.Unmarshal(body, &reqDTO) // forward regardless; parse is best-effort

	// Tool discovery happens HERE, on the client's request: every runtime
	// declares its tools in the request body (chat: tools[].function.name,
	// Responses/Anthropic: tools[].name). No need to catch proposals in the
	// rewritten response — the declaration is visible before any model call.
	if h.Observe != nil && meta.identity.OrganizationID != "" {
		for _, name := range declaredToolNames(body) {
			h.Observe(meta.identity.OrganizationID, name)
		}
	}

	// Route to the right upstream. Hostname-routed tenants (<provider>.gw.*)
	// are served purely from their own BYOK endpoint config; otherwise the
	// registry routes by model with an optional tenant endpoint override.
	if strings.TrimSpace(reqDTO.Model) == "" {
		writeError(w, http.StatusBadRequest, "request requires a model")
		return
	}
	personalCredential := strings.TrimSpace(r.Header.Get("X-Descles-Provider-Key")) != ""
	up, pname, routed := h.resolveUpstream(r, reqDTO.Model, meta.identity.OrganizationID)
	if meta.identity.AgentID != "" && !personalCredential && h.HostedProviderAllowed != nil && !h.HostedProviderAllowed(meta.identity.AgentID, pname) {
		writeError(w, http.StatusForbidden, "agent has no grant for company provider "+pname)
		return
	}
	if routed && up != nil && h.EgressCheck != nil {
		if err := h.EgressCheck(meta.identity.OrganizationID, up.BaseURL); err != nil {
			span := &tracing.Span{SpanID: meta.spanID, TraceID: meta.traceID, SpanType: tracing.SpanTypeLLM, StartedAt: time.Now().UTC(), ActorType: actorType(meta.identity), ActorID: actorID(meta.identity), UserID: meta.identity.UserID, AgentID: meta.identity.AgentID, OrganizationID: meta.identity.OrganizationID, ResourceType: "llm", ResourceID: up.BaseURL, Status: tracing.StatusError, ErrorType: "egress_blocked", Attributes: map[string]any{tracing.AttrProvider: pname, tracing.AttrModel: reqDTO.Model, "egress_error": err.Error()}, EndedAt: time.Now().UTC()}
			_ = h.Store.PutSpan(r.Context(), span)
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}
	if !routed {
		if p := h.providerFromHost(r); p != "" {
			writeError(w, http.StatusBadRequest, "no provider \""+p+"\" configured for this tenant (add an org provider or send X-Descles-Provider-Key)")
			return
		}
		if h.Registry == nil {
			writeError(w, http.StatusServiceUnavailable, "model routing is unavailable")
			return
		}
		writeError(w, http.StatusBadRequest, "no provider is configured for model "+reqDTO.Model)
		return
	}

	// M4 policy gate: deny an over-budget agent's request before it reaches the
	// provider. The request is never executed, so the span is recorded as
	// cancelled with policy_decision=deny.
	if denied, err := h.budgetGate(r.Context(), meta); err != nil {
		h.Logger.Error("budget gate", "err", err)
	} else if denied {
		span := &tracing.Span{
			SpanID:         meta.spanID,
			TraceID:        meta.traceID,
			SpanType:       tracing.SpanTypeLLM,
			StartedAt:      time.Now().UTC(),
			EndedAt:        time.Now().UTC(),
			ActorType:      actorType(meta.identity),
			ActorID:        actorID(meta.identity),
			UserID:         meta.identity.UserID,
			AgentID:        meta.identity.AgentID,
			SessionID:      meta.sessionID,
			OrganizationID: meta.identity.OrganizationID,
			ProjectID:      meta.identity.ProjectID,
			ResourceType:   "llm",
			Status:         tracing.StatusCancelled,
			Attributes: map[string]any{
				tracing.AttrProvider:   pname,
				tracing.AttrModel:      reqDTO.Model,
				tracing.AttrPolicy:     string(policy.Deny),
				"policy_reason":        "budget_daily_usd_exceeded",
				"policy_remaining_usd": 0,
			},
		}
		_ = h.Store.PutSpan(r.Context(), span)
		writeError(w, http.StatusTooManyRequests,
			"budget exceeded: agent "+meta.identity.AgentID+" has reached its daily limit")
		return
	}

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
		ResourceID:     up.BaseURL,
		Attributes: map[string]any{
			tracing.AttrProvider: pname,
			tracing.AttrModel:    reqDTO.Model,
		},
	}
	if ev := h.evidence(extractToolEvidence(body)); len(ev) > 0 {
		span.Attributes["tool_evidence"] = ev
	}

	ctx := r.Context()
	upReq, err := up.NewRequest(ctx, path, body)
	if err != nil {
		h.fail(span, "build_upstream", err)
		writeError(w, http.StatusBadGateway, "build upstream request: "+err.Error())
		return
	}
	copyHeader(upReq.Header, r.Header, "OpenAI-Organization")
	copyHeader(upReq.Header, r.Header, "OpenAI-Project")
	copyHeader(upReq.Header, r.Header, "Idempotency-Key")

	upResp, err := up.Do(upReq)
	if err != nil {
		h.fail(span, "upstream_unreachable", err)
		writeError(w, http.StatusBadGateway, "upstream unreachable: "+err.Error())
		return
	}
	defer upResp.Body.Close()

	setIDHeaders(w, meta)

	if reqDTO.Stream && upResp.StatusCode < http.StatusBadRequest {
		orgPol := h.policyFor(meta.identity.OrganizationID)
		if h.Cfg.DenyEnforce && orgPol.HasToolRules() {
			switch path {
			case "/chat/completions":
				h.relayChatStreamWithPolicy(w, r, span, upResp, meta.identity.AgentID, orgPol)
				return
			case "/responses":
				h.relayResponsesStreamWithPolicy(r.Context(), w, span, upResp, meta.identity.AgentID, orgPol)
				return
			}
		}
		h.relayStream(w, r, span, upResp)
		return
	}

	buf, err := io.ReadAll(upResp.Body)
	if err != nil {
		h.fail(span, "read_upstream_body", err)
		writeError(w, http.StatusBadGateway, "read upstream body: "+err.Error())
		return
	}
	res, parseErr := parse(buf)
	if parseErr != nil {
		h.Logger.Debug("parse upstream body", "path", path, "err", parseErr)
	}
	cost := h.estimate(span, meta.identity.OrganizationID, res.Model, res.Usage.InputTokens, res.Usage.OutputTokens, res.Usage.CachedTokens)
	finalizeSpan(span, res.Model, res.Usage, res.ToolCallCount, cost, upResp.StatusCode)
	span.Attributes[tracing.AttrPolicy] = string(policy.Allow)
	applyToolPolicy(span, meta.identity.AgentID, h.groupOf(meta.identity.AgentID), res.ToolNames, h.policyFor(meta.identity.OrganizationID))
	// Durable tool trace: record every proposed tool + its policy decision
	// (allow / deny / require_approval), not only the approval-shaped subset.
	if h.ToolCall != nil {
		for _, note := range proposedToolCalls(buf, meta.identity.AgentID, h.groupOf(meta.identity.AgentID), h.policyFor(meta.identity.OrganizationID), h.DelegatedToolAllowed) {
			h.ToolCall(meta.identity.OrganizationID, meta.identity.AgentID, note.name, string(note.decision), note.args)
		}
	}

	// G1 rewrite: strip denied tool calls and park require_approval calls
	// before returning to the runtime — neither reaches it as an executable
	// tool_call.
	if h.Cfg.DenyEnforce {
		var rewritten []byte
		var st rewriteStats
		if path == "/responses" {
			rewritten, st = rewriteDeniedToolCallsResponses(buf, meta.identity.AgentID, h.groupOf(meta.identity.AgentID), h.policyFor(meta.identity.OrganizationID), h.ApprovalSuspender, h.ApprovalResumer, h.ApprovalBlocker, h.DelegatedToolAllowed)
		} else {
			rewritten, st = rewriteDeniedToolCalls(buf, meta.identity.AgentID, h.groupOf(meta.identity.AgentID), h.policyFor(meta.identity.OrganizationID), h.ApprovalSuspender, h.ApprovalResumer, h.ApprovalBlocker, h.DelegatedToolAllowed)
		}
		if st.denied > 0 || st.suspended > 0 {
			buf = rewritten
			span.Attributes[tracing.AttrPolicy] = string(policy.Deny)
			if st.denied > 0 {
				span.Attributes["policy_denied_tools"] = st.denied
			}
			if st.suspended > 0 {
				span.Attributes[tracing.AttrPolicy] = string(policy.RequireApproval)
				span.Attributes["policy_suspended_tools"] = st.suspended
			}
		}
	}

	if err := h.Store.PutSpan(ctx, span); err != nil {
		h.Logger.Error("store span", "err", err)
	}

	w.Header().Set("Content-Type", contentType(upResp))
	copyUpstreamResponseHeaders(w.Header(), upResp.Header)
	w.WriteHeader(upResp.StatusCode)
	_, _ = w.Write(buf)
}

func (h *Handler) relayStream(w http.ResponseWriter, r *http.Request, span *tracing.Span, upResp *http.Response) {
	w.Header().Set("Content-Type", contentType(upResp))
	copyUpstreamResponseHeaders(w.Header(), upResp.Header)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(upResp.StatusCode)

	flusher, _ := w.(http.Flusher)
	res, err := provider.RelayStream(w, upResp.Body, flusher)
	if err != nil && err != io.EOF {
		h.Logger.Warn("stream relay", "err", err)
	}

	model, _ := span.Attributes[tracing.AttrModel].(string)
	cost := h.estimate(span, span.OrganizationID, priceModelFor(span, model), res.Usage.InputTokens, res.Usage.OutputTokens, res.Usage.CachedTokens)
	finalizeSpan(span, model, res.Usage, res.ToolCallCount, cost, upResp.StatusCode)
	span.Attributes[tracing.AttrPolicy] = string(policy.Allow)
	if err := h.Store.PutSpan(r.Context(), span); err != nil {
		h.Logger.Error("store span", "err", err)
	}
}

// handleModels forwards the selected provider's model list. It deliberately
// uses the same tenant hostname and per-request BYOK rules as inference calls:
// clients such as cc-switch probe /v1/models before accepting an endpoint.
func (h *Handler) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed: must be GET")
		return
	}

	orgID := h.requestOrg(r)
	var up *provider.Upstream
	providerName := ""

	// Hostname-routed hosted BYOK and explicit per-request endpoints take
	// precedence, exactly as they do for chat/responses calls.
	if h.providerFromHost(r) != "" || strings.TrimSpace(r.Header.Get("X-Descles-Provider-Base-URL")) != "" {
		var ok bool
		up, providerName, ok = h.resolveUpstream(r, "", orgID)
		if !ok || up == nil {
			writeError(w, http.StatusBadRequest, "no provider \""+providerName+"\" configured for this tenant")
			return
		}
	} else {
		if h.Registry == nil {
			writeError(w, http.StatusServiceUnavailable, "model routing is unavailable")
			return
		}
		selected := strings.TrimSpace(r.Header.Get("X-Descles-Provider"))
		configured := h.Registry.Default()
		if selected != "" {
			var ok bool
			configured, ok = h.Registry.ByName(selected)
			if !ok {
				writeError(w, http.StatusBadRequest, "unknown provider "+selected)
				return
			}
		}
		if configured.Upstream == nil {
			writeError(w, http.StatusServiceUnavailable, "no provider is configured")
			return
		}
		up = configured.Upstream
		providerName = configured.Name
		if providerName == "" {
			providerName = provider.ProviderName(up.BaseURL)
		}
		if h.OrgUpstream != nil && orgID != "" {
			if baseURL, key, found := h.OrgUpstream(orgID, providerName); found && baseURL != "" {
				clone := *up
				clone.BaseURL = baseURL
				if key != "" {
					clone.APIKey = key
				}
				up = &clone
			}
		}
		if providerKey := strings.TrimSpace(r.Header.Get("X-Descles-Provider-Key")); providerKey != "" {
			clone := *up
			clone.APIKey = providerKey
			up = &clone
		}
		r.Header.Del("X-Descles-Provider-Key")
	}

	if h.EgressCheck != nil {
		if err := h.EgressCheck(orgID, up.BaseURL); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}
	base := strings.TrimRight(up.BaseURL, "/")
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, base+"/models", nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "build models request: "+err.Error())
		return
	}
	if up.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+up.APIKey)
	}
	copyHeader(req.Header, r.Header, "OpenAI-Organization")
	copyHeader(req.Header, r.Header, "OpenAI-Project")
	resp, err := up.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(resp.Body)
	// Advertise the tenant's model aliases: with a model map configured, the
	// alias is a name this gateway accepts but the upstream has never heard of,
	// and clients discover endpoints by probing this route.
	if aliases, def, wire, ok := h.slotCatalog(orgID, providerName); ok && resp.StatusCode < http.StatusBadRequest {
		buf = mergeModelCatalog(buf, wire, aliases, def, providerName)
	}
	w.Header().Set("Content-Type", contentType(resp))
	copyUpstreamResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(buf)
}

// ---------- Internal read endpoints (M0 verification / dashboard seed) ----------

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (h *Handler) handleListSpans(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}
	spans, err := h.Store.Query(r.Context(), storage.SpanFilter{OrganizationID: h.requestOrg(r), Limit: limit, Offset: offset})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list spans: "+err.Error())
		return
	}
	if spans == nil {
		spans = []*tracing.Span{}
	}
	writeJSON(w, http.StatusOK, spans)
}

func (h *Handler) handleGetTrace(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/traces/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing trace id")
		return
	}
	spans, err := h.Store.Query(r.Context(), storage.SpanFilter{TraceID: id, OrganizationID: h.requestOrg(r)})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get trace: "+err.Error())
		return
	}
	if len(spans) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"trace_id": id, "spans": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, &tracing.Trace{TraceID: tracing.TraceID(id), Spans: spans})
}

// ---------- Dashboard query views (Requests + Costs) ----------

// handleRequests lists llm.call spans with optional filters, newest first.
func (h *Handler) handleRequests(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := storage.SpanFilter{
		TraceID:        q.Get("trace"),
		SessionID:      q.Get("session"),
		UserID:         q.Get("user"),
		AgentID:        q.Get("agent"),
		OrganizationID: h.requestOrg(r),
		Model:          q.Get("model"),
		Provider:       q.Get("provider"),
		Status:         q.Get("status"),
	}
	if v := q.Get("from"); v != "" {
		f.From = parseTime(v)
	}
	if v := q.Get("to"); v != "" {
		f.To = parseTime(v)
	}
	if v := q.Get("limit"); v != "" {
		f.Limit, _ = strconv.Atoi(v)
	}
	if v := q.Get("offset"); v != "" {
		f.Offset, _ = strconv.Atoi(v)
	}
	spans, err := h.Store.Query(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query requests: "+err.Error())
		return
	}
	if spans == nil {
		spans = []*tracing.Span{}
	}
	writeJSON(w, http.StatusOK, spans)
}

// handleCosts aggregates cost by model/provider/user/agent/project/day.
func (h *Handler) handleCosts(w http.ResponseWriter, r *http.Request) {
	group := r.URL.Query().Get("group")
	if group == "" {
		group = "model"
	}
	var from time.Time
	if v := r.URL.Query().Get("from"); v != "" {
		from = parseTime(v)
	}
	rows, err := h.Store.Costs(r.Context(), group, from, h.requestOrg(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "costs: "+err.Error())
		return
	}
	if rows == nil {
		rows = []storage.CostRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func parseTime(s string) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.UnixMilli(n)
	}
	return time.Time{}
}

// handlePolicyEvents returns recent spans whose policy_decision was not
// "allow" (e.g. a budget denial, or a tool decision recorded as an event).
func (h *Handler) handlePolicyEvents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	spans, err := h.Store.Query(r.Context(), storage.SpanFilter{OrganizationID: h.requestOrg(r), Limit: limit})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "policy events: "+err.Error())
		return
	}
	out := make([]*tracing.Span, 0)
	for _, s := range spans {
		d, _ := s.Attributes[tracing.AttrPolicy].(string)
		if d != "" && d != string(policy.Allow) {
			out = append(out, s)
		}
	}
	if out == nil {
		out = []*tracing.Span{}
	}
	writeJSON(w, http.StatusOK, out)
}

// budgetGate reports whether an agent OR its employee has already reached its
// daily budget. Budgets are denominated in USD and/or tokens (policy Budget):
// each configured cap is enforced against today's usage since UTC midnight. No
// budget configured -> never denied.
func (h *Handler) budgetGate(ctx context.Context, meta requestMeta) (bool, error) {
	pol := h.policyFor(meta.identity.OrganizationID)
	// Per-agent budget.
	if agent := meta.identity.AgentID; agent != "" {
		dailyUSD, usdOK := pol.BudgetFor(agent)
		if h.DelegatedDailyBudget != nil {
			if cap, ok := h.DelegatedDailyBudget(agent); ok && (!usdOK || cap < dailyUSD) {
				dailyUSD, usdOK = cap, true
			}
		}
		dailyTokens, tokenOK := pol.TokenBudgetFor(agent)
		if usdOK || tokenOK {
			if usdOK && dailyUSD <= 0 {
				return true, nil // legacy explicit zero: block the next request
			}
			rows, err := h.Store.Costs(ctx, "agent", startOfUTC(), meta.identity.OrganizationID)
			if err != nil {
				return false, err
			}
			for _, r := range rows {
				if r.Group != agent {
					continue
				}
				if usdOK && r.CostUSD >= dailyUSD {
					return true, nil
				}
				if tokenOK && int64(r.InputTokens+r.OutputTokens+r.CachedTokens) >= dailyTokens {
					return true, nil
				}
			}
		}
	}
	// Per-employee budget (legacy user dimension).
	if user := meta.identity.UserID; user != "" {
		dailyUSD, usdOK := pol.BudgetForUser(user)
		dailyTokens, tokenOK := pol.TokenBudgetForUser(user)
		if usdOK || tokenOK {
			if usdOK && dailyUSD <= 0 {
				return true, nil
			}
			rows, err := h.Store.Costs(ctx, "user", startOfUTC(), meta.identity.OrganizationID)
			if err != nil {
				return false, err
			}
			for _, r := range rows {
				if r.Group != user {
					continue
				}
				if usdOK && r.CostUSD >= dailyUSD {
					return true, nil
				}
				if tokenOK && int64(r.InputTokens+r.OutputTokens+r.CachedTokens) >= dailyTokens {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// applyToolPolicy records an auditable tool-decision event for any requested
// tool call that is not allowed, and tags the span with the full set of tool
// names the model proposed this turn (allowed, denied or suspended) so the
// console can show the workspace's real tool inventory. (Execution gating
// becomes live with the MCP gateway milestone; here it is recorded for the
// audit trail.)
func applyToolPolicy(span *tracing.Span, agent, group string, toolNames []string, pol *policy.Policy) {
	if len(toolNames) > 0 {
		span.Attributes["tools_proposed"] = append([]string(nil), toolNames...)
	}
	for _, tn := range toolNames {
		d := pol.ToolDecisionIn(agent, group, tn)
		if d != policy.Allow {
			span.Events = append(span.Events, tracing.Event{
				Name:       "policy.tool",
				Attributes: map[string]any{"tool": tn, "decision": string(d)},
			})
		}
	}
}

// rewriteStats reports what G1 response rewriting did to a response.
type rewriteStats struct {
	denied    int // tool calls stripped by a deny rule
	suspended int // tool calls parked pending human approval
}

// approvalSuspender opens a pending human approval for an LLM-generated tool
// call. It returns the approval ID, or "" / error when no approval could be
// opened (the caller then strips the call with an approval note).
type approvalSuspender func(agentID, tool string, args map[string]any) (approvalID string, err error)

// approvalBlocker implements blocking (synchronous) human approval: called
// after an approval is opened, it blocks until a human decides or a short
// window elapses. Allow = approved (the real tool call is delivered to the
// agent THIS turn), Deny = rejected, RequireApproval = timed out (approval
// stays durable; the pending note + resume path covers it).
type approvalBlocker func(approvalID, agentID, tool string, args map[string]any) policy.Decision

// approvalResumer reports whether an already-approved approval authorizes this
// exact (agent, tool, args) call to proceed without parking again. When true
// the resumer must mark the approval single-use (consume) so a second identical
// call cannot ride the same grant. This is the resume half of approval-suspend:
// the agent saw the pending note, a human approved in the console, and the
// agent re-issued the call — it must now flow through instead of hanging again.
type approvalResumer func(agentID, tool string, args map[string]any) bool

func delegatedToolDecision(pol *policy.Policy, agent, group, tool string, args map[string]any, guards []func(string, string, map[string]any) bool) policy.Decision {
	for _, guard := range guards {
		if guard != nil && !guard(agent, tool, args) {
			return policy.Deny
		}
	}
	return pol.ToolDecisionInArgs(agent, group, tool, args)
}

func (h *Handler) toolDecision(pol *policy.Policy, agent, group, tool string, args map[string]any) policy.Decision {
	return delegatedToolDecision(pol, agent, group, tool, args, []func(string, string, map[string]any) bool{h.DelegatedToolAllowed})
}

// rewriteDeniedToolCalls strips tool calls the policy denies from an
// OpenAI-compatible non-streaming response, rewriting each removed call into a
// text note so the runtime can surface why the call is missing. It returns the
// (possibly rewritten) body and the number of denied calls. This is G1
// "deny rewrite": the tool_call never reaches the runtime.
func rewriteDeniedToolCalls(buf []byte, agent, group string, pol *policy.Policy, suspend approvalSuspender, resume approvalResumer, blocker approvalBlocker, guard ...func(string, string, map[string]any) bool) ([]byte, rewriteStats) {
	var resp map[string]any
	if err := json.Unmarshal(buf, &resp); err != nil {
		return buf, rewriteStats{}
	}
	choices, ok := resp["choices"].([]any)
	if !ok {
		return buf, rewriteStats{}
	}
	var st rewriteStats
	for _, ci := range choices {
		choice, ok := ci.(map[string]any)
		if !ok {
			continue
		}
		msg, ok := choice["message"].(map[string]any)
		if !ok {
			continue
		}
		toolCalls, ok := msg["tool_calls"].([]any)
		if !ok || len(toolCalls) == 0 {
			continue
		}
		kept := make([]any, 0, len(toolCalls))
		for _, tci := range toolCalls {
			tc, ok := tci.(map[string]any)
			if !ok {
				kept = append(kept, tci)
				continue
			}
			fn, _ := tc["function"].(map[string]any)
			name, _ := fn["name"].(string)
			args := toolArguments(fn)
			switch delegatedToolDecision(pol, agent, group, name, args, guard) {
			case policy.Deny:
				st.denied++
				appendBlockedNote(msg, name)
				continue
			case policy.RequireApproval:
				switch dec, id := decideSuspendedCall(suspend, resume, blocker, agent, name, args); dec {
				case policy.Allow:
					// Approved (resume grant or blocking gate): deliver the real call.
					kept = append(kept, tci)
					continue
				case policy.Deny:
					st.denied++
					appendToolNote(msg, "[denied by human approval: "+name+"]")
					continue
				default:
					st.suspended++
					appendApprovalNote(msg, name, id)
					continue
				}
			}
			kept = append(kept, tci)
		}
		if len(kept) == 0 {
			delete(msg, "tool_calls")
		} else {
			msg["tool_calls"] = kept
		}
	}
	if st.denied == 0 && st.suspended == 0 {
		return buf, st
	}
	out, err := json.Marshal(resp)
	if err != nil {
		return buf, st
	}
	return out, st
}

// toolArguments best-effort parses a function call's arguments JSON string
// into a map (empty when absent or invalid).
func toolArguments(fn map[string]any) map[string]any {
	raw, _ := fn["arguments"].(string)
	args := map[string]any{}
	_ = json.Unmarshal([]byte(raw), &args)
	return args
}

// suspendApproval opens a pending approval via the suspender; returns "" when
// none is wired or the approval could not be opened.
func suspendApproval(suspend approvalSuspender, agent, tool string, args map[string]any) string {
	if suspend == nil {
		return ""
	}
	id, err := suspend(agent, tool, args)
	if err != nil || id == "" {
		return ""
	}
	return id
}

// decideSuspendedCall resolves a require_approval call through the approval
// pipeline. Returns the outcome and the approval id when one was opened.
func decideSuspendedCall(suspend approvalSuspender, resume approvalResumer, blocker approvalBlocker, agent, tool string, args map[string]any) (policy.Decision, string) {
	if resume != nil && resume(agent, tool, args) {
		return policy.Allow, ""
	}
	id := suspendApproval(suspend, agent, tool, args)
	if blocker != nil && id != "" {
		if dec := blocker(id, agent, tool, args); dec != policy.RequireApproval {
			return dec, id
		}
	}
	return policy.RequireApproval, id
}

// approvalOutcome is the Handler-shaped decideSuspendedCall (wires the
// handler's resumer + blocker). Streaming flushes use this so a blocking
// approval holds the flush and then delivers the real call.
func (h *Handler) approvalOutcome(suspend approvalSuspender, agent, tool string, args map[string]any) (policy.Decision, string) {
	return decideSuspendedCall(suspend, h.ApprovalResumer, h.ApprovalBlocker, agent, tool, args)
}

// appendBlockedNote appends a human-readable note about a denied tool to an
// assistant message's content (string, array, or previously empty).
func appendBlockedNote(msg map[string]any, name string) {
	appendToolNote(msg, "[blocked by Descles policy: "+name+"]")
}

// appendApprovalNote appends a note that a tool call was parked for human
// approval, carrying the approval id when one was opened.
func appendApprovalNote(msg map[string]any, name, approvalID string) {
	note := "[requires human approval before execution: " + name + "]"
	if approvalID != "" {
		note = "[pending human approval: " + name + " (approval " + approvalID + ")]"
	}
	appendToolNote(msg, note)
}

// appendToolNote appends a text note to an assistant message's content.
func appendToolNote(msg map[string]any, note string) {
	switch c := msg["content"].(type) {
	case string:
		msg["content"] = c + "\n\n" + note
	case nil:
		msg["content"] = note
	default:
		if arr, ok := c.([]any); ok {
			msg["content"] = append(arr, map[string]any{"type": "text", "text": note})
		}
	}
}

// rewriteDeniedToolCallsResponses strips denied function_call items from an
// OpenAI Responses API non-streaming response, replacing each with an
// output_text message note.
func rewriteDeniedToolCallsResponses(buf []byte, agent, group string, pol *policy.Policy, suspend approvalSuspender, resume approvalResumer, blocker approvalBlocker, guard ...func(string, string, map[string]any) bool) ([]byte, rewriteStats) {
	var resp map[string]any
	if err := json.Unmarshal(buf, &resp); err != nil {
		return buf, rewriteStats{}
	}
	output, ok := resp["output"].([]any)
	if !ok {
		return buf, rewriteStats{}
	}
	var st rewriteStats
	kept := make([]any, 0, len(output))
	for _, oi := range output {
		item, ok := oi.(map[string]any)
		if !ok {
			kept = append(kept, oi)
			continue
		}
		if item["type"] == "function_call" {
			name, _ := item["name"].(string)
			args := map[string]any{}
			if raw, _ := item["arguments"].(string); raw != "" {
				_ = json.Unmarshal([]byte(raw), &args)
			}
			switch delegatedToolDecision(pol, agent, group, name, args, guard) {
			case policy.Deny:
				st.denied++
				kept = append(kept, map[string]any{
					"type":    "message",
					"role":    "assistant",
					"content": []any{map[string]any{"type": "output_text", "text": "[blocked by Descles policy: " + name + "]"}},
				})
				continue
			case policy.RequireApproval:
				switch dec, id := decideSuspendedCall(suspend, resume, blocker, agent, name, args); dec {
				case policy.Allow:
					kept = append(kept, oi)
					continue
				case policy.Deny:
					st.denied++
					kept = append(kept, map[string]any{
						"type":    "message",
						"role":    "assistant",
						"content": []any{map[string]any{"type": "output_text", "text": "[denied by human approval: " + name + "]"}},
					})
					continue
				default:
					st.suspended++
					note := "[requires human approval before execution: " + name + "]"
					if id != "" {
						note = "[pending human approval: " + name + " (approval " + id + ")]"
					}
					kept = append(kept, map[string]any{
						"type":    "message",
						"role":    "assistant",
						"content": []any{map[string]any{"type": "output_text", "text": note}},
					})
					continue
				}
			}
		}
		kept = append(kept, oi)
	}
	if st.denied == 0 && st.suspended == 0 {
		return buf, st
	}
	resp["output"] = kept
	out, err := json.Marshal(resp)
	if err != nil {
		return buf, st
	}
	return out, st
}

func startOfUTC() time.Time {
	now := time.Now().UTC()
	y, m, d := now.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// ---------- Shared helpers ----------

type requestMeta struct {
	traceID   tracing.TraceID
	spanID    tracing.SpanID
	sessionID string
	identity  identity.Identity
}

func (h *Handler) beginMeta(r *http.Request) requestMeta {
	id := identity.FromHeaders(r.Header)
	// Tenant binding: when a key resolver is wired, the org is derived from
	// the bearer key (authoritative) — never trusted from the header. The same
	// applies to user and agent: a key without that binding must not inherit a
	// caller-supplied X-Descles-User or X-Descles-Agent identity.
	if h.KeyResolver != nil {
		id.OrganizationID, id.UserID, id.AgentID = "", "", ""
		if key := desclesClientKey(r); key != "" {
			if orgID, employeeID, agentID, ok := h.KeyResolver(key); ok {
				id.OrganizationID = orgID
				id.UserID = employeeID
				id.AgentID = agentID
			}
		}
	}
	traceID := tracing.TraceID(id.TraceID)
	if traceID == "" {
		traceID = tracing.NewTraceID()
	}
	spanID := tracing.NewSpanID()
	sessionID := id.SessionID
	if sessionID == "" {
		sessionID = tracing.RandHex(8)
	}
	return requestMeta{traceID: traceID, spanID: spanID, sessionID: sessionID, identity: id}
}

// bearerKey extracts the plaintext key from an "Authorization: Bearer <key>"
// header (empty when absent or malformed).
func bearerKey(auth string) string {
	const p = "Bearer "
	if !strings.HasPrefix(auth, p) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(auth, p))
}

// desclesClientKey supports the native authentication shape of each SDK:
// OpenAI-compatible clients use Authorization Bearer; Anthropic clients use
// x-api-key. In both cases this is the Descles key, never the provider key.
func desclesClientKey(r *http.Request) string {
	if key := bearerKey(r.Header.Get("Authorization")); key != "" {
		return key
	}
	// Native Anthropic clients authenticate with x-api-key, not Bearer. Accept
	// it on both Anthropic routes: the canonical /v1/messages alias a client
	// reaches via ANTHROPIC_BASE_URL, and the legacy /anthropic/v1/ namespace.
	// The check stays path-scoped so an OpenAI-plane request can never have its
	// x-api-key mistaken for a Descles token.
	if r.URL.Path == "/v1/messages" || strings.HasPrefix(r.URL.Path, "/anthropic/v1/") {
		return strings.TrimSpace(r.Header.Get("x-api-key"))
	}
	return ""
}

// requestOrg resolves the tenant org for a query request: from the bearer key
// when a resolver is wired, else the X-Descles-Org header. Empty in single-tenant
// (metadata-only) mode.
func (h *Handler) requestOrg(r *http.Request) string {
	if h.KeyResolver != nil {
		if key := desclesClientKey(r); key != "" {
			if orgID, _, _, ok := h.KeyResolver(key); ok {
				return orgID
			}
		}
		return ""
	}
	return r.Header.Get("X-Descles-Org")
}

func actorType(id identity.Identity) string {
	if id.UserID != "" {
		return "user"
	}
	if id.AgentID != "" {
		return "agent"
	}
	return ""
}

func actorID(id identity.Identity) string {
	if id.UserID != "" {
		return id.UserID
	}
	return id.AgentID
}

// groupOf resolves an agent's policy group name (nil-safe).
func (h *Handler) groupOf(agent string) string {
	if h.GroupOfAgent != nil {
		return h.GroupOfAgent(agent)
	}
	return ""
}

// policyFor returns the effective policy for an org: the org's own holder when
// configured, else the global holder.
func (h *Handler) policyFor(orgID string) *policy.Policy {
	if orgID != "" && h.OrgPolicy != nil {
		if hp := h.OrgPolicy(orgID); hp != nil {
			return hp.Get()
		}
	}
	return h.Policy.Get()
}
func (h *Handler) fail(span *tracing.Span, errorType string, err error) {
	span.Status = tracing.StatusError
	span.ErrorType = errorType
	span.EndedAt = time.Now().UTC()
	span.Attributes["error"] = err.Error()
	if err := h.Store.PutSpan(context.Background(), span); err != nil {
		h.Logger.Error("store error span", "err", err)
	}
}

// finalizeSpan records timing, usage, cost and status on a span.
func finalizeSpan(span *tracing.Span, model string, u provider.Usage, toolCalls int, cost float64, statusCode int) {
	span.EndedAt = time.Now().UTC()
	if model != "" {
		span.Attributes[tracing.AttrModel] = model
	}
	span.Attributes[tracing.AttrInputToks] = u.InputTokens
	span.Attributes[tracing.AttrOutputToks] = u.OutputTokens
	span.Attributes[tracing.AttrCachedToks] = u.CachedTokens
	span.Attributes[tracing.AttrCostUSD] = cost
	span.Attributes[tracing.AttrToolCalls] = toolCalls
	span.Attributes[tracing.AttrLatencyMS] = span.EndedAt.Sub(span.StartedAt).Milliseconds()
	if statusCode >= 400 {
		span.Status = tracing.StatusError
		span.ErrorType = "upstream_http_" + strconv.Itoa(statusCode)
	} else {
		span.Status = tracing.StatusOK
	}
}

// estimate prices a call with the tenant's override table when present and
// records where the price came from, so a cost derived from the generic
// fallback rate is visible in the ledger rather than looking like a real price.
func (h *Handler) estimate(span *tracing.Span, orgID, model string, inputTokens, outputTokens, cachedTokens int) float64 {
	var overrides map[string]pricing.Price
	if h.OrgPrices != nil && orgID != "" {
		if m, ok := h.OrgPrices(orgID); ok {
			overrides = m
		}
	}
	cost, source := pricing.NewResolver(overrides).EstimateAt(model, inputTokens, outputTokens, cachedTokens, time.Now().UTC())
	if span != nil {
		span.Attributes[tracing.AttrCostSource] = source
	}
	return cost
}

// priceModelFor picks the model name to price a call by. The span's model
// attribute is what the client asked for (an alias when a slot maps names);
// upstream_model is what actually served it, and pricing the alias would charge
// one vendor's rates for another vendor's tokens.
func priceModelFor(span *tracing.Span, fallback string) string {
	if span != nil {
		if up, ok := span.Attributes["upstream_model"].(string); ok && up != "" {
			return up
		}
	}
	return fallback
}

// ExportPriceModelFor exposes the pricing-name resolution to the test package.
func ExportPriceModelFor(span *tracing.Span, fallback string) string {
	return priceModelFor(span, fallback)
}

func setIDHeaders(w http.ResponseWriter, meta requestMeta) {
	w.Header().Set("X-Request-Id", string(meta.spanID))
	w.Header().Set("X-Trace-Id", string(meta.traceID))
	w.Header().Set("X-Descles-Session", meta.sessionID)
}

func contentType(resp *http.Response) string {
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		return ct
	}
	return "application/json"
}

func copyHeader(dst, src http.Header, name string) {
	for _, value := range src.Values(name) {
		dst.Add(name, value)
	}
}

func copyUpstreamResponseHeaders(dst, src http.Header) {
	for name, values := range src {
		lower := strings.ToLower(name)
		if lower != "retry-after" && !strings.HasPrefix(lower, "x-ratelimit-") {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"message": msg, "type": "descles_error"},
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
