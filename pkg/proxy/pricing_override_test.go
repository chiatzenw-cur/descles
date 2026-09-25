package proxy_test

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/pricing"
	"github.com/chiatzenw-cur/descles/pkg/proxy"
	"github.com/chiatzenw-cur/descles/pkg/tracing"
)

// pricingUpstream answers an OpenAI-wire call with a fixed model and usage.
func pricingUpstream(model string, in, out int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"chatcmpl-1","model":"`+model+`","choices":[{"index":0,"finish_reason":"stop",`+
			`"message":{"content":"ok"}}],"usage":{"prompt_tokens":`+itoa(in)+`,"completion_tokens":`+itoa(out)+`}}`)
	}))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

func latestSpan(t *testing.T, h *proxy.Handler) *tracing.Span {
	t.Helper()
	spans, err := h.Store.ListRecent(context.Background(), 3)
	if err != nil || len(spans) == 0 {
		t.Fatalf("no span: %v", err)
	}
	return spans[0]
}

// A request whose prefix was mostly cache hits must be billed once: fresh input
// at the input rate, cached input at the cached rate, output at the output rate.
// Billing prompt_tokens (which already include the cached subset) as fresh input
// charged the cache hit twice at full rate — for agent traffic, where the system
// prompt and tool schemas are nearly always cached, that dominated the bill.
func TestCachedPrefixIsNotBilledTwice(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"chatcmpl-1","model":"deepseek-v4-pro","choices":[{"index":0,"finish_reason":"stop",`+
			`"message":{"content":"ok"}}],"usage":{"prompt_tokens":1000,"completion_tokens":10,"total_tokens":1010,`+
			`"prompt_tokens_details":{"cached_tokens":800}}}`)
	}))
	defer upstream.Close()
	h := newTranslatedFixture(t, upstream, "openai")
	h.OrgSlotConfig = func(orgID, slot string) (string, map[string]string, string, bool) {
		return "openai", map[string]string{"claude-*": "deepseek-v4-pro"}, "", true
	}

	rr := translatedRequest(t, h, `{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	span := latestSpan(t, h)

	// Fresh input is prompt minus cached; cached stays its own line.
	if in := span.Attributes[tracing.AttrInputToks]; in != 200 {
		t.Fatalf("input_tokens = %v, want the fresh 200 (1000 prompt - 800 cached)", in)
	}
	if c := span.Attributes[tracing.AttrCachedToks]; c != 800 {
		t.Fatalf("cached_tokens = %v, want 800", c)
	}
	// The vendor's total is preserved so token budgets are unaffected.
	total := span.Attributes[tracing.AttrInputToks].(int) +
		span.Attributes[tracing.AttrCachedToks].(int) +
		span.Attributes[tracing.AttrOutputToks].(int)
	if total != 1010 {
		t.Fatalf("input + cached + output = %d, want the upstream total 1010", total)
	}

	want := pricing.EstimateAt("deepseek-v4-pro", 200, 10, 800, time.Now().UTC())
	doubleCharged := pricing.EstimateAt("deepseek-v4-pro", 1000, 10, 800, time.Now().UTC())
	cost, _ := span.Attributes[tracing.AttrCostUSD].(float64)
	if math.Abs(cost-want) > want*0.0001 {
		t.Fatalf("cost = %v, want %v (the double-charged figure would be %v)", cost, want, doubleCharged)
	}
}

// A tenant price table must win over the built-in list price: this is how a
// self-hosted or negotiated-rate model gets a real cost instead of the generic
// fallback figure, and how an org corrects a list price that has drifted.
func TestTenantPriceTableOverridesBuiltin(t *testing.T) {
	upstream := pricingUpstream("deepseek-chat", 30, 5)
	defer upstream.Close()
	h := newTranslatedFixture(t, upstream, "openai")
	h.OrgPrices = func(orgID string) (map[string]pricing.Price, bool) {
		if orgID != "org1" {
			return nil, false
		}
		return map[string]pricing.Price{"deepseek-chat": {Input: 100, Output: 200}}, true
	}

	rr := translatedRequest(t, h, `{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	span := latestSpan(t, h)
	cost, _ := span.Attributes[tracing.AttrCostUSD].(float64)
	builtin := pricing.Estimate("deepseek-chat", 30, 5, 0)
	want, _ := pricing.NewResolver(map[string]pricing.Price{"deepseek-chat": {Input: 100, Output: 200}}).EstimateAt("deepseek-chat", 30, 5, 0, time.Now().UTC())
	if math.Abs(cost-want) > want*0.0001 {
		t.Fatalf("cost = %v, want %v (tenant price); built-in price would be %v", cost, want, builtin)
	}
	if got, _ := span.Attributes[tracing.AttrCostSource].(string); got != pricing.SourceOrg {
		t.Fatalf("cost_source = %q, want %q", got, pricing.SourceOrg)
	}
}

// The ledger has to say when a price was invented: an unlisted model is priced
// from the generic fallback rate, and that must be visible rather than looking
// like a real list price.
//
// Note the priced name is the one the gateway ASKED the upstream for (the slot's
// mapped name), not whatever the upstream echoes back in its response body.
func TestCostSourceLabelsBuiltinAndFallback(t *testing.T) {
	for _, tc := range []struct {
		mapped string
		source string
	}{
		{"deepseek-chat", pricing.SourceBuiltin},
		{"my-unlisted-model", pricing.SourceFallback},
	} {
		upstream := pricingUpstream(tc.mapped, 10, 2)
		h := newTranslatedFixture(t, upstream, "openai")
		h.OrgSlotConfig = func(orgID, slot string) (string, map[string]string, string, bool) {
			return "openai", map[string]string{"claude-*": tc.mapped}, "", true
		}
		rr := translatedRequest(t, h, `{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", tc.mapped, rr.Code, rr.Body.String())
		}
		span := latestSpan(t, h)
		if got, _ := span.Attributes[tracing.AttrCostSource].(string); got != tc.source {
			t.Fatalf("%s: cost_source = %q, want %q", tc.mapped, got, tc.source)
		}
		upstream.Close()
	}
}

// A tenant table that does not mention the model must not change anything.
func TestTenantPriceTableOnlyAffectsListedModels(t *testing.T) {
	upstream := pricingUpstream("deepseek-v4-pro", 10, 2)
	defer upstream.Close()
	h := newTranslatedFixture(t, upstream, "openai")
	h.OrgPrices = func(orgID string) (map[string]pricing.Price, bool) {
		return map[string]pricing.Price{"something-else": {Input: 999, Output: 999}}, true
	}
	rr := translatedRequest(t, h, `{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	span := latestSpan(t, h)
	cost, _ := span.Attributes[tracing.AttrCostUSD].(float64)
	// The fixture's slot maps claude-* → deepseek-chat, so that is the model the
	// call is billed as; an unrelated tenant entry must not touch it.
	want := pricing.Estimate("deepseek-chat", 10, 2, 0)
	if math.Abs(cost-want) > want*0.0001 {
		t.Fatalf("cost = %v, want the built-in price %v", cost, want)
	}
	if got, _ := span.Attributes[tracing.AttrCostSource].(string); got != pricing.SourceBuiltin {
		t.Fatalf("cost_source = %q, want %q", got, pricing.SourceBuiltin)
	}
}
