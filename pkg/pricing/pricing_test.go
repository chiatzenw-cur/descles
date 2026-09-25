package pricing_test

import (
	"math"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/pricing"
)

// Off-peak list prices come from api-docs.deepseek.com/quick_start/pricing;
// peak bills double. A table that lacks the models actually in use silently
// falls back to the default rate, which is how every translated call was
// priced before this was covered.
func TestDeepSeekModelsArePriced(t *testing.T) {
	// 2026-09-22 is a Tuesday; 12:00 UTC is off-peak (peak is 01-04 and 06-10).
	offPeak := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	peak := time.Date(2026, 9, 22, 2, 0, 0, 0, time.UTC)
	weekend := time.Date(2026, 9, 26, 2, 0, 0, 0, time.UTC) // Saturday, same hour

	const m = 1_000_000

	flashOff := pricing.EstimateAt("deepseek-flash", m, m, 0, offPeak)
	if math.Abs(flashOff-0.75) > 1e-9 { // 0.15 in + 0.60 out
		t.Fatalf("flash off-peak = %v, want 0.75", flashOff)
	}
	flashPeak := pricing.EstimateAt("deepseek-flash", m, m, 0, peak)
	if math.Abs(flashPeak-1.50) > 1e-9 {
		t.Fatalf("flash peak = %v, want 1.50 (double)", flashPeak)
	}
	proOff := pricing.EstimateAt("deepseek-v4-pro", m, m, 0, offPeak)
	if math.Abs(proOff-2.64) > 1e-9 { // 0.66 in + 1.98 out
		t.Fatalf("pro off-peak = %v, want 2.64", proOff)
	}
	// Weekends are off-peak at every hour.
	if got := pricing.EstimateAt("deepseek-v4-pro", m, 0, 0, weekend); math.Abs(got-0.66) > 1e-9 {
		t.Fatalf("weekend pro input = %v, want off-peak 0.66", got)
	}
	// Cached input is its own, much cheaper rate.
	if got := pricing.EstimateAt("deepseek-v4-pro", 0, 0, m, offPeak); math.Abs(got-0.022) > 1e-9 {
		t.Fatalf("cached input = %v, want 0.022", got)
	}
	// Non-DeepSeek models are unaffected by the peak schedule.
	if pricing.EstimateAt("gpt-4o", m, 0, 0, peak) != pricing.EstimateAt("gpt-4o", m, 0, 0, offPeak) {
		t.Fatalf("peak multiplier leaked onto a non-DeepSeek model")
	}
}

// A wrong rate silently mis-bills every call to that model, and the table is
// now far too big to proof-read by eye — so the invariants are checked instead.
func TestTableEntriesAreSane(t *testing.T) {
	all := pricing.All()
	if len(all) < 40 {
		t.Fatalf("table shrank to %d entries — did a provider block get dropped?", len(all))
	}
	for model, p := range all {
		if model == "_default" {
			continue
		}
		if p.Input <= 0 || p.Output <= 0 {
			t.Fatalf("%s: input/output must both be positive (a zero silently under-charges): %+v", model, p)
		}
		if p.Cached < 0 {
			t.Fatalf("%s: negative cached rate %+v", model, p)
		}
		// Cached input is always the cheapest input tier.
		if p.Cached > p.Input {
			t.Fatalf("%s: cached input %v above standard input %v", model, p.Cached, p.Input)
		}
		// Output is never cheaper than input on any provider we list.
		if p.Output < p.Input {
			t.Fatalf("%s: output %v cheaper than input %v — looks like swapped columns", model, p.Output, p.Input)
		}
	}
}

// Pin one entry per provider family so an edit that breaks a whole block is
// caught, and so the numbers in the table stay traceable to their source.
func TestTablePinsOneEntryPerProvider(t *testing.T) {
	want := map[string]pricing.Price{
		"gpt-6-astra":           {10.00, 50.00, 1.00},
		"gpt-5.6-luna":          {0.20, 1.20, 0.02},
		"gpt-5.6-cyber":         {12.50, 75.00, 1.25},
		"claude-opus-5":         {5.00, 25.00, 0.50},
		"claude-sonnet-5":       {2.00, 10.00, 0.20},
		"claude-haiku-4-5":      {1.00, 5.00, 0.10},
		"deepseek-v4-pro":       {0.66, 1.98, 0.022},
		"gemini-3.8-flash":      {0.75, 3.75, 0.075},
		"gemini-2.5-pro":        {1.25, 10.00, 0.125},
		"grok-4.7":              {2.00, 6.00, 2.00}, // no cached rate published
		"mistral-large-3-25-12": {0.50, 1.50, 0.05},
		"kimi-k3":               {3.00, 15.00, 0.30},
		"glm-5.3":               {1.40, 4.40, 0.26},
		"qwen3.8-max":           {2.00, 6.00, 2.00}, // no cached rate published,
	}
	for model, wantPrice := range want {
		if got := pricing.Get(model); got != wantPrice {
			t.Fatalf("%s = %+v, want %+v", model, got, wantPrice)
		}
		// And it must be listed, not silently served by the fallback entry.
		if _, source := pricing.NewResolver(nil).Lookup(model); source != pricing.SourceBuiltin {
			t.Fatalf("%s is not in the built-in table (source %q)", model, source)
		}
	}
}

func TestUnknownModelFallsBackToDefault(t *testing.T) {
	at := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	got := pricing.EstimateAt("some-unlisted-model", 1_000_000, 0, 0, at)
	if got != pricing.Get("_default").Input {
		t.Fatalf("fallback = %v, want the default rate %v", got, pricing.Get("_default").Input)
	}
}

// DeepSeek still accepts these legacy ids and serves them with the current
// model of the same tier, so they have to price like it instead of falling
// through to the generic rate (a retired name is not an unknown name).
func TestLegacyDeepSeekIdsPriceAsTheirTier(t *testing.T) {
	for _, legacy := range []string{"deepseek-v4-flash", "deepseek-v4-flash-vision-exp"} {
		if pricing.Get(legacy) != pricing.Get("deepseek-flash") {
			t.Fatalf("%s should price as flash: %+v vs %+v", legacy, pricing.Get(legacy), pricing.Get("deepseek-flash"))
		}
	}
	// Retired-and-not-served ids keep a historical price so old spans still price.
	for _, retired := range []string{"deepseek-chat", "deepseek-reasoner", "deepseek-v3"} {
		if pricing.Get(retired) == pricing.Get("_default") {
			t.Fatalf("%s should keep a historical price, not the generic rate", retired)
		}
	}
}
