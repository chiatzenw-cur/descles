// Package pricing estimates per-request USD cost from token usage.
//
// This is a curated table of list-price-per-1M-tokens for the providers Descles
// commonly sits in front of. It is an ESTIMATE, not a billing source of
// truth — prices drift and enterprise contracts are negotiated. The table is
// deliberately small and easy to extend; a future milestone can source it
// from provider APIs or a config file.
package pricing

import (
	"strings"
	"time"
)

// Price is USD per 1M tokens.
type Price struct {
	Input  float64
	Output float64
	Cached float64
}

// prices is the built-in list-price table in USD per 1M tokens as
// {input, output, cached input}. Every block cites its source and the date it
// was checked — prices drift, so this is an estimate, and a tenant can override
// any model in it (see Resolver / OrgPrices).
//
// Convention: standard tier, short context, list price, no batch/flex/priority
// discounts. Where a vendor prices long context or peak hours differently, the
// comment says so; the table stores the entry-tier figure.
//
// Cached input: if a vendor does not publish a cached-input rate, the entry
// repeats its input rate rather than using 0 — an unknown discount must not turn
// into a free line on the bill (cached tokens are recorded separately, see the
// provider package).
//
// Usage.InputTokens excludes cached tokens on every wire, so the three columns
// above are the three things a request is billed for.
var prices = map[string]Price{
	// OpenAI — developers.openai.com/api/docs/pricing (checked 2026-09-22).
	// Short-context standard tier. Long context bills 2x input / 1.5x output;
	// cache writes are billed separately. Neither is modelled here.
	// gpt-5.5 / 5.4 / 5.2 are NOT listed: they did not appear in the page as
	// fetched, and an unverified number is worse than the labelled fallback —
	// a tenant can price them in the console instead.
	"gpt-6-astra":   {10.00, 50.00, 1.00},
	"gpt-5.6-sol":   {4.00, 20.00, 0.40}, // promotional at least through 2026-11-21
	"gpt-5.6-terra": {2.00, 12.00, 0.20},
	"gpt-5.6-luna":  {0.20, 1.20, 0.02},
	"gpt-5.6-cyber": {12.50, 75.00, 1.25}, // no long-context row published
	"gpt-5.3-codex": {1.75, 14.00, 0.175},
	// No longer on OpenAI's pricing page (retired): kept so historical spans
	// still price instead of falling through to the generic rate.
	"gpt-4o":               {2.50, 10.00, 1.25},
	"gpt-4o-mini":          {0.15, 0.60, 0.075},
	"gpt-4.1":              {2.00, 8.00, 0.50},
	"gpt-4.1-mini":         {0.40, 1.60, 0.10},
	"gpt-4.1-nano":         {0.10, 0.40, 0.025},
	"gpt-3.5-turbo":        {0.50, 1.50, 0.50},
	"gpt-4o-audio-preview": {2.50, 10.00, 1.25},

	// Anthropic — docs.anthropic.com/en/docs/about-claude/pricing (checked
	// 2026-09-22). Cache hits bill at 0.1x input (the table's cached column).
	// Fable 5.1 / Mythos 5.1 are limited-availability at $10/$50 and are not
	// listed here.
	"claude-opus-5":              {5.00, 25.00, 0.50},
	"claude-opus-4-8":            {5.00, 25.00, 0.50},
	"claude-opus-4-7":            {5.00, 25.00, 0.50},
	"claude-opus-4-6":            {5.00, 25.00, 0.50},
	"claude-opus-4-5":            {5.00, 25.00, 0.50},
	"claude-sonnet-5":            {2.00, 10.00, 0.20},
	"claude-sonnet-4-6":          {3.00, 15.00, 0.30},
	"claude-sonnet-4-5":          {3.00, 15.00, 0.30},
	"claude-haiku-4-5":           {1.00, 5.00, 0.10},
	"claude-3-5-sonnet-20241022": {3.00, 15.00, 0.30},
	"claude-3-5-haiku-20241022":  {0.80, 4.00, 0.08},
	"claude-sonnet-4-20250514":   {3.00, 15.00, 0.30},
	"claude-3-7-sonnet-20250219": {3.00, 15.00, 0.30},

	// DeepSeek — api-docs.deepseek.com/quick_start/pricing (checked 2026-09-22).
	// OFF-PEAK rates; peak bills exactly double and EstimateAt applies it. Peak
	// hours are 01:00-04:00 and 06:00-10:00 UTC Mon-Fri, excluding Chinese
	// public holidays (holidays are off-peak and are not modelled, so a holiday
	// call inside a peak window is over-estimated, never under-estimated).
	"deepseek-flash":               {0.15, 0.60, 0.003},
	"deepseek-v4-pro":              {0.66, 1.98, 0.022},
	"deepseek-v4-flash":            {0.15, 0.60, 0.003}, // legacy id, served by V4.1-Flash
	"deepseek-v4-flash-vision-exp": {0.15, 0.60, 0.003}, // legacy id, served by V4.1-Flash
	"deepseek-chat":                {0.27, 1.10, 0.07},  // retired, kept for history
	"deepseek-reasoner":            {0.55, 2.19, 0.14},  // retired, kept for history
	"deepseek-v3":                  {0.27, 1.10, 0.07},  // retired, kept for history

	// Google Gemini — ai.google.dev/gemini-api/docs/pricing (checked 2026-09-22).
	// Standard paid tier for <=200k prompts. NOTE: the current Flash rates are
	// promotional and DOUBLE on 2027-01-01 ($0.75/$3.75 becomes $1.50/$7.50 for
	// the 3.6-3.8 generation) — this table will need an update then. Audio input
	// costs more on Flash models and is not modelled.
	"gemini-3.8-flash":       {0.75, 3.75, 0.075},
	"gemini-3.7-flash":       {0.75, 3.75, 0.075},
	"gemini-3.6-flash":       {0.75, 3.75, 0.075},
	"gemini-3.5-flash":       {1.50, 9.00, 0.15},
	"gemini-3.5-flash-lite":  {0.30, 2.50, 0.03},
	"gemini-3.1-flash-lite":  {0.25, 1.50, 0.025},
	"gemini-3.1-pro-preview": {2.00, 12.00, 0.20},
	"gemini-2.5-pro":         {1.25, 10.00, 0.125},
	"gemini-2.5-flash":       {0.30, 2.50, 0.03},
	"gemini-omni-1.1-flash":  {1.50, 9.00, 1.50},

	// xAI — docs.x.ai (checked 2026-09-22). No cached-input rate is published.
	"grok-4.7": {2.00, 6.00, 2.00},

	// Mistral — docs.mistral.ai/inference/pricing (checked 2026-09-22). Ids are
	// the docs' model slugs for the dated releases.
	"mistral-large-3-25-12":    {0.50, 1.50, 0.05},
	"mistral-medium-3-5-26-04": {1.50, 7.50, 0.15},
	"mistral-small-4-0-26-03":  {0.15, 0.60, 0.015},
	"ministral-3-14b-25-12":    {0.20, 0.20, 0.02},
	"ministral-3-8b-25-12":     {0.15, 0.15, 0.015},
	"ministral-3-3b-25-12":     {0.10, 0.10, 0.01},
	"codestral-25-08":          {0.30, 0.90, 0.03},

	// Moonshot Kimi — platform.kimi.ai/docs/pricing (checked 2026-09-22). K3 also
	// bills cache WRITES ($3.00/1M at 5min TTL, $6.00 at 1h) which this table
	// cannot express; only cached reads are modelled.
	"kimi-k3":                  {3.00, 15.00, 0.30},
	"kimi-k2.7-code":           {0.95, 4.00, 0.19},
	"kimi-k2.7-code-highspeed": {1.90, 8.00, 0.38},
	"kimi-k2.6":                {0.95, 4.00, 0.16},

	// Z.ai GLM — docs.z.ai/guides/overview/pricing (checked 2026-09-22). The
	// CN platform (open.bigmodel.cn) quotes the same models in CNY and is not
	// used here: no FX rate is baked into this table.
	"glm-5.3":        {1.40, 4.40, 0.26},
	"glm-5.3-flash":  {0.15, 0.50, 0.03},
	"glm-5.3-flashx": {0.37, 1.25, 0.075},
	"glm-5.2":        {1.40, 4.40, 0.26},
	"glm-5.1":        {1.40, 4.40, 0.26},
	"glm-5":          {1.00, 3.20, 0.20},
	"glm-4.7":        {0.60, 2.20, 0.11},
	"glm-4.6":        {0.60, 2.20, 0.11},

	// Alibaba Qwen — alibabacloud.com/help/en/model-studio/model-pricing
	// (checked 2026-09-22), International deployment, standard tier. No cached
	// input rate is published for these, so cached repeats the input rate.
	"qwen3.8-max":       {2.00, 6.00, 2.00},
	"qwen3.7-plus":      {0.40, 1.60, 0.40},
	"qwen3.8-flash":     {0.15, 0.47, 0.15},
	"qwen3.7-flash":     {0.03, 0.13, 0.03}, // <=32k prompts
	"qwen-flash":        {0.05, 0.40, 0.05},
	"qwen3-coder-plus":  {1.00, 5.00, 1.00}, // <=32k prompts
	"qwen3-coder-flash": {0.30, 1.50, 0.30},

	// Fallback for anything not listed. A span priced from this entry is marked
	// cost_source="fallback" so the ledger never presents it as a real price.
	"_default": {1.00, 2.00, 0.50},
}

// All returns a copy of the built-in price table, keyed by model.
func All() map[string]Price {
	out := make(map[string]Price, len(prices))
	for model, p := range prices {
		out[model] = p
	}
	return out
}

// Get returns the price entry for a model, falling back to the default.
func Get(model string) Price {
	if p, ok := prices[model]; ok {
		return p
	}
	return prices["_default"]
}

// Resolver prices calls with an optional per-tenant override table on top of the
// built-in list prices. Price sources are reported so a cost that came from the
// generic fallback rate (i.e. nobody knows this model's real price) is visible in
// the ledger instead of looking authoritative.
type Resolver struct {
	overrides map[string]Price
}

// NewResolver builds a resolver. overrides may be nil.
func NewResolver(overrides map[string]Price) *Resolver {
	return &Resolver{overrides: overrides}
}

// Price sources reported on spans.
const (
	SourceOrg      = "org"      // tenant-supplied price
	SourceBuiltin  = "builtin"  // curated list price
	SourceFallback = "fallback" // unknown model, generic rate
)

// Lookup returns the price for a model and where it came from.
func (r *Resolver) Lookup(model string) (Price, string) {
	if r != nil {
		if p, ok := r.overrides[model]; ok {
			return p, SourceOrg
		}
	}
	if p, ok := prices[model]; ok {
		return p, SourceBuiltin
	}
	return prices["_default"], SourceFallback
}

// EstimateAt prices a request at a given instant and reports the price source.
func (r *Resolver) EstimateAt(model string, inputTokens, outputTokens, cachedTokens int, at time.Time) (float64, string) {
	p, source := r.Lookup(model)
	multiplier := 1.0
	if isDeepSeekPeak(at) && isDeepSeek(model) {
		multiplier = 2.0
	}
	return float64(inputTokens)/1e6*p.Input*multiplier +
		float64(outputTokens)/1e6*p.Output*multiplier +
		float64(cachedTokens)/1e6*p.Cached*multiplier, source
}

// Estimate returns the estimated USD cost for a request at the current time.
func Estimate(model string, inputTokens, outputTokens, cachedTokens int) float64 {
	return EstimateAt(model, inputTokens, outputTokens, cachedTokens, time.Now().UTC())
}

// EstimateAt prices a request at a given instant. DeepSeek bills peak hours at
// double the off-peak rate; peak is 01:00-04:00 and 06:00-10:00 UTC, Monday to
// Friday. Chinese public holidays are also off-peak and are NOT modelled here,
// so a holiday call is over-estimated (never under-estimated) during those
// windows.
func EstimateAt(model string, inputTokens, outputTokens, cachedTokens int, at time.Time) float64 {
	p := Get(model)
	multiplier := 1.0
	if isDeepSeekPeak(at) && isDeepSeek(model) {
		multiplier = 2.0
	}
	price := Price{Input: p.Input * multiplier, Output: p.Output * multiplier, Cached: p.Cached * multiplier}
	return float64(inputTokens)/1e6*price.Input +
		float64(outputTokens)/1e6*price.Output +
		float64(cachedTokens)/1e6*price.Cached
}

func isDeepSeek(model string) bool {
	return strings.HasPrefix(model, "deepseek-")
}

// isDeepSeekPeak reports whether t falls in a DeepSeek peak window (UTC).
func isDeepSeekPeak(t time.Time) bool {
	t = t.UTC()
	switch t.Weekday() {
	case time.Saturday, time.Sunday:
		return false
	}
	h := t.Hour()
	return (h >= 1 && h < 4) || (h >= 6 && h < 10)
}
