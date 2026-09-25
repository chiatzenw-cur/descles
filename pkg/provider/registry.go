package provider

import "strings"

// Config declares one upstream provider (M2 multi-provider routing).
// Providers are OpenAI-compatible, so "multi-provider" is mostly a matter of
// pointing each name at a different base_url + api_key and declaring which
// models it serves; the gateway then routes a request by the requested model.
type Config struct {
	// Name is the human label recorded on spans (e.g. "deepseek"). When empty,
	// a name is derived from the base URL host.
	Name string `json:"name"`
	// BaseURL is the OpenAI-compatible root, e.g. "https://api.deepseek.com/v1".
	BaseURL string `json:"base_url"`
	// APIKey is the provider credential, kept separate from the client key.
	APIKey string `json:"api_key"`
	// Models lists the models this provider serves. Patterns support a
	// trailing/leading '*' wildcard (e.g. "gpt-*"). Empty means "catch-all /
	// default". A default (catch-all) provider should be listed LAST.
	Models []string `json:"models"`
}

// Provider is a resolved upstream plus its routing metadata.
type Provider struct {
	Name     string
	Models   []string
	Upstream *Upstream
}

// Registry routes requests to one of several providers by model.
type Registry struct {
	providers []Provider
}

// NewRegistry builds a registry from provider configs.
func NewRegistry(cfgs []Config) *Registry {
	out := make([]Provider, 0, len(cfgs))
	for _, c := range cfgs {
		name := c.Name
		if name == "" {
			name = ProviderName(c.BaseURL)
		}
		out = append(out, Provider{
			Name:     name,
			Models:   c.Models,
			Upstream: &Upstream{BaseURL: strings.TrimRight(c.BaseURL, "/"), APIKey: c.APIKey},
		})
	}
	return &Registry{providers: out}
}

// Resolve returns the provider that serves a model. A provider with a matching
// model pattern wins; otherwise the default (a provider with no model list) is
// used; else the first provider.
func (r *Registry) Resolve(model string) Provider {
	if provider, ok := r.ResolveMatch(model); ok {
		return provider
	}
	if len(r.providers) == 0 {
		return Provider{}
	}
	return r.providers[0]
}

// ResolveMatch returns only an explicit model match or a configured catch-all.
// Gateways should use this strict form so unknown models are never sent to an
// arbitrary first provider.
func (r *Registry) ResolveMatch(model string) (Provider, bool) {
	if len(r.providers) == 0 || model == "" {
		return Provider{}, false
	}
	var def *Provider
	for i := range r.providers {
		p := &r.providers[i]
		if len(p.Models) == 0 {
			def = p
			continue
		}
		if matchesModel(p.Models, model) {
			return *p, true
		}
	}
	if def != nil {
		return *def, true
	}
	return Provider{}, false
}

// Default returns the default (first real / catch-all) provider version.
func (r *Registry) Default() Provider {
	if len(r.providers) == 0 {
		return Provider{}
	}
	return r.providers[0]
}

// ByName selects a provider for endpoints, such as /models, that carry no
// model in their request body.
func (r *Registry) ByName(name string) (Provider, bool) {
	for _, provider := range r.providers {
		if provider.Name == name {
			return provider, true
		}
	}
	return Provider{}, false
}

func matchesModel(patterns []string, model string) bool {
	if model == "" {
		return false
	}
	for _, pat := range patterns {
		if matchModel(pat, model) {
			return true
		}
	}
	return false
}

func matchModel(pattern, model string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(model, strings.TrimSuffix(pattern, "*"))
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(model, strings.TrimPrefix(pattern, "*"))
	}
	return pattern == model
}
