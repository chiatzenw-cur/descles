package provider

import "testing"

func TestRegistryResolve(t *testing.T) {
	reg := NewRegistry([]Config{
		{Name: "deepseek", BaseURL: "https://api.deepseek.com/v1", Models: []string{"deepseek-chat", "deepseek-reasoner"}},
		{Name: "openai", BaseURL: "https://api.openai.com/v1", Models: []string{"gpt-*"}},
		{Name: "fallback", BaseURL: "https://example.com/v1"}, // catch-all last
	})

	cases := []struct{ model, name string }{
		{"deepseek-chat", "deepseek"},
		{"deepseek-reasoner", "deepseek"},
		{"gpt-4o", "openai"},
		{"gpt-4o-mini", "openai"},
		{"unknown-model", "fallback"},
	}
	for _, c := range cases {
		p := reg.Resolve(c.model)
		if p.Name != c.name {
			t.Errorf("Resolve(%q).Name = %q, want %q", c.model, p.Name, c.name)
		}
	}

	if reg.Default().Name != "deepseek" {
		t.Errorf("Default = %q, want deepseek", reg.Default().Name)
	}
}

func TestMatchModel(t *testing.T) {
	cases := []struct {
		pat, model string
		want       bool
	}{
		{"*", "gpt-4o", true},
		{"gpt-*", "gpt-4o", true},
		{"gpt-*", "claude-3", false},
		{"deepseek-chat", "deepseek-chat", true},
		{"deepseek-chat", "deepseek-reasoner", false},
		{"*-mini", "gpt-4o-mini", true},
	}
	for _, c := range cases {
		if got := matchModel(c.pat, c.model); got != c.want {
			t.Errorf("matchModel(%q, %q) = %v, want %v", c.pat, c.model, got, c.want)
		}
	}
}

func TestRegistryStrictResolutionAndNamedSelection(t *testing.T) {
	reg := NewRegistry([]Config{
		{Name: "deepseek", BaseURL: "https://api.deepseek.com/v1", Models: []string{"deepseek-*"}},
		{Name: "openai", BaseURL: "https://api.openai.com/v1", Models: []string{"gpt-*"}},
	})
	if _, ok := reg.ResolveMatch("claude-sonnet"); ok {
		t.Fatal("unknown model silently resolved")
	}
	if got, ok := reg.ResolveMatch("gpt-test"); !ok || got.Name != "openai" {
		t.Fatalf("gpt route = %+v, %v", got, ok)
	}
	if got, ok := reg.ByName("deepseek"); !ok || got.Name != "deepseek" {
		t.Fatalf("named route = %+v, %v", got, ok)
	}
	if _, ok := reg.ByName("missing"); ok {
		t.Fatal("unknown provider name resolved")
	}
}
