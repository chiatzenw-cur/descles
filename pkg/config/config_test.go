package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestProviderConfigurationFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"invalid json", `{`, "invalid JSON"},
		{"empty list", `[]`, "at least one"},
		{"relative url", `[{"name":"x","base_url":"api.example.com"}]`, "absolute http"},
		{"url credential", `[{"name":"x","base_url":"https://user:secret@api.example.com/v1"}]`, "absolute http"},
		{"duplicate name", `[{"name":"x","base_url":"https://a.example/v1"},{"name":"x","base_url":"https://b.example/v1","models":["b"]}]`, "duplicate"},
		{"two catch alls", `[{"name":"a","base_url":"https://a.example/v1"},{"name":"b","base_url":"https://b.example/v1"}]`, "catch-all"},
		{"unsupported wildcard", `[{"name":"a","base_url":"https://a.example/v1","models":["gpt-*-mini"]}]`, "invalid model pattern"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("DESCLES_PROVIDERS", test.raw)
			t.Setenv("DESCLES_MASTER_KEY", "")
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestDefaultProviderURLAlsoFailsClosed(t *testing.T) {
	t.Setenv("DESCLES_PROVIDERS", "")
	t.Setenv("DESCLES_UPSTREAM_BASE_URL", "not-a-url")
	t.Setenv("DESCLES_MASTER_KEY", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "base_url") {
		t.Fatalf("Load error = %v", err)
	}
}

func TestValidBYOKProviderConfiguration(t *testing.T) {
	t.Setenv("DESCLES_PROVIDERS", `[{"name":"openai","base_url":"https://api.openai.com/v1/","models":["gpt-*"]},{"name":"other","base_url":"https://models.example/v1"}]`)
	t.Setenv("DESCLES_MASTER_KEY", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Providers) != 2 || cfg.Providers[0].BaseURL != "https://api.openai.com/v1" || cfg.Providers[0].APIKey != "" {
		t.Fatalf("providers = %+v", cfg.Providers)
	}
}

// The master key is what makes "keys encrypted at rest" true. It used to accept
// any value of >=16 bytes, while the sealing path (aes.NewCipher) only accepts
// 16/24/32 and otherwise stored PLAINTEXT with no warning — the console then
// reported the credential as encrypted. Enforce the lengths that work, and prove
// the accepted ones actually decode.
func TestMasterKeyLengthIsEnforced(t *testing.T) {
	providers := `[{"name":"openai","base_url":"https://api.openai.com/v1/"}]`
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"16 bytes", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), true},
		{"24 bytes", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 24)), true},
		{"32 bytes", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), true},
		{"20 bytes is not an AES key size", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 20)), false},
		{"8 bytes is too short", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 8)), false},
		{"not base64", "sk-not-base64!!", false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("DESCLES_PROVIDERS", providers)
			t.Setenv("DESCLES_MASTER_KEY", test.raw)
			cfg, err := Load()
			if test.ok {
				if err != nil {
					t.Fatalf("Load error = %v, want success", err)
				}
				if len(cfg.MasterKey) == 0 {
					t.Fatal("master key missing from the loaded config")
				}
				return
			}
			if err == nil {
				t.Fatalf("Load accepted an unusable master key (%d bytes decoded) — it would store plaintext", len(cfg.MasterKey))
			}
			if !strings.Contains(err.Error(), "DESCLES_MASTER_KEY") {
				t.Fatalf("Load error = %v, want it to name DESCLES_MASTER_KEY", err)
			}
		})
	}
}
