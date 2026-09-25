package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProviderCredentialCanLoadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider-key")
	if err := os.WriteFile(path, []byte("sk-local-only\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DESCLES_UPSTREAM_API_KEY", "")
	t.Setenv("DESCLES_UPSTREAM_API_KEY_FILE", path)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UpstreamAPIKey != "sk-local-only" || cfg.Providers[0].APIKey != "sk-local-only" {
		t.Fatal("mounted credential not used")
	}
}

func TestProviderCredentialEnvAndFileConflict(t *testing.T) {
	t.Setenv("DESCLES_UPSTREAM_API_KEY", "sk-env")
	t.Setenv("DESCLES_UPSTREAM_API_KEY_FILE", "some-file")
	if _, err := Load(); err == nil {
		t.Fatal("accepted ambiguous provider credential")
	}
}
