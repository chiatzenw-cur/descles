package edge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/policy"
)

func TestShippedExampleMCPConfigParses(t *testing.T) {
	raw, err := os.ReadFile("../../examples/edge-mcp.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Point token files at a temp file so only the shape is under test.
	dir := t.TempDir()
	tok := filepath.Join(dir, "tok")
	if err := os.WriteFile(tok, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	text := strings.NewReplacer("/config/secrets/stripe-token", filepath.ToSlash(tok), "/config/secrets/github-token", filepath.ToSlash(tok)).Replace(string(raw))
	file := filepath.Join(dir, "mcp.yaml")
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadMCPConfig(file)
	if err != nil || len(cfg.Connectors) != 3 || len(cfg.Clearances.Groups) != 2 {
		t.Fatalf("%+v %v", cfg, err)
	}
}

func TestShippedExamplePolicyGovernsLocalTools(t *testing.T) {
	pol, err := policy.LoadFile("../../examples/edge-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	g := &MCPGateway{Policy: policy.NewHolder(pol)}
	for tool, want := range map[string]policy.Decision{
		"Bash:git status":               policy.Allow,
		"Bash:cd x && rm -rf build":     policy.Deny,
		"Read:/repo/.env":               policy.Deny,
		"Edit:/repo/main.go":            policy.RequireApproval,
		"Bash:kubectl delete ns prod-1": policy.Deny,
	} {
		name, arg, _ := strings.Cut(tool, ":")
		input := map[string]any{"command": arg}
		if name != "Bash" {
			input = map[string]any{"file_path": arg}
		}
		norm, args := NormalizeTool(name, input)
		if got := g.decideLocal("agent", norm, args); got != want {
			t.Errorf("%s: got %s want %s", tool, got, want)
		}
	}
}
