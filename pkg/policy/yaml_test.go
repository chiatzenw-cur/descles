package policy

import (
	"os"
	"path/filepath"
	"testing"
)

const yamlPolicy = `
defaults:
  tools:
    shell.rm: deny
agents:
  ops-agent:
    tools:
      shell.kubectl.delete: require_approval
      github.delete_repository: deny
`

// TestFromYAMLMatchesJSON proves a YAML policy produces the same decisions as
// its JSON equivalent.
func TestFromYAMLMatchesJSON(t *testing.T) {
	jsonEq := `{"defaults":{"tools":{"shell.rm":"deny"}},"agents":{"ops-agent":{"tools":{"shell.kubectl.delete":"require_approval","github.delete_repository":"deny"}}}}`

	yamlPol, err := FromYAML(yamlPolicy)
	if err != nil {
		t.Fatalf("FromYAML: %v", err)
	}
	jsonPol, err := FromJSON(jsonEq)
	if err != nil {
		t.Fatalf("FromJSON: %v", err)
	}

	cases := []struct {
		agent, tool string
		want        Decision
	}{
		{"ops-agent", "shell.rm", Deny},
		{"ops-agent", "shell.kubectl.delete", RequireApproval},
		{"ops-agent", "github.delete_repository", Deny},
		{"ops-agent", "shell.ls", Allow},
		{"nobody", "shell.rm", Deny},
	}
	for _, c := range cases {
		if got := yamlPol.ToolDecision(c.agent, c.tool); got != c.want {
			t.Errorf("yaml ToolDecision(%s,%s)=%s want %s", c.agent, c.tool, got, c.want)
		}
		if got := jsonPol.ToolDecision(c.agent, c.tool); got != c.want {
			t.Errorf("json ToolDecision(%s,%s)=%s want %s", c.agent, c.tool, got, c.want)
		}
	}
}

func TestLoadDetectsJSONAndYAML(t *testing.T) {
	jsonDoc := `{"defaults":{"tools":{"shell.rm":"deny"}}}`

	for name, doc := range map[string]string{"json": jsonDoc, "yaml": yamlPolicy} {
		p, err := Load(doc)
		if err != nil {
			t.Fatalf("Load(%s): %v", name, err)
		}
		if p.ToolDecision("ops-agent", "shell.rm") != Deny {
			t.Errorf("Load(%s): shell.rm should be denied", name)
		}
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(yamlPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if p.ToolDecision("ops-agent", "shell.kubectl.delete") != RequireApproval {
		t.Error("LoadFile: kubectl.delete should require approval")
	}

	if _, err := LoadFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("LoadFile: expected error for missing file")
	}
}

func TestLoadUnifiedYAML(t *testing.T) {
	doc := `
defaults:
  capabilities:
    shell.exec: require_approval
  resources:
    production-db:
      write: deny
agents:
  coding-agent:
    models:
      gpt-expensive:
        allow: false
`
	u, err := LoadUnified(doc)
	if err != nil {
		t.Fatalf("LoadUnified: %v", err)
	}
	if got := u.Decide(DecisionRequest{Agent: "coding-agent", Capability: "shell.exec"}); got != RequireApproval {
		t.Errorf("shell.exec decision=%s want require_approval", got)
	}
	if got := u.Decide(DecisionRequest{Agent: "coding-agent", Resource: "production-db", Verb: "write"}); got != Deny {
		t.Errorf("prod-db write decision=%s want deny", got)
	}
	if got := u.Decide(DecisionRequest{Agent: "coding-agent", Model: "gpt-expensive", Capability: "shell.exec"}); got != Deny {
		t.Errorf("expensive model decision=%s want deny", got)
	}
}
