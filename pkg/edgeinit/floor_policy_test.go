package edgeinit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/policy"
)

// In managed mode the generated policy is a floor under the control plane's,
// so it keeps its denies but no budget that would silently cap every agent.
func TestManagedPolicyFileIsAFloorWithoutABudget(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "edge")
	if _, err := Generate(Options{Dir: dir, Mode: "hosted", HostedURL: "https://cp.example", OrgID: "org_1",
		BundleKey: strings.Repeat("ab", 32), Providers: []string{"anthropic"}, UID: -1, GID: -1}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "can only make it stricter") {
		t.Errorf("managed policy does not explain the floor:\n%s", text)
	}
	p, err := policy.Load(text)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.BudgetFor("any-agent"); ok {
		t.Error("managed policy caps every agent's budget")
	}
	if d := p.ToolDecisionInArgs("a", "", "local.bash", map[string]any{"command": "rm -rf /"}); d != policy.Deny {
		t.Errorf("managed policy lost its denies: rm -rf is %s", d)
	}
}
