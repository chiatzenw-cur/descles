package policy_test

import (
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/policy"
)

// HasToolRules gates whether a stream is buffered for enforcement. It must see
// every place a decision can come from — a rule configured only on a group was
// invisible here, so those streams skipped enforcement entirely.
func TestHasToolRulesSeesEveryLayer(t *testing.T) {
	cases := map[string]struct {
		raw  string
		want bool
	}{
		"empty":             {`{}`, false},
		"defaults tools":    {`{"defaults":{"tools":{"Bash":"deny"}}}`, true},
		"defaults approval": {`{"defaults":{"require_approval":["Bash"]}}`, true},
		"agent tools":       {`{"agents":{"agent1":{"tools":{"Bash":"deny"}}}}`, true},
		"group tools":       {`{"groups":{"team-a":{"tools":{"Bash":"deny"}}}}`, true},
		"group approval":    {`{"groups":{"team-a":{"require_approval":["Bash"]}}}`, true},
		"arg tools":         {`{"agents":{"agent1":{"arg_tools":[{"tool":"Bash","arg":"command","pattern":"rm -rf*","decision":"deny"}]}}}`, true},
		"budget only":       {`{"agents":{"agent1":{"budget":{"daily_usd":5}}}}`, false},
	}
	for name, tc := range cases {
		pol, err := policy.FromJSON(tc.raw)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if got := pol.HasToolRules(); got != tc.want {
			t.Fatalf("%s: HasToolRules() = %v, want %v", name, got, tc.want)
		}
	}
}
