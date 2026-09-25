package policy

import "testing"

func TestUnifiedDecide(t *testing.T) {
	u, err := ParseUnified(`{"agents":{"coding-agent":{
		"models":{"gpt-expensive":{"allow":false},"claude-sonnet":{"allow":true}},
		"capabilities":{"github.merge":"require_approval","shell.exec":"allow"},
		"resources":{"engineering-repo":{"read":"allow","write":"allow"},"production-db":{"read":"allow","write":"deny"}}
	}}}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	cases := []struct {
		name string
		req  DecisionRequest
		want Decision
	}{
		{"allow", DecisionRequest{"coding-agent", "claude-sonnet", "shell.exec", "engineering-repo", "write"}, Allow},
		{"model denied", DecisionRequest{"coding-agent", "gpt-expensive", "shell.exec", "", ""}, Deny},
		{"capability approval", DecisionRequest{"coding-agent", "claude-sonnet", "github.merge", "", ""}, RequireApproval},
		{"resource write deny", DecisionRequest{"coding-agent", "claude-sonnet", "filesystem.write", "production-db", "write"}, Deny},
		{"resource read allow", DecisionRequest{"coding-agent", "claude-sonnet", "postgres.query", "production-db", "read"}, Allow},
		{"unknown agent defaults", DecisionRequest{"other-agent", "claude-sonnet", "shell.exec", "production-db", "write"}, Allow},
		{"deny outranks approval", DecisionRequest{"coding-agent", "gpt-expensive", "github.merge", "production-db", "write"}, Deny},
	}

	for _, c := range cases {
		if got := u.Decide(c.req); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestUnifiedParseEmptyIsAllowAll(t *testing.T) {
	u, err := ParseUnified("")
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if got := u.Decide(DecisionRequest{Agent: "x", Model: "m", Capability: "c", Resource: "r", Verb: "write"}); got != Allow {
		t.Fatalf("empty policy should allow, got %s", got)
	}
}
