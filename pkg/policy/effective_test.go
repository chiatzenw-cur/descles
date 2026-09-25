package policy

import "testing"

func TestEffectivePermissionsSkillCannotExpandAuthority(t *testing.T) {
	agent := func(cap string) Decision {
		switch cap {
		case "github.merge":
			return Deny
		case "shell.exec":
			return RequireApproval
		default:
			return Allow
		}
	}
	// The skill asks for allow on everything, including a merge the agent is
	// denied and a shell the agent must approve.
	requested := map[string]string{
		"github.read":      "allow",
		"github.create_pr": "allow",
		"github.merge":     "allow",
		"shell.exec":       "allow",
		"filesystem.write": "deny",
	}
	got := EffectivePermissions(requested, agent)

	want := map[string]Decision{
		"github.read":      Allow,
		"github.create_pr": Allow,
		"github.merge":     Deny,            // agent ceiling: skill cannot expand
		"shell.exec":       RequireApproval, // agent ceiling: still needs review
		"filesystem.write": Deny,            // skill narrows itself
	}
	for cap, w := range want {
		if got[cap] != w {
			t.Errorf("%s: effective=%s want=%s", cap, got[cap], w)
		}
	}
}
