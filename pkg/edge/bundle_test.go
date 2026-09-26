package edge

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/policy"
)

func TestSignedBundlePinsPolicyAndGrants(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := "dsk_remote_agent"
	hash := sha256.Sum256([]byte(key))
	now := time.Now().UTC()
	payload := BundlePayload{Version: 1, OrgID: "org_1", Policy: json.RawMessage(`{"defaults":{"tools":{"shell.rm":"deny"}}}`),
		Grants:   []Grant{{KeySHA256: hex.EncodeToString(hash[:]), AgentID: "agent_1", Permission: "github.*", Resource: "repo/acme", AllowedProviders: []string{"openai"}, ExpiresAt: now.Add(5 * time.Minute)}},
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	signed, err := SignBundle(payload, private)
	if err != nil {
		t.Fatal(err)
	}
	state := NewBundleState("org_1", public, filepath.Join(t.TempDir(), "bundle.json"))
	if err := state.Apply(signed); err != nil {
		t.Fatal(err)
	}
	if err := state.Apply(signed); err != nil {
		t.Fatalf("bundle refresh cannot replace cache: %v", err)
	}
	if org, _, agent, ok := state.Resolve(key); !ok || org != "org_1" || agent != "agent_1" {
		t.Fatalf("wrong grant: %q %q %t", org, agent, ok)
	}
	if !state.ToolAllowed("agent_1", "github.read", map[string]any{"repo": "repo/acme"}) {
		t.Fatal("scoped read denied")
	}
	if state.ToolAllowed("agent_1", "github.read", map[string]any{"repo": "repo/other"}) || state.ToolAllowed("agent_1", "shell.rm", nil) {
		t.Fatal("delegation ceiling bypassed")
	}
	if !state.ProviderAllowed("agent_1", "openai") || state.ProviderAllowed("agent_1", "anthropic") {
		t.Fatal("provider grant bypassed")
	}
	if got := state.Policy.Get().ToolDecision("agent_1", "shell.rm"); got != policy.Deny {
		t.Fatalf("policy = %s", got)
	}
	reloaded := NewBundleState("org_1", public, state.CachePath)
	if err := reloaded.LoadCache(); err != nil || !reloaded.Valid() {
		t.Fatalf("cached bundle unusable: %v", err)
	}
	tampered := signed
	tampered.Payload.Policy = json.RawMessage(`{"defaults":{}}`)
	if err := state.Apply(tampered); err == nil {
		t.Fatal("unsigned policy change accepted")
	}
	if err := VerifyBundle(signed, public, "other-org", now); err == nil {
		t.Fatal("cross-org bundle accepted")
	}
}

// The control plane can tighten the edge's local policy but never loosen it,
// on every refresh.
func TestBundlePolicyIsBoundedByTheLocalFloor(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := policy.FromJSON(`{"defaults":{"tools":{"github.delete_repository":"deny"},"require_approval":["stripe.refund"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	state := NewBundleState("org_1", public, filepath.Join(t.TempDir(), "bundle.json"))
	state.Floor = floor
	for _, raw := range []string{
		`{"defaults":{"tools":{"github.delete_repository":"allow","stripe.refund":"allow"}}}`,
		`{"agents":{"bot":{"tools":{"github.delete_repository":"allow"}}},"defaults":{"tools":{"crm.export":"deny"}}}`,
	} {
		now := time.Now().UTC()
		signed, err := SignBundle(BundlePayload{Version: 1, OrgID: "org_1", Policy: json.RawMessage(raw), IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute)}, private)
		if err != nil {
			t.Fatal(err)
		}
		if err := state.Apply(signed); err != nil {
			t.Fatal(err)
		}
		p := state.Policy.Get()
		if d := p.ToolDecisionInArgs("bot", "", "github.delete_repository", nil); d != policy.Deny {
			t.Errorf("bundle %s loosened the floor: delete_repository is %s", raw, d)
		}
		if d := p.ToolDecisionInArgs("a", "", "stripe.refund", nil); d != policy.RequireApproval {
			t.Errorf("bundle %s loosened the floor: refund is %s", raw, d)
		}
	}
	if d := state.Policy.Get().ToolDecisionInArgs("a", "", "crm.export", nil); d != policy.Deny {
		t.Errorf("the bundle's own tightening was lost: %s", d)
	}
}
