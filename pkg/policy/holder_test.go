package policy

import "testing"

// TestHolderSwap proves a hot reload swaps the effective policy atomically.
func TestHolderSwap(t *testing.T) {
	deny, _ := FromJSON(`{"defaults":{"tools":{"shell.rm":"deny"}}}`)
	allow, _ := FromJSON(`{"defaults":{"tools":{"shell.rm":"allow"}}}`)

	h := NewHolder(deny)
	if got := h.Get().ToolDecision("ops-agent", "shell.rm"); got != Deny {
		t.Fatalf("initial policy: %s, want deny", got)
	}

	h.Set(allow)
	if got := h.Get().ToolDecision("ops-agent", "shell.rm"); got != Allow {
		t.Fatalf("after swap: %s, want allow", got)
	}
}

// TestHolderNewNil stores an allow-all placeholder when given nil.
func TestHolderNewNil(t *testing.T) {
	h := NewHolder(nil)
	if h.Get() == nil {
		t.Fatal("NewHolder(nil) should not store a nil policy")
	}
}
