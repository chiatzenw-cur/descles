package proxy

import (
	"context"
	"testing"

	"github.com/chiatzenw-cur/descles/pkg/identity"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/storage"
)

// TestTokenOnlyBudgetSkipsUSDZeroBlock guards the token-only semantics: a
// budget carrying daily_tokens only must not be read as the legacy "USD 0 =
// block" — a token cap stands alone without tripping the USD gate.
func TestTokenOnlyBudgetSkipsUSDZeroBlock(t *testing.T) {
	p, err := policy.FromJSON(`{"agents":{"worker":{"budget":{"daily_tokens":100}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Policy: policy.NewHolder(p), Store: storage.NewMemory()}
	denied, err := h.budgetGate(context.Background(), requestMeta{identity: identity.Identity{UserID: "alice", AgentID: "worker"}})
	if err != nil || denied {
		t.Fatal("token-only budget must not zero-block", denied, err)
	}
}
