package proxy

import (
	"context"
	"github.com/chiatzenw-cur/descles/pkg/identity"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/storage"
	"testing"
)

func TestZeroBudgetStopsFirstRequest(t *testing.T) {
	for _, raw := range []string{`{"users":{"alice":{"budget":{"daily_usd":0}}}}`, `{"agents":{"worker":{"budget":{"daily_usd":0}}}}`} {
		p, err := policy.FromJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		h := &Handler{Policy: policy.NewHolder(p), Store: storage.NewMemory()}
		denied, err := h.budgetGate(context.Background(), requestMeta{identity: identity.Identity{UserID: "alice", AgentID: "worker"}})
		if err != nil || !denied {
			t.Fatal("zero budget allowed a first request", err)
		}
	}
}
