package policy

import "sync/atomic"

// Holder is a concurrency-safe reference to the active policy. It lets the
// gateway swap the policy at runtime (hot reload) without restarting, while
// proxy/action read it lock-free via Get. A nil stored policy is treated by
// callers as allow-all (the same semantics as an empty document).
type Holder struct {
	p atomic.Pointer[Policy]
}

// NewHolder returns a holder storing p. A nil p stores an allow-all policy so
// Get never returns nil.
func NewHolder(p *Policy) *Holder {
	h := &Holder{}
	if p == nil {
		p = AllowAll()
	}
	h.p.Store(p)
	return h
}

// Get returns the currently active policy (never nil after NewHolder/Set).
func (h *Holder) Get() *Policy { return h.p.Load() }

// Set atomically swaps in a new policy; all subsequent Get calls observe it.
func (h *Holder) Set(p *Policy) { h.p.Store(p) }
