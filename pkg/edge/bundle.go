package edge

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/policy"
)

const bundleDomain = "descles-edge-bundle-v1\x00"

type Grant struct {
	KeySHA256        string    `json:"key_sha256"`
	AgentID          string    `json:"agent_id"`
	UserID           string    `json:"user_id,omitempty"`
	GroupName        string    `json:"group_name,omitempty"`
	Permission       string    `json:"permission"`
	Resource         string    `json:"resource"`
	DailyBudgetCents int64     `json:"daily_budget_cents,omitempty"`
	AllowedProviders []string  `json:"allowed_providers,omitempty"`
	ContextLabels    []string  `json:"context_labels,omitempty"` // organization-context clearances
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
}

type BundlePayload struct {
	Version   int             `json:"version"`
	OrgID     string          `json:"org_id"`
	Policy    json.RawMessage `json:"policy"`
	Grants    []Grant         `json:"grants"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

type SignedBundle struct {
	Payload   BundlePayload `json:"payload"`
	Signature string        `json:"signature"`
}

func SignBundle(payload BundlePayload, private ed25519.PrivateKey) (SignedBundle, error) {
	message, err := json.Marshal(payload)
	if err != nil {
		return SignedBundle{}, err
	}
	return SignedBundle{Payload: payload, Signature: hex.EncodeToString(ed25519.Sign(private, append([]byte(bundleDomain), message...)))}, nil
}

// MaxBundleLease is the longest validity an edge accepts for a bundle: the
// longest a disconnected edge keeps honouring grants revoked after its last
// refresh. The control plane must not issue longer leases.
const MaxBundleLease = 20 * time.Minute

func VerifyBundle(bundle SignedBundle, public ed25519.PublicKey, orgID string, now time.Time) error {
	if bundle.Payload.Version != 1 || bundle.Payload.OrgID != orgID || bundle.Payload.IssuedAt.After(now.Add(5*time.Minute)) || !now.Before(bundle.Payload.ExpiresAt) || bundle.Payload.ExpiresAt.After(bundle.Payload.IssuedAt.Add(MaxBundleLease)) {
		return fmt.Errorf("edge bundle version, organization or validity window is invalid")
	}
	signature, err := hex.DecodeString(bundle.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("edge bundle signature is invalid")
	}
	message, err := json.Marshal(bundle.Payload)
	if err != nil {
		return err
	}
	if !ed25519.Verify(public, append([]byte(bundleDomain), message...), signature) {
		return fmt.Errorf("edge bundle signature verification failed")
	}
	if len(bundle.Payload.Policy) == 0 {
		return fmt.Errorf("edge bundle has no policy")
	}
	if _, err := policy.FromJSON(string(bundle.Payload.Policy)); err != nil {
		return fmt.Errorf("edge bundle policy: %w", err)
	}
	for _, grant := range bundle.Payload.Grants {
		decoded, err := hex.DecodeString(grant.KeySHA256)
		if err != nil || len(decoded) != sha256.Size || grant.AgentID == "" || grant.Permission == "" || grant.Resource == "" {
			return fmt.Errorf("edge bundle has an invalid grant")
		}
	}
	return nil
}

// BundleState atomically swaps validated remote grants and policy. Requests
// stop when its lease expires, including during a hosted control-plane outage.
type BundleState struct {
	mu        sync.RWMutex
	OrgID     string
	PublicKey ed25519.PublicKey
	CachePath string
	Policy    *policy.Holder
	// Floor is the edge administrator's local policy. Every bundle's policy
	// is bounded by it: the control plane can tighten it but never loosen it.
	Floor   *policy.Policy
	current SignedBundle
	byHash  map[string]Grant
	byAgent map[string]Grant
}

func NewBundleState(orgID string, public ed25519.PublicKey, cachePath string) *BundleState {
	return &BundleState{OrgID: orgID, PublicKey: public, CachePath: cachePath, Policy: policy.NewHolder(policy.AllowAll())}
}

func (s *BundleState) Apply(bundle SignedBundle) error {
	if err := VerifyBundle(bundle, s.PublicKey, s.OrgID, time.Now().UTC()); err != nil {
		return err
	}
	compiled, _ := policy.FromJSON(string(bundle.Payload.Policy))
	byHash := make(map[string]Grant, len(bundle.Payload.Grants))
	byAgent := make(map[string]Grant, len(bundle.Payload.Grants))
	for _, grant := range bundle.Payload.Grants {
		byHash[grant.KeySHA256] = grant
		byAgent[grant.AgentID] = grant
	}
	if s.CachePath != "" {
		data, err := json.Marshal(bundle)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(s.CachePath), 0700); err != nil {
			return err
		}
		temp := s.CachePath + ".tmp"
		if err := os.WriteFile(temp, data, 0600); err != nil {
			return err
		}
		if err := os.Rename(temp, s.CachePath); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.current, s.byHash, s.byAgent = bundle, byHash, byAgent
	s.Policy.Set(compiled.WithFloor(s.Floor))
	s.mu.Unlock()
	return nil
}

func (s *BundleState) LoadCache() error {
	data, err := os.ReadFile(s.CachePath)
	if err != nil {
		return err
	}
	var bundle SignedBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return err
	}
	// The same verification path is used for online and cached bundles.
	return s.Apply(bundle)
}

func (s *BundleState) Valid() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.current.Payload.ExpiresAt.IsZero() && time.Now().Before(s.current.Payload.ExpiresAt)
}

func (s *BundleState) Resolve(plaintext string) (orgID, userID, agentID string, ok bool) {
	if plaintext == "" {
		return "", "", "", false
	}
	digest := sha256.Sum256([]byte(plaintext))
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !time.Now().Before(s.current.Payload.ExpiresAt) {
		return "", "", "", false
	}
	grant, ok := s.byHash[hex.EncodeToString(digest[:])]
	if !ok || (!grant.ExpiresAt.IsZero() && !time.Now().Before(grant.ExpiresAt)) {
		return "", "", "", false
	}
	return s.OrgID, grant.UserID, grant.AgentID, true
}

func (s *BundleState) AgentGrant(agentID string) (Grant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !time.Now().Before(s.current.Payload.ExpiresAt) {
		return Grant{}, false
	}
	grant, ok := s.byAgent[agentID]
	return grant, ok && (grant.ExpiresAt.IsZero() || time.Now().Before(grant.ExpiresAt))
}
