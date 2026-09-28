package edge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// LocalKeyGrant binds a customer-issued virtual key to an agent. Only the SHA-256
// digest is stored in the local file; the plaintext key stays with the agent.
type LocalKeyGrant struct {
	KeySHA256 string `json:"key_sha256"`
	OrgID     string `json:"org_id"`
	AgentID   string `json:"agent_id"`
	UserID    string `json:"user_id,omitempty"`
	GroupID   string `json:"group_id,omitempty"`
}

type Keyring struct {
	mu     sync.RWMutex
	byHash map[string]LocalKeyGrant
	path   string // writable state; the initial config/keys.json remains read-only
}

func (k *Keyring) OrgID() (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	var org string
	for _, grant := range k.byHash {
		if org == "" {
			org = grant.OrgID
		}
		if grant.OrgID != org {
			return "", fmt.Errorf("edge key file must contain one organization")
		}
	}
	return org, nil
}

func LoadKeyring(path string) (*Keyring, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var grants []LocalKeyGrant
	if err := json.Unmarshal(raw, &grants); err != nil {
		return nil, fmt.Errorf("edge key file: %w", err)
	}
	if len(grants) == 0 {
		return nil, fmt.Errorf("edge key file contains no grants")
	}
	ring := &Keyring{byHash: make(map[string]LocalKeyGrant, len(grants))}
	for _, grant := range grants {
		grant.KeySHA256 = strings.ToLower(strings.TrimSpace(grant.KeySHA256))
		decoded, err := hex.DecodeString(grant.KeySHA256)
		if err != nil || len(decoded) != sha256.Size || grant.OrgID == "" || grant.AgentID == "" {
			return nil, fmt.Errorf("edge key file has an invalid grant")
		}
		if _, exists := ring.byHash[grant.KeySHA256]; exists {
			return nil, fmt.Errorf("duplicate edge key hash")
		}
		ring.byHash[grant.KeySHA256] = grant
	}
	return ring, nil
}

func (k *Keyring) Resolve(plaintext string) (orgID, userID, agentID string, ok bool) {
	if k == nil || plaintext == "" {
		return "", "", "", false
	}
	digest := sha256.Sum256([]byte(plaintext))
	k.mu.RLock()
	grant, ok := k.byHash[hex.EncodeToString(digest[:])]
	k.mu.RUnlock()
	if !ok {
		return "", "", "", false
	}
	return grant.OrgID, grant.UserID, grant.AgentID, true
}

// LoadWritableKeyring uses the seed key file until the first console change,
// then loads durable grants from the edge's writable data volume.
func LoadWritableKeyring(seed, state string) (*Keyring, error) {
	path := seed
	if _, err := os.Stat(state); err == nil {
		path = state
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	k, err := LoadKeyring(path)
	if err != nil {
		return nil, err
	}
	k.path = state
	return k, nil
}

// Agents lists identities, never hashes. Several keys for one agent collapse
// into one row; rotation and revocation operate on the entire identity.
func (k *Keyring) Agents() []LocalKeyGrant {
	k.mu.RLock()
	defer k.mu.RUnlock()
	byID := map[string]LocalKeyGrant{}
	for _, g := range k.byHash {
		g.KeySHA256 = ""
		byID[g.AgentID] = g
	}
	out := make([]LocalKeyGrant, 0, len(byID))
	for _, g := range byID {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out
}

func (k *Keyring) GroupOf(agentID string) string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, g := range k.byHash {
		if g.AgentID == agentID {
			return g.GroupID
		}
	}
	return ""
}

var localID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// Issue creates or rotates an agent key. The plaintext is returned once and
// never persisted. Replacing the state file happens before the live swap.
func (k *Keyring) Issue(agentID, userID, groupID string) (string, error) {
	if !localID.MatchString(agentID) || (groupID != "" && !localID.MatchString(groupID)) || len(userID) > 120 {
		return "", fmt.Errorf("invalid agent, user or team identifier")
	}
	if k.path == "" {
		return "", fmt.Errorf("keyring is read-only")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	plaintext := "vk_" + hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(plaintext))
	k.mu.Lock()
	defer k.mu.Unlock()
	var org string
	for _, g := range k.byHash {
		org = g.OrgID
		break
	}
	if org == "" {
		return "", fmt.Errorf("keyring has no organization")
	}
	next := make(map[string]LocalKeyGrant, len(k.byHash)+1)
	for hash, g := range k.byHash {
		if g.AgentID != agentID {
			next[hash] = g
		}
	}
	next[hex.EncodeToString(sum[:])] = LocalKeyGrant{KeySHA256: hex.EncodeToString(sum[:]), OrgID: org, AgentID: agentID, UserID: strings.TrimSpace(userID), GroupID: groupID}
	if err := k.persist(next); err != nil {
		return "", err
	}
	k.byHash = next
	return plaintext, nil
}

func (k *Keyring) Revoke(agentID string) error {
	if !localID.MatchString(agentID) || k.path == "" {
		return fmt.Errorf("invalid agent identifier")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	next := make(map[string]LocalKeyGrant, len(k.byHash))
	for hash, g := range k.byHash {
		if g.AgentID != agentID {
			next[hash] = g
		}
	}
	if len(next) == len(k.byHash) {
		return fmt.Errorf("agent not found")
	}
	if len(next) == 0 {
		return fmt.Errorf("cannot revoke the last agent key")
	}
	if err := k.persist(next); err != nil {
		return err
	}
	k.byHash = next
	return nil
}

func (k *Keyring) persist(next map[string]LocalKeyGrant) error {
	grants := make([]LocalKeyGrant, 0, len(next))
	for _, g := range next {
		grants = append(grants, g)
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].AgentID < grants[j].AgentID })
	raw, err := json.MarshalIndent(grants, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return err
	}
	tmp := k.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, k.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
