package edge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// LocalKeyGrant binds a customer-issued virtual key to an agent. Only the SHA-256
// digest is stored in the local file; the plaintext key stays with the agent.
type LocalKeyGrant struct {
	KeySHA256 string `json:"key_sha256"`
	OrgID     string `json:"org_id"`
	AgentID   string `json:"agent_id"`
	UserID    string `json:"user_id,omitempty"`
}

type Keyring struct{ byHash map[string]LocalKeyGrant }

func (k *Keyring) OrgID() (string, error) {
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
	grant, ok := k.byHash[hex.EncodeToString(digest[:])]
	if !ok {
		return "", "", "", false
	}
	return grant.OrgID, grant.UserID, grant.AgentID, true
}
