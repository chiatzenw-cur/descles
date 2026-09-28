package edge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// AdminIdentity is attached to every authenticated console request. The
// bootstrap token remains an owner recovery credential; named tokens identify
// the person operating the console without putting credentials in audit data.
type AdminIdentity struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Role    string   `json:"role"`
	TeamIDs []string `json:"team_ids,omitempty"`
	Shared  bool     `json:"shared,omitempty"`
}

func (id AdminIdentity) Scoped() bool { return id.Role == "team_admin" || id.Role == "team_viewer" }
func (id AdminIdentity) AllowsTeam(team string) bool {
	if !id.Scoped() {
		return true
	}
	if team == "" {
		return false
	}
	for _, allowed := range id.TeamIDs {
		if allowed == team {
			return true
		}
	}
	return false
}
func (id AdminIdentity) ReadOnly() bool { return id.Role == "viewer" || id.Role == "team_viewer" }

type adminIdentityKey struct{}

func AdminFromContext(ctx context.Context) (AdminIdentity, bool) {
	id, ok := ctx.Value(adminIdentityKey{}).(AdminIdentity)
	return id, ok
}

type adminGrant struct {
	AdminIdentity
	KeySHA256 string `json:"key_sha256"`
}

type AdminAccess struct {
	mu     sync.RWMutex
	path   string
	grants []adminGrant
}

var adminID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func OpenAdminAccess(path string) (*AdminAccess, error) {
	a := &AdminAccess{path: path, grants: []adminGrant{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &a.grants); err != nil {
		return nil, fmt.Errorf("console users: %w", err)
	}
	seen := map[string]bool{}
	seenHash := map[string]bool{}
	for _, g := range a.grants {
		b, err := hex.DecodeString(g.KeySHA256)
		if !adminID.MatchString(g.ID) || strings.EqualFold(g.ID, "owner") || strings.TrimSpace(g.Name) == "" || !validAdminScope(g.Role, g.TeamIDs) || err != nil || len(b) != sha256.Size || seen[g.ID] || seenHash[g.KeySHA256] {
			return nil, errors.New("console users: invalid saved user")
		}
		seen[g.ID] = true
		seenHash[g.KeySHA256] = true
	}
	return a, nil
}

func (a *AdminAccess) List() []AdminIdentity {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := []AdminIdentity{{ID: "owner", Name: "Bootstrap owner token", Role: "owner", Shared: true}}
	for _, g := range a.grants {
		out = append(out, g.AdminIdentity)
	}
	sort.Slice(out[1:], func(i, j int) bool { return out[i+1].ID < out[j+1].ID })
	return out
}

func (a *AdminAccess) Resolve(token string) (AdminIdentity, bool) {
	sum := sha256.Sum256([]byte(token))
	return a.ResolveDigest(hex.EncodeToString(sum[:]))
}

// ResolveDigest keeps a browser session tied to the exact named grant that
// signed in. Revoking and reissuing the same user ID cannot revive old cookies.
func (a *AdminAccess) ResolveDigest(digest string) (AdminIdentity, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, g := range a.grants {
		if g.KeySHA256 == digest {
			return g.AdminIdentity, true
		}
	}
	return AdminIdentity{}, false
}

func (a *AdminAccess) save(grants []adminGrant) error {
	raw, err := json.MarshalIndent(grants, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0700); err != nil {
		return err
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, a.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	a.grants = grants
	return nil
}

func validAdminScope(role string, teams []string) bool {
	switch role {
	case "admin", "viewer":
		return len(teams) == 0
	case "team_admin", "team_viewer":
		if len(teams) == 0 {
			return false
		}
		seen := map[string]bool{}
		for _, team := range teams {
			if !adminID.MatchString(team) || seen[team] {
				return false
			}
			seen[team] = true
		}
		return true
	}
	return false
}

func (a *AdminAccess) Issue(id, name, role string) (string, error) {
	return a.IssueScoped(id, name, role, nil)
}

func (a *AdminAccess) IssueScoped(id, name, role string, teams []string) (string, error) {
	id, name = strings.TrimSpace(id), strings.TrimSpace(name)
	if !adminID.MatchString(id) || strings.EqualFold(id, "owner") || name == "" || len(name) > 120 || !validAdminScope(role, teams) {
		return "", errors.New("enter a unique user ID, name, valid role and team scope")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, g := range a.grants {
		if g.ID == id {
			return "", errors.New("user already exists; revoke the old token first")
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := "ak_" + hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	next := append(append([]adminGrant(nil), a.grants...), adminGrant{AdminIdentity: AdminIdentity{ID: id, Name: name, Role: role, TeamIDs: append([]string(nil), teams...)}, KeySHA256: hex.EncodeToString(sum[:])})
	if err := a.save(next); err != nil {
		return "", err
	}
	return token, nil
}

func (a *AdminAccess) Revoke(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	next := make([]adminGrant, 0, len(a.grants))
	for _, g := range a.grants {
		if g.ID != id {
			next = append(next, g)
		}
	}
	if len(next) == len(a.grants) {
		return os.ErrNotExist
	}
	return a.save(next)
}

func (a *ApprovalAdmin) me(w http.ResponseWriter, r *http.Request) {
	id, _ := AdminFromContext(r.Context())
	writeJSONBody(w, id)
}

func (a *ApprovalAdmin) operators(w http.ResponseWriter, r *http.Request) {
	if id, _ := AdminFromContext(r.Context()); id.Scoped() {
		http.Error(w, "edge-wide users unavailable to team scope", http.StatusForbidden)
		return
	}
	if a.Access == nil {
		writeJSONBody(w, map[string]any{"users": []AdminIdentity{{ID: "owner", Name: "Bootstrap owner token", Role: "owner", Shared: true}}})
		return
	}
	writeJSONBody(w, map[string]any{"users": a.Access.List()})
}

func (a *ApprovalAdmin) issueOperator(w http.ResponseWriter, r *http.Request) {
	if id, _ := AdminFromContext(r.Context()); id.Role != "owner" {
		http.Error(w, "owner token required", http.StatusForbidden)
		return
	}
	var in struct {
		ID, Name, Role string
		TeamIDs        []string `json:"team_ids"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		http.Error(w, "invalid user", http.StatusBadRequest)
		return
	}
	if len(in.TeamIDs) > 0 {
		check, ok := a.LocalManagement.(interface{ HasTeam(string) bool })
		if !ok {
			http.Error(w, "team scope unavailable on this edge", http.StatusBadRequest)
			return
		}
		for _, team := range in.TeamIDs {
			if !check.HasTeam(team) {
				http.Error(w, "team not found", http.StatusBadRequest)
				return
			}
		}
	}
	key, err := a.Access.IssueScoped(in.ID, in.Name, in.Role, in.TeamIDs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONBody(w, map[string]any{"id": in.ID, "token": key})
}

func (a *ApprovalAdmin) revokeOperator(w http.ResponseWriter, r *http.Request) {
	if id, _ := AdminFromContext(r.Context()); id.Role != "owner" {
		http.Error(w, "owner token required", http.StatusForbidden)
		return
	}
	if err := a.Access.Revoke(r.PathValue("id")); err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	writeJSONBody(w, map[string]any{"removed": r.PathValue("id")})
}
