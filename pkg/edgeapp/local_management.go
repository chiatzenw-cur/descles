package edgeapp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/edge"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/provider"
)

// localManagement owns the standalone edge's writable configuration. The
// generated /config volume can remain read-only; changes live under /data.
type localManagement struct {
	mu           sync.Mutex
	path         string
	state        localState
	keys         *edge.Keyring
	registry     *provider.Registry
	seed         []provider.Config
	sealKey      [32]byte
	policy       *policy.Holder
	policySource string
	policyPath   string
}

type localTeam struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type localEvent struct {
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	Target string    `json:"target"`
}
type localState struct {
	Teams     []localTeam       `json:"teams"`
	Providers []provider.Config `json:"providers"`
	Events    []localEvent      `json:"events"`
}

var consoleID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func openLocalManagement(dataDir string, keys *edge.Keyring, registry *provider.Registry, seed []provider.Config, adminToken string, holder *policy.Holder, policySource string) (*localManagement, error) {
	m := &localManagement{path: filepath.Join(dataDir, "console.json"), keys: keys, registry: registry, seed: append([]provider.Config(nil), seed...), sealKey: sha256.Sum256([]byte("descles edge console providers v1:" + adminToken)), policy: holder, policySource: policySource, policyPath: filepath.Join(dataDir, "policy.yaml")}
	raw, err := os.ReadFile(m.path)
	if err == nil {
		if err := json.Unmarshal(raw, &m.state); err != nil {
			return nil, fmt.Errorf("local console state: %w", err)
		}
		for i := range m.state.Providers {
			key, err := m.unseal(m.state.Providers[i].APIKey)
			if err != nil {
				return nil, fmt.Errorf("saved provider %q: cannot decrypt key (was the edge admin token changed?): %w", m.state.Providers[i].Name, err)
			}
			m.state.Providers[i].APIKey = key
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	for _, p := range m.state.Providers {
		if err := validLocalProvider(p); err != nil {
			return nil, fmt.Errorf("saved provider %q: %w", p.Name, err)
		}
	}
	m.publishProviders()
	return m, nil
}

func (m *localManagement) publishProviders() {
	all := append([]provider.Config(nil), m.state.Providers...)
	for _, p := range m.seed {
		name := p.Name
		if name == "" {
			name = provider.ProviderName(p.BaseURL)
		}
		if !overriddenBy(m.state.Providers, name) {
			all = append(all, p)
		}
	}
	m.registry.Replace(all)
}

func overriddenBy(providers []provider.Config, name string) bool {
	for _, p := range providers {
		if p.Name == name {
			return true
		}
	}
	return false
}

func (m *localManagement) save(next localState) error {
	disk := next
	disk.Providers = append([]provider.Config(nil), next.Providers...)
	for i := range disk.Providers {
		sealed, err := m.seal(disk.Providers[i].APIKey)
		if err != nil {
			return err
		}
		disk.Providers[i].APIKey = sealed
	}
	raw, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, m.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	m.state = next
	m.publishProviders()
	return nil
}

func (m *localManagement) seal(plaintext string) (string, error) {
	block, err := aes.NewCipher(m.sealKey[:])
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return "enc:v1:" + base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plaintext), nil)), nil
}
func (m *localManagement) unseal(value string) (string, error) {
	if !strings.HasPrefix(value, "enc:v1:") {
		return "", fmt.Errorf("unsupported credential format")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "enc:v1:"))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(m.sealKey[:])
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < aead.NonceSize() {
		return "", fmt.Errorf("truncated credential")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (m *localManagement) changed(next *localState, action, target string) error {
	next.Events = append(append([]localEvent(nil), m.state.Events...), localEvent{At: time.Now().UTC(), Action: action, Target: target})
	if len(next.Events) > 1000 {
		next.Events = next.Events[len(next.Events)-1000:]
	}
	return m.save(*next)
}

func (m *localManagement) RegisterAdmin(mux *http.ServeMux, auth func(http.Handler) http.Handler) {
	for _, route := range []struct {
		pattern string
		fn      http.HandlerFunc
	}{
		{"GET /admin/providers", m.providers}, {"POST /admin/providers", m.addProvider}, {"DELETE /admin/providers/{id}", m.deleteProvider},
		{"GET /admin/teams", m.teams}, {"POST /admin/teams", m.addTeam}, {"DELETE /admin/teams/{id}", m.deleteTeam},
		{"GET /admin/agents", m.agents}, {"POST /admin/agents", m.issueAgent}, {"POST /admin/agents/{id}/rotate", m.rotateAgent}, {"DELETE /admin/agents/{id}", m.deleteAgent},
		{"GET /admin/audit", m.audit},
		{"GET /admin/policy/source", m.policyDocument}, {"PUT /admin/policy/source", m.savePolicy},
	} {
		mux.Handle(route.pattern, auth(route.fn))
	}
}

func (m *localManagement) policyDocument(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	path := m.policySource
	if _, err := os.Stat(m.policyPath); err == nil {
		path = m.policyPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		localError(w, 500, err)
		return
	}
	localJSON(w, map[string]any{"raw": string(raw), "source": path})
}
func (m *localManagement) savePolicy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Raw string `json:"raw"`
	}
	if err := decodeLocal(r, &in); err != nil {
		localError(w, 400, err)
		return
	}
	if strings.TrimSpace(in.Raw) == "" {
		localError(w, 400, fmt.Errorf("policy cannot be empty"))
		return
	}
	p, err := policy.Load(in.Raw)
	if err != nil {
		localError(w, 400, err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(m.policyPath), 0o700); err != nil {
		localError(w, 500, err)
		return
	}
	tmp := m.policyPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(in.Raw), 0o600); err != nil {
		localError(w, 500, err)
		return
	}
	if err := os.Rename(tmp, m.policyPath); err != nil {
		_ = os.Remove(tmp)
		localError(w, 500, err)
		return
	}
	m.policy.Set(p)
	next := m.state
	_ = m.changed(&next, "policy.update", "local")
	localJSON(w, map[string]any{"saved": true})
}

func decodeLocal(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 32<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
func localError(w http.ResponseWriter, status int, err error) { http.Error(w, err.Error(), status) }
func localJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func validLocalProvider(p provider.Config) error {
	if !consoleID.MatchString(p.Name) || len(p.APIKey) < 1 || len(p.APIKey) > 8192 || len(p.Models) > 100 {
		return fmt.Errorf("name, key or model list is invalid")
	}
	u, err := url.Parse(p.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("base URL must be http(s)://host[/path] without credentials or query")
	}
	if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return fmt.Errorf("provider keys require HTTPS (HTTP is accepted only on loopback)")
	}
	for _, model := range p.Models {
		if model == "" || len(model) > 120 {
			return fmt.Errorf("invalid model pattern")
		}
	}
	return nil
}

func (m *localManagement) providers(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	type row struct {
		Name    string   `json:"name"`
		BaseURL string   `json:"base_url"`
		Models  []string `json:"models"`
		HasKey  bool     `json:"has_key"`
		Source  string   `json:"source"`
	}
	rows := []row{}
	for _, p := range m.state.Providers {
		rows = append(rows, row{p.Name, p.BaseURL, p.Models, p.APIKey != "", "console"})
	}
	for _, p := range m.seed {
		name := p.Name
		if name == "" {
			name = provider.ProviderName(p.BaseURL)
		}
		if overriddenBy(m.state.Providers, name) {
			continue
		}
		rows = append(rows, row{name, p.BaseURL, p.Models, p.APIKey != "", "environment"})
	}
	localJSON(w, map[string]any{"providers": rows, "credential_storage": "local edge data volume"})
}

func (m *localManagement) addProvider(w http.ResponseWriter, r *http.Request) {
	var in provider.Config
	if err := decodeLocal(r, &in); err != nil {
		localError(w, 400, err)
		return
	}
	in.Name, in.BaseURL, in.APIKey = strings.TrimSpace(in.Name), strings.TrimRight(strings.TrimSpace(in.BaseURL), "/"), strings.TrimSpace(in.APIKey)
	if err := validLocalProvider(in); err != nil {
		localError(w, 400, err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.state
	next.Providers = append([]provider.Config(nil), next.Providers...)
	action := "provider.add"
	if overriddenBy(next.Providers, in.Name) {
		for i := range next.Providers {
			if next.Providers[i].Name == in.Name {
				next.Providers[i] = in
				break
			}
		}
		action = "provider.update"
	} else {
		next.Providers = append(next.Providers, in)
	}
	if err := m.changed(&next, action, in.Name); err != nil {
		localError(w, 500, err)
		return
	}
	localJSON(w, map[string]any{"name": in.Name})
}

func (m *localManagement) deleteProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.state
	next.Providers = []provider.Config{}
	for _, p := range m.state.Providers {
		if p.Name != id {
			next.Providers = append(next.Providers, p)
		}
	}
	if len(next.Providers) == len(m.state.Providers) {
		localError(w, 404, fmt.Errorf("console-managed provider not found"))
		return
	}
	if err := m.changed(&next, "provider.remove", id); err != nil {
		localError(w, 500, err)
		return
	}
	localJSON(w, map[string]any{"removed": id})
}

func (m *localManagement) teams(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	localJSON(w, map[string]any{"teams": append([]localTeam{}, m.state.Teams...)})
}
func (m *localManagement) addTeam(w http.ResponseWriter, r *http.Request) {
	var in localTeam
	if err := decodeLocal(r, &in); err != nil {
		localError(w, 400, err)
		return
	}
	in.ID = strings.TrimSpace(in.ID)
	in.Name = strings.TrimSpace(in.Name)
	if !consoleID.MatchString(in.ID) || in.Name == "" || len(in.Name) > 120 {
		localError(w, 400, fmt.Errorf("invalid team id or name"))
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.state.Teams {
		if t.ID == in.ID {
			localError(w, 409, fmt.Errorf("team already exists"))
			return
		}
	}
	next := m.state
	next.Teams = append(append([]localTeam(nil), next.Teams...), in)
	if err := m.changed(&next, "team.add", in.ID); err != nil {
		localError(w, 500, err)
		return
	}
	localJSON(w, in)
}
func (m *localManagement) deleteTeam(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.keys.Agents() {
		if a.GroupID == id {
			localError(w, 409, fmt.Errorf("team still has agents"))
			return
		}
	}
	next := m.state
	next.Teams = []localTeam{}
	for _, t := range m.state.Teams {
		if t.ID != id {
			next.Teams = append(next.Teams, t)
		}
	}
	if len(next.Teams) == len(m.state.Teams) {
		localError(w, 404, fmt.Errorf("team not found"))
		return
	}
	if err := m.changed(&next, "team.remove", id); err != nil {
		localError(w, 500, err)
		return
	}
	localJSON(w, map[string]any{"removed": id})
}

func (m *localManagement) agents(w http.ResponseWriter, _ *http.Request) {
	localJSON(w, map[string]any{"agents": m.keys.Agents()})
}
func (m *localManagement) issueAgent(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID      string `json:"id"`
		UserID  string `json:"user_id"`
		GroupID string `json:"group_id"`
	}
	if err := decodeLocal(r, &in); err != nil {
		localError(w, 400, err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.keys.Agents() {
		if a.AgentID == in.ID {
			localError(w, 409, fmt.Errorf("agent exists; use rotate"))
			return
		}
	}
	if in.GroupID != "" && !m.hasTeam(in.GroupID) {
		localError(w, 400, fmt.Errorf("team not found"))
		return
	}
	key, err := m.keys.Issue(in.ID, in.UserID, in.GroupID)
	if err != nil {
		localError(w, 400, err)
		return
	}
	next := m.state
	_ = m.changed(&next, "agent.add", in.ID)
	localJSON(w, map[string]any{"id": in.ID, "key": key})
}
func (m *localManagement) rotateAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.keys.Agents() {
		if a.AgentID == id {
			key, err := m.keys.Issue(id, a.UserID, a.GroupID)
			if err != nil {
				localError(w, 500, err)
				return
			}
			next := m.state
			_ = m.changed(&next, "agent.rotate", id)
			localJSON(w, map[string]any{"id": id, "key": key})
			return
		}
	}
	localError(w, 404, fmt.Errorf("agent not found"))
}
func (m *localManagement) deleteAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.keys.Revoke(id); err != nil {
		localError(w, 400, err)
		return
	}
	next := m.state
	_ = m.changed(&next, "agent.remove", id)
	localJSON(w, map[string]any{"removed": id})
}
func (m *localManagement) hasTeam(id string) bool {
	for _, t := range m.state.Teams {
		if t.ID == id {
			return true
		}
	}
	return false
}
func (m *localManagement) audit(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	events := append([]localEvent{}, m.state.Events...)
	sort.Slice(events, func(i, j int) bool { return events[i].At.After(events[j].At) })
	localJSON(w, map[string]any{"events": events, "integrity": "local history; not tamper-evident"})
}
