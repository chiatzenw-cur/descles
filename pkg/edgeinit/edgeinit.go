// Package edgeinit generates a ready-to-run Descles edge deployment: config,
// policy, secret file placeholders and a compose file. It writes files for the
// customer's own review and deployment pipeline; it never deploys anything and
// never handles provider credentials.
package edgeinit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// DefaultImage is the published open-core edge image. Pin it by digest once
// releases are signed; a tag alone is what the generated file warns about.
const DefaultImage = "ghcr.io/descles/edge:latest"

type Connector struct {
	ID  string
	URL string
}

type Options struct {
	Dir        string
	Mode       string // "standalone" (no hosted control plane) or "hosted"
	EdgeID     string
	Providers  []string // "openai", "anthropic"
	OpenAIBase string   // OpenAI-compatible upstream, default api.openai.com
	Connectors []Connector
	AgentName  string // standalone: first agent id
	HostedURL  string // hosted: control plane origin, e.g. https://app.descles.com
	OrgID      string // hosted
	BundleKey  string // hosted: pinned Ed25519 public key (hex)
	Image      string
	Port       int
	// OrgContext adds organization-context configuration. It needs the
	// enterprise edge image; the open-core edge ignores it.
	OrgContext bool
	// UID/GID the container runs as, so it can read 0600 secret files and
	// write ./data. Negative (Windows, Docker Desktop) omits the setting.
	UID, GID int
}

// Result tells the caller what was created. AgentKey is set only in
// standalone mode and is shown once; only its hash is stored.
type Result struct {
	Files    []string
	AgentKey string
	Next     []string
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,120}$`)
var connectorPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)

func (o *Options) normalize() error {
	if o.Dir == "" {
		o.Dir = "descles-edge"
	}
	if o.Mode == "" {
		o.Mode = "standalone"
	}
	if o.Mode != "standalone" && o.Mode != "hosted" {
		return errors.New("mode must be standalone or hosted")
	}
	if o.EdgeID == "" {
		o.EdgeID = "edge-1"
	}
	if !idPattern.MatchString(o.EdgeID) {
		return errors.New("edge id must be letters, digits, '-' or '_'")
	}
	if len(o.Providers) == 0 {
		o.Providers = []string{"anthropic", "openai"}
	}
	for _, p := range o.Providers {
		if p != "openai" && p != "anthropic" {
			return fmt.Errorf("unknown provider %q (openai, anthropic)", p)
		}
	}
	if o.OpenAIBase == "" {
		o.OpenAIBase = "https://api.openai.com/v1"
	}
	if u, err := url.Parse(o.OpenAIBase); err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("OpenAI-compatible upstream must be an https URL")
	}
	seen := map[string]bool{}
	for _, c := range o.Connectors {
		if !connectorPattern.MatchString(c.ID) || c.ID == "org" || seen[c.ID] {
			return fmt.Errorf("connector id %q must be unique lowercase letters, digits or '-' and not \"org\"", c.ID)
		}
		seen[c.ID] = true
		if u, err := url.Parse(c.URL); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return fmt.Errorf("connector %q needs an http(s) URL", c.ID)
		}
	}
	if o.AgentName == "" {
		o.AgentName = "agent-1"
	}
	if !idPattern.MatchString(o.AgentName) {
		return errors.New("agent name must be letters, digits, '-' or '_'")
	}
	if o.Mode == "hosted" {
		u, err := url.Parse(o.HostedURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") {
			return errors.New("hosted mode needs the control plane origin as https://host")
		}
		o.HostedURL = strings.TrimRight(o.HostedURL, "/")
		if !idPattern.MatchString(o.OrgID) {
			return errors.New("hosted mode needs your organization id")
		}
		if b, err := hex.DecodeString(o.BundleKey); err != nil || len(b) != 32 {
			return errors.New("hosted mode needs the control plane's Ed25519 bundle key (64 hex characters) from a trusted channel")
		}
	}
	if o.Image == "" {
		o.Image = DefaultImage
	}
	if o.Port == 0 {
		o.Port = 8081
	}
	if o.Port < 1 || o.Port > 65535 {
		return errors.New("port out of range")
	}
	return nil
}

// Generate writes the deployment into o.Dir. It refuses to overwrite an
// existing deployment so a re-run cannot clobber edited policy or secrets.
func Generate(o Options) (*Result, error) {
	if err := o.normalize(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(o.Dir, "compose.yml")); err == nil {
		return nil, fmt.Errorf("%s already contains an edge deployment; choose another --dir", o.Dir)
	}
	res := &Result{}
	write := func(rel, content string, mode os.FileMode) error {
		path := filepath.Join(o.Dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			return err
		}
		res.Files = append(res.Files, rel)
		return nil
	}

	env := []string{
		"# Descles edge configuration (no secrets in this file).",
		"DESCLES_MODE=edge",
		"DESCLES_ADDR=:8080",
		"DESCLES_STORAGE=sqlite",
		"DESCLES_SQLITE_PATH=/data/spans.db",
		"DESCLES_LOG_PAYLOADS=false",
		"DESCLES_DENY_ENFORCE=true",
		"DESCLES_EDGE_ID=" + o.EdgeID,
		"DESCLES_POLICY_FILE=/config/policy.yaml",
		"DESCLES_EDGE_MCP_FILE=/config/edge-mcp.yaml",
	}
	if o.OrgContext {
		env = append(env,
			"# Organization context (enterprise edge image).",
			"DESCLES_ORGCTX_DB=/data/org.db",
			"DESCLES_ORGCTX_EXTRACTORS=/config/orgctx-extractors.yaml")
	}
	secrets := []string{}
	for _, p := range o.Providers {
		switch p {
		case "openai":
			env = append(env, "DESCLES_UPSTREAM_BASE_URL="+o.OpenAIBase, "DESCLES_UPSTREAM_API_KEY_FILE=/config/secrets/openai-key")
			secrets = append(secrets, "openai-key")
		case "anthropic":
			env = append(env, "DESCLES_ANTHROPIC_API_KEY_FILE=/config/secrets/anthropic-key")
			secrets = append(secrets, "anthropic-key")
		}
	}
	if o.Mode == "standalone" {
		env = append(env,
			"# Standalone: no hosted control plane; nothing leaves this network.",
			"DESCLES_EDGE_REPORT_URL=off",
			"DESCLES_EDGE_KEYS_FILE=/config/keys.json")
		key, err := randomKey()
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(key))
		keys, _ := json.MarshalIndent([]map[string]string{{
			"key_sha256": hex.EncodeToString(sum[:]), "org_id": "local", "agent_id": o.AgentName,
		}}, "", "  ")
		if err := write("config/keys.json", string(keys)+"\n", 0o600); err != nil {
			return nil, err
		}
		res.AgentKey = key
	} else {
		env = append(env,
			"# Hosted: signed policy and agent grants are pulled from the control plane;",
			"# only metadata (tokens, cost, tool names, decisions) is reported.",
			"DESCLES_EDGE_ORG_ID="+o.OrgID,
			"DESCLES_EDGE_REPORT_URL="+o.HostedURL+"/edge/spans",
			"DESCLES_EDGE_BUNDLE_URL="+o.HostedURL+"/edge/bundle",
			"DESCLES_EDGE_BUNDLE_PUBKEY="+strings.ToLower(o.BundleKey),
			"DESCLES_EDGE_BUNDLE_CACHE=/data/bundle.json",
			"DESCLES_EDGE_OUTBOX_DB=/data/outbox.db",
			"DESCLES_EDGE_REPORT_TOKEN_FILE=/config/secrets/report-token")
		secrets = append(secrets, "report-token")
	}
	if err := write("edge.env", strings.Join(env, "\n")+"\n", 0o644); err != nil {
		return nil, err
	}
	// Empty placeholders: the edge refuses to start until they are filled, so
	// a half-configured edge cannot run.
	for _, s := range secrets {
		if err := write("config/secrets/"+s, "", 0o600); err != nil {
			return nil, err
		}
	}
	if err := write("config/policy.yaml", policyYAML, 0o644); err != nil {
		return nil, err
	}
	if err := write("config/edge-mcp.yaml", mcpYAML(o.Connectors), 0o644); err != nil {
		return nil, err
	}
	if o.OrgContext {
		if err := write("config/orgctx-extractors.yaml", extractorsYAML, 0o644); err != nil {
			return nil, err
		}
	}
	if err := write("compose.yml", composeYAML(o), 0o644); err != nil {
		return nil, err
	}
	if err := write(".gitignore", "config/secrets/\ndata/\n", 0o644); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(o.Dir, "data"), 0o700); err != nil {
		return nil, err
	}
	var fill []string
	for _, s := range secrets {
		fill = append(fill, "config/secrets/"+s)
	}
	res.Next = []string{
		"Put credentials in: " + strings.Join(fill, ", ") + " (they never leave this machine).",
		"Review config/policy.yaml and config/edge-mcp.yaml.",
		"Start: descles edge up --dir " + o.Dir + "   (or: docker compose -f " + filepath.ToSlash(filepath.Join(o.Dir, "compose.yml")) + " up -d)",
		fmt.Sprintf("Connect an agent: descles connect claude-code --edge http://127.0.0.1:%d --key <agent key>", o.Port),
	}
	if err := write("README.md", readme(o, res), 0o644); err != nil {
		return nil, err
	}
	sort.Strings(res.Files)
	return res, nil
}

func randomKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "vk_" + hex.EncodeToString(b), nil
}

func composeYAML(o Options) string {
	user := ""
	if o.UID >= 0 && o.GID >= 0 {
		user = fmt.Sprintf("    user: \"%d:%d\"   # owner of ./config and ./data\n", o.UID, o.GID)
	}
	pinNote := ""
	if !strings.Contains(o.Image, "@sha256:") {
		pinNote = "    # Pin by digest (image@sha256:...) before production use.\n"
	}
	return fmt.Sprintf(`# Descles edge. Runs entirely in your network.
services:
  descles-edge:
%s    image: %s
%s    env_file: edge.env
    ports:
      - "127.0.0.1:%d:8080"   # loopback only; put your internal TLS ingress in front for a VPC
    volumes:
      - ./data:/data
      - ./config:/config:ro
    restart: unless-stopped
`, pinNote, o.Image, user, o.Port)
}

func mcpYAML(cs []Connector) string {
	var b strings.Builder
	b.WriteString("# MCP servers reachable from this edge. Tokens are read from local files only.\n")
	b.WriteString("# Agents call POST /mcp/<id>.\n")
	if len(cs) == 0 {
		b.WriteString("connectors: []\n")
		b.WriteString("#  - id: github\n#    url: https://api.githubcopilot.com/mcp/\n#    token_file: /config/secrets/github-token\n")
	} else {
		b.WriteString("connectors:\n")
		for _, c := range cs {
			fmt.Fprintf(&b, "  - id: %s\n    url: %s\n    # token_file: /config/secrets/%s-token\n", c.ID, c.URL, c.ID)
			if strings.HasPrefix(c.URL, "http://") {
				b.WriteString("    insecure_http: true\n")
			}
		}
	}
	b.WriteString("\n# Context labels each agent or group may read (used by extensions such as\n# organization context in the enterprise edge).\nclearances:\n  agents: {}\n  groups: {}\n")
	return b.String()
}

const policyYAML = `# Edge policy: enforced here, for every model, MCP and client-native tool call.
defaults:
  budget:
    daily_usd: 20
  tools:
    github.delete_repository: deny
  # Client-native tools from Claude Code / Codex / Hermes hooks:
  # local.bash, local.write, local.read, local.web, mcp.<server>.<tool>
  arg_tools:
    - {tool: local.bash, args: {command: ["*rm -rf*", "*push --force*", "*kubectl delete*", "*terraform destroy*"]}, decision: deny}
    - {tool: local.read, args: {path: ["*.env", "*/secrets/*", "*id_rsa*"]}, decision: deny}
  # require_approval: [local.write]
`

const extractorsYAML = `# Tool result -> organization context. Uncomment and adapt to your tools.
# Paths: $ is the tool's structured result. Keys decide identity; labels are the read ACL.
extractors: []
#  - tool: crm.get_account
#    entity: {kind: customer, keys: {crm: $.Id, email: $.BillingEmail}, name: $.Name}
#    facts: {stage: $.StageName}
#    relations:
#      owned_by: {kind: person, keys: {email: $.Owner.Email}, name: $.Owner.Name}
#    labels: [sales]
`

func readme(o Options, r *Result) string {
	var b strings.Builder
	b.WriteString("# Descles edge `" + o.EdgeID + "`\n\n")
	if o.Mode == "standalone" {
		b.WriteString("Standalone mode: no hosted control plane. Nothing leaves this network.\n")
		b.WriteString("Agent keys live in `config/keys.json` as SHA-256 hashes; `" + o.AgentName + "` was created by `descles edge init`.\n\n")
	} else {
		b.WriteString("Hosted mode: policy and agent grants come signed from " + o.HostedURL + "; only metadata is reported.\n\n")
	}
	b.WriteString("## Next\n\n")
	for i, n := range r.Next {
		fmt.Fprintf(&b, "%d. %s\n", i+1, n)
	}
	b.WriteString("\nFiles under `config/secrets/` are git-ignored. Keep this directory in your own infrastructure repo.\n")
	return b.String()
}
