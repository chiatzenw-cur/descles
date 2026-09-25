// Package config loads Descles Gateway configuration from the environment.
//
// All settings are environment variables (or sensible defaults) so the same
// binary runs locally, in a container, or in a managed deployment without
// code changes. Provider credentials are configured separately from the
// client-facing project key — Descles never forwards a client's Authorization
// header upstream.
package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/provider"
)

// Config is the fully-resolved gateway configuration.
type Config struct {
	// Addr is the listen address, e.g. ":8080".
	Addr string

	// UpstreamBaseURL is the OpenAI-compatible provider root, e.g.
	// "https://api.openai.com/v1". This is where proxied requests go.
	UpstreamBaseURL string

	// UpstreamAPIKey is the real provider credential. The incoming client
	// Authorization header is NOT forwarded; it is treated as an Descles
	// project key and discarded.
	UpstreamAPIKey string

	// AnthropicBaseURL is the Anthropic Messages API root; AnthropicAPIKey is
	// the real provider credential. The client's x-api-key is never forwarded.
	AnthropicBaseURL string
	AnthropicAPIKey  string

	// Providers is the ordered list of upstream providers (M2 routing).
	// When DESCLES_PROVIDERS is unset it contains a single default provider
	// built from DESCLES_UPSTREAM_BASE_URL / DESCLES_UPSTREAM_API_KEY.
	Providers []provider.Config

	// GatewayDomain is the apex host this gateway is served on for
	// hostname-routed tenants, e.g. "gw.descles.com". A request whose Host is
	// "<provider>.gw.descles.com" selects provider "<provider>" from the
	// tenant's own BYOK configuration instead of registry model routing.
	// Empty disables hostname routing.
	GatewayDomain string

	// Storage selects the backend: "memory" | "sqlite" (default for M1).
	Storage string

	// SQLitePath is the DB file (or empty for the default "descles.db").
	SQLitePath string

	// PostgresDSN is the PostgreSQL DSN used when DESCLES_STORAGE=postgres.
	PostgresDSN string

	// PolicyJSON is the DESCLES_POLICY JSON string (M4 budget + tool decisions).
	PolicyJSON string

	// PolicyFile is the path to a JSON or YAML policy document
	// (DESCLES_POLICY_FILE). Takes precedence over PolicyJSON when both are set.
	PolicyFile string

	// AuditDB is the durable audit-ledger SQLite path; AuditKeyPath is the
	// Ed25519 private key kept across restarts so prior signatures verify.
	AuditDB      string
	AuditKeyPath string

	// AuditRequireDurable, when true, makes the gateway fail to boot if the
	// audit DB cannot open/load, the loaded chain fails verification, or the
	// signing key cannot be obtained. Audit is the tamper-evident core promise:
	// telemetry may degrade, audit must fail closed. (DESCLES_AUDIT_REQUIRE_DURABLE)
	AuditRequireDurable bool

	// Audit anchoring (hosted control plane). With a sink configured
	// the gateway checkpoints each chain's head OUTSIDE the audit database — in
	// the customer's own storage — and refuses to boot when the ledger is
	// shorter than the anchored head or disagrees with it at that height.
	//   AuditAnchorDir      filesystem sink: a volume the customer controls
	//   AuditAnchorURL      HTTP sink: the customer's own endpoint (strongest —
	//                       the operator holds no credential for it)
	//   AuditAnchorRequire  also fail an append whose checkpoint cannot be written
	//   AuditAnchorInit     one-time migration from a verified durable ledger to
	//                       an empty external anchor store; remove after startup
	AuditAnchorDir     string
	AuditAnchorURL     string
	AuditAnchorToken   string
	AuditAnchorRequire bool
	AuditAnchorInit    bool

	// ControlDB is the durable control-plane entity store (orgs/agents/
	// approvals/skills), so the HITL queue and governed library survive restart.
	ControlDB string

	// Demo seeds a demo tenant + approval + skill so the console is populated.
	Demo bool

	// ShadowMode, when true, records policy decisions (deny, require_approval)
	// without actually blocking execution. Used to measure false-positive rate
	// before enforcement.
	ShadowMode bool

	// DenyEnforce, when true (default), rewrites denied tool calls out of
	// non-streaming responses so they never reach the runtime. When false, the
	// proxy only records the deny (observability-only, like ShadowMode for the
	// response path).
	DenyEnforce bool

	// AdminToken authenticates requests to the management endpoints
	// (/control, /action, /skills, /trust). When unset, a random token is
	// generated and logged at startup.
	AdminToken string

	// DataToken authenticates LLM requests to the data plane (/v1/*,
	// /anthropic/v1/*). When unset, the data plane accepts any key.
	DataToken string

	// LogLevel is one of debug|info|warn|error.
	LogLevel string

	// LogPayloads, when true, stores request/response bodies in span
	// attributes. Defaults to false: Descles avoids persisting prompts by
	// default (see the security model in project.md).
	LogPayloads bool

	// UpstreamTimeout bounds a single upstream round trip.
	UpstreamTimeout time.Duration

	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout time.Duration

	// MasterKey (DESCLES_MASTER_KEY, base64) seals tenant provider keys (BYOK) at
	// rest with AES-GCM, so it has to decode to an AES key size (16, 24 or 32
	// bytes). Unset = demo mode: keys stored in plaintext with a startup warning.
	// A usable-length key is also what makes the seal actually happen: any other
	// length would silently store plaintext while the console claims encryption.
	MasterKey []byte

	// CustomerCustody (DESCLES_SECRET_CUSTODY=customer) makes the hosted
	// control plane refuse to store or use provider keys and MCP connector
	// tokens. Credentials then live only on customer-run edges.
	CustomerCustody bool
}

// Load reads configuration from the environment, applying defaults.
func Load() (Config, error) {
	upstreamBase := strings.TrimRight(getenv("DESCLES_UPSTREAM_BASE_URL", "https://api.openai.com/v1"), "/")
	upstreamKey, err := secretValue("DESCLES_UPSTREAM_API_KEY")
	if err != nil {
		return Config{}, err
	}
	providerConfig, err := secretValue("DESCLES_PROVIDERS")
	if err != nil {
		return Config{}, err
	}
	providers, err := parseProviders(providerConfig)
	if err != nil {
		return Config{}, err
	}
	if len(providers) == 0 {
		providers = []provider.Config{{BaseURL: upstreamBase, APIKey: upstreamKey}}
	}
	providers, err = validateProviders(providers)
	if err != nil {
		return Config{}, err
	}
	anthropicBase := strings.TrimRight(getenv("DESCLES_ANTHROPIC_BASE_URL", "https://api.anthropic.com"), "/")
	if err := validateBaseURL(anthropicBase); err != nil {
		return Config{}, fmt.Errorf("DESCLES_ANTHROPIC_BASE_URL %w", err)
	}
	anthropicKey, err := secretValue("DESCLES_ANTHROPIC_API_KEY")
	if err != nil {
		return Config{}, err
	}
	custody := strings.ToLower(strings.TrimSpace(getenv("DESCLES_SECRET_CUSTODY", "hosted")))
	if custody != "hosted" && custody != "customer" {
		return Config{}, fmt.Errorf("DESCLES_SECRET_CUSTODY must be hosted or customer")
	}
	var masterKey []byte
	if raw := os.Getenv("DESCLES_MASTER_KEY"); raw != "" {
		b, derr := base64.StdEncoding.DecodeString(raw)
		if derr != nil {
			return Config{}, fmt.Errorf("DESCLES_MASTER_KEY must be valid base64")
		}
		switch len(b) {
		case 16, 24, 32:
		default:
			// Anything else cannot be used as an AES key, and the sealing path
			// would fall back to storing plaintext while the console reports the
			// credential as encrypted — refuse it instead of faking the promise.
			return Config{}, fmt.Errorf("DESCLES_MASTER_KEY must decode to 16, 24 or 32 bytes (an AES key size); got %d", len(b))
		}
		masterKey = b
	}
	return Config{
		Addr:                getenv("DESCLES_ADDR", ":8080"),
		UpstreamBaseURL:     upstreamBase,
		UpstreamAPIKey:      upstreamKey,
		AnthropicBaseURL:    anthropicBase,
		AnthropicAPIKey:     anthropicKey,
		Providers:           providers,
		GatewayDomain:       os.Getenv("DESCLES_GATEWAY_DOMAIN"),
		Storage:             getenv("DESCLES_STORAGE", "sqlite"),
		SQLitePath:          getenv("DESCLES_SQLITE_PATH", "descles.db"),
		PostgresDSN:         os.Getenv("DESCLES_POSTGRES_DSN"),
		PolicyJSON:          os.Getenv("DESCLES_POLICY"),
		PolicyFile:          os.Getenv("DESCLES_POLICY_FILE"),
		AuditDB:             getenv("DESCLES_AUDIT_DB", "descles-control.db"),
		AuditKeyPath:        getenv("DESCLES_AUDIT_KEY", "descles-audit.key"),
		AuditRequireDurable: getenv("DESCLES_AUDIT_REQUIRE_DURABLE", "false") == "true",
		AuditAnchorDir:      os.Getenv("DESCLES_AUDIT_ANCHOR_DIR"),
		AuditAnchorURL:      os.Getenv("DESCLES_AUDIT_ANCHOR_URL"),
		AuditAnchorToken:    os.Getenv("DESCLES_AUDIT_ANCHOR_TOKEN"),
		AuditAnchorRequire:  getenv("DESCLES_AUDIT_ANCHOR_REQUIRE", "false") == "true",
		AuditAnchorInit:     getenv("DESCLES_AUDIT_ANCHOR_INIT", "false") == "true",
		ControlDB:           getenv("DESCLES_CONTROL_DB", "descles-control.db"),
		Demo:                getenv("DESCLES_DEMO", "false") == "true",
		ShadowMode:          getenv("DESCLES_SHADOW_MODE", "false") == "true",
		DenyEnforce:         getenv("DESCLES_DENY_ENFORCE", "true") == "true",
		AdminToken:          os.Getenv("DESCLES_ADMIN_TOKEN"),
		DataToken:           os.Getenv("DESCLES_DATA_TOKEN"),
		LogLevel:            getenv("DESCLES_LOG_LEVEL", "info"),
		LogPayloads:         getenv("DESCLES_LOG_PAYLOADS", "false") == "true",
		UpstreamTimeout:     120 * time.Second,
		ShutdownTimeout:     10 * time.Second,
		MasterKey:           masterKey,
		CustomerCustody:     custody == "customer",
	}, nil
}

// secretValue supports an env value or a mounted secret file, never both.
// The _FILE variant keeps provider keys out of image layers and Docker env.
func secretValue(name string) (string, error) {
	value, path := os.Getenv(name), os.Getenv(name+"_FILE")
	if value != "" && path != "" {
		return "", fmt.Errorf("set %s or %s_FILE, not both", name, name)
	}
	if path == "" {
		return value, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", name, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func parseProviders(raw string) ([]provider.Config, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var list []provider.Config
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, fmt.Errorf("DESCLES_PROVIDERS is invalid JSON: %w", err)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("DESCLES_PROVIDERS must contain at least one provider")
	}
	return list, nil
}

func validateProviders(list []provider.Config) ([]provider.Config, error) {
	seenNames := map[string]bool{}
	catchAlls := 0
	for i := range list {
		list[i].BaseURL = strings.TrimRight(strings.TrimSpace(list[i].BaseURL), "/")
		if err := validateBaseURL(list[i].BaseURL); err != nil {
			return nil, fmt.Errorf("DESCLES_PROVIDERS[%d].base_url must be an absolute http(s) URL", i)
		}
		name := strings.TrimSpace(list[i].Name)
		if name == "" {
			name = provider.ProviderName(list[i].BaseURL)
		}
		list[i].Name = name
		if seenNames[name] {
			return nil, fmt.Errorf("DESCLES_PROVIDERS contains duplicate provider name %q", name)
		}
		seenNames[name] = true
		if len(list[i].Models) == 0 {
			catchAlls++
		}
		for modelIndex, pattern := range list[i].Models {
			pattern = strings.TrimSpace(pattern)
			stars := strings.Count(pattern, "*")
			if pattern == "" || stars > 1 || (stars == 1 && pattern != "*" && !strings.HasPrefix(pattern, "*") && !strings.HasSuffix(pattern, "*")) {
				return nil, fmt.Errorf("DESCLES_PROVIDERS[%d] has invalid model pattern %q", i, pattern)
			}
			list[i].Models[modelIndex] = pattern
		}
	}
	if catchAlls > 1 {
		return nil, fmt.Errorf("DESCLES_PROVIDERS may contain at most one catch-all provider")
	}
	return list, nil
}

func validateBaseURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return fmt.Errorf("must be an absolute http(s) URL without credentials, query, or fragment")
	}
	return nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
