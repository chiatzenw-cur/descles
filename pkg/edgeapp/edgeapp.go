// Package edgeapp is the customer-side Descles edge: the open-core data plane
// that runs in the customer's network. It must never import the hosted
// control plane (see boundary_test.go).
package edgeapp

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/chiatzenw-cur/descles/pkg/config"
	"github.com/chiatzenw-cur/descles/pkg/edge"
	"github.com/chiatzenw-cur/descles/pkg/policy"
	"github.com/chiatzenw-cur/descles/pkg/provider"
	"github.com/chiatzenw-cur/descles/pkg/proxy"
	"github.com/chiatzenw-cur/descles/pkg/storage"
)

// Run is the customer-side data plane. Provider credentials, prompts and
// tool arguments stay here. Only a strict usage/cost metadata contract leaves.
// It serves until ctx is cancelled, then shuts down gracefully.
//
// Plugins add extensions (served at /mcp/<id>) and result observers. The
// open-core edge passes none; commercial builds register theirs here.
func Run(ctx context.Context, cfg config.Config, logger *slog.Logger, plugins ...Plugin) error {
	if cfg.Storage != "sqlite" {
		return fmt.Errorf("edge mode requires DESCLES_STORAGE=sqlite")
	}
	if cfg.LogPayloads || cfg.ShadowMode || !cfg.DenyEnforce {
		return fmt.Errorf("edge mode requires payload logging off and enforcement on")
	}
	if cfg.DataToken != "" || cfg.AdminToken != "" {
		return fmt.Errorf("edge mode uses agent-bound keys; unset DESCLES_DATA_TOKEN and DESCLES_ADMIN_TOKEN")
	}
	keyedProviders := make([]provider.Config, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		if p.APIKey != "" {
			keyedProviders = append(keyedProviders, p)
		}
	}
	if len(keyedProviders) == 0 && cfg.AnthropicAPIKey == "" {
		return fmt.Errorf("configure a local provider key before starting edge mode")
	}
	edgeID := strings.TrimSpace(os.Getenv("DESCLES_EDGE_ID"))
	if !edge.ValidEdgeID(edgeID) {
		return fmt.Errorf("DESCLES_EDGE_ID must be 1-120 letters, digits, '-' or '_'")
	}
	reportURL := strings.TrimSpace(os.Getenv("DESCLES_EDGE_REPORT_URL"))
	reportToken, err := edgeSecret("DESCLES_EDGE_REPORT_TOKEN")
	if err != nil {
		return err
	}
	// "off" is the standalone open-core edge: no hosted control plane, no
	// metadata leaves at all. Everything is still recorded locally.
	offline := reportURL == "off"
	var parsed *url.URL
	if offline {
		if strings.TrimSpace(os.Getenv("DESCLES_EDGE_BUNDLE_URL")) != "" {
			return fmt.Errorf("DESCLES_EDGE_REPORT_URL=off cannot be combined with a hosted policy bundle")
		}
	} else {
		if reportURL == "" || reportToken == "" {
			return fmt.Errorf("edge mode requires report URL and token (or DESCLES_EDGE_REPORT_URL=off for a standalone edge)")
		}
		parsed, err = url.Parse(reportURL)
		if err != nil || parsed.Host == "" || parsed.Path != "/edge/spans" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()))) {
			return fmt.Errorf("DESCLES_EDGE_REPORT_URL must be an HTTPS /edge/spans endpoint (HTTP only for loopback testing)")
		}
	}
	var orgID string
	var holder *policy.Holder
	var keys *edge.Keyring
	var bundle *edge.BundleState
	bundleURL := strings.TrimSpace(os.Getenv("DESCLES_EDGE_BUNDLE_URL"))
	if bundleURL != "" {
		bundleEndpoint, parseErr := url.Parse(bundleURL)
		if parseErr != nil || bundleEndpoint.Scheme != parsed.Scheme || bundleEndpoint.Host != parsed.Host || bundleEndpoint.Path != "/edge/bundle" || bundleEndpoint.RawQuery != "" || bundleEndpoint.Fragment != "" {
			return fmt.Errorf("DESCLES_EDGE_BUNDLE_URL must share the report URL origin and end in /edge/bundle")
		}
		orgID = strings.TrimSpace(os.Getenv("DESCLES_EDGE_ORG_ID"))
		pubRaw := strings.TrimSpace(os.Getenv("DESCLES_EDGE_BUNDLE_PUBKEY"))
		pub, decodeErr := hex.DecodeString(pubRaw)
		cachePath := strings.TrimSpace(os.Getenv("DESCLES_EDGE_BUNDLE_CACHE"))
		if orgID == "" || decodeErr != nil || len(pub) != ed25519.PublicKeySize || cachePath == "" {
			return fmt.Errorf("signed bundle mode requires org ID, Ed25519 public key and cache path")
		}
		bundle = edge.NewBundleState(orgID, ed25519.PublicKey(pub), cachePath)
		if err := bundle.LoadCache(); err != nil {
			logger.Info("no usable cached edge bundle", "err", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		fetchErr := bundle.Fetch(ctx, provider.NoRedirectClient(10*time.Second), bundleURL, reportToken)
		cancel()
		if fetchErr != nil && !bundle.Valid() {
			return fmt.Errorf("no valid edge policy bundle: %w", fetchErr)
		}
		if fetchErr != nil {
			logger.Warn("using cached edge bundle", "err", fetchErr)
		}
		holder = bundle.Policy
	} else {
		keyFile := strings.TrimSpace(os.Getenv("DESCLES_EDGE_KEYS_FILE"))
		if keyFile == "" || cfg.PolicyFile == "" {
			return fmt.Errorf("local edge mode requires DESCLES_EDGE_KEYS_FILE and DESCLES_POLICY_FILE")
		}
		keys, err = edge.LoadKeyring(keyFile)
		if err != nil {
			return err
		}
		orgID, err = keys.OrgID()
		if err != nil {
			return err
		}
		pol, err := policy.LoadFile(cfg.PolicyFile)
		if err != nil {
			return err
		}
		holder = policy.NewHolder(pol)
	}
	local, err := storage.NewSQLite(cfg.SQLitePath)
	if err != nil {
		return err
	}
	var queue *edge.Outbox
	if !offline {
		if queue, err = edge.OpenOutbox(strings.TrimSpace(os.Getenv("DESCLES_EDGE_OUTBOX_DB"))); err != nil {
			_ = local.Close()
			return err
		}
	}
	metered := &edge.MeteredStore{Storage: local, Outbox: queue, EdgeID: edgeID}
	defer metered.Close()
	h := proxy.New(cfg, provider.NewRegistry(keyedProviders), holder, metered, logger)
	if bundle != nil {
		h.KeyResolver = bundle.Resolve
		h.GroupOfAgent = func(agentID string) string { grant, _ := bundle.AgentGrant(agentID); return grant.GroupName }
		h.DelegatedToolAllowed = bundle.ToolAllowed
		h.DelegatedDailyBudget = func(agentID string) (float64, bool) {
			grant, ok := bundle.AgentGrant(agentID)
			return float64(grant.DailyBudgetCents) / 100, ok && grant.DailyBudgetCents > 0
		}
		h.HostedProviderAllowed = bundle.ProviderAllowed
	} else {
		h.KeyResolver = keys.Resolve
	}
	// An agent cannot substitute an arbitrary BYOK endpoint to reach an internal
	// host or move requests outside the configured provider set.
	allowed := map[string]bool{}
	for _, p := range keyedProviders {
		allowed[origin(p.BaseURL)] = true
	}
	if cfg.AnthropicAPIKey != "" {
		allowed[origin(cfg.AnthropicBaseURL)] = true
	}
	h.EgressCheck = func(_ string, baseURL string) error {
		if !allowed[origin(baseURL)] {
			return fmt.Errorf("upstream not configured by edge administrator")
		}
		return nil
	}
	var reporter *edge.Reporter
	if !offline {
		reporter = &edge.Reporter{Outbox: queue, URL: reportURL, Token: reportToken, Client: provider.NoRedirectClient(10 * time.Second)}
	}
	workerCtx, stopWorker := context.WithCancel(context.Background())
	defer stopWorker()
	go func() {
		if reporter == nil {
			return
		}
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(workerCtx, 10*time.Second)
				_, err := reporter.Flush(ctx, 100)
				cancel()
				if err != nil {
					logger.Warn("metadata delivery deferred", "err", err)
				}
			}
		}
	}()
	if bundle != nil {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-workerCtx.Done():
					return
				case <-ticker.C:
					ctx, cancel := context.WithTimeout(workerCtx, 10*time.Second)
					err := bundle.Fetch(ctx, provider.NoRedirectClient(10*time.Second), bundleURL, reportToken)
					cancel()
					if err != nil {
						logger.Warn("edge policy refresh deferred", "err", err)
					}
				}
			}
		}()
	}
	mcp, closeMCP, err := edgeMCP(logger, metered, holder, bundle, keys, plugins)
	if err != nil {
		return err
	}
	defer closeMCP()
	inner := h.Routes()
	mux := http.NewServeMux()
	guard := guardWith(bundle, metered, queue, inner)
	mux.Handle("/v1/", guard)
	mux.Handle("/anthropic/v1/", guard)
	mux.Handle("POST /mcp/{connector}", guardWith(bundle, metered, queue, mcp))
	mux.Handle("GET /mcp", guardWith(bundle, metered, queue, http.HandlerFunc(mcp.ServeConnectors)))
	// Hooks of client-native tools (Claude Code, Codex, ...) ask before and
	// report after, so shell and file tools fall under the same policy.
	mux.Handle("POST /v1/tool-check", guardWith(bundle, metered, queue, http.HandlerFunc(mcp.ServeToolCheck)))
	mux.Handle("POST /v1/tool-report", guardWith(bundle, metered, queue, http.HandlerFunc(mcp.ServeToolReport)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if !metered.Ready() || (bundle != nil && !bundle.Valid()) {
			http.Error(w, "local metering unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: cfg.Addr, Handler: mux, ReadHeaderTimeout: 15 * time.Second}
	errs := make(chan error, 1)
	go func() {
		logger.Info("customer-side data plane listening", "addr", cfg.Addr, "org", orgID, "edge", edgeID)
		errs <- srv.ListenAndServe()
	}()
	select {
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		stopWorker()
		if reporter != nil {
			_, _ = reporter.Flush(shutdownCtx, 100)
		}
	}
	return nil
}

// guardWith refuses traffic once the policy lease expires or metering can no
// longer be kept: the edge fails closed rather than acting unobserved.
func guardWith(bundle *edge.BundleState, metered *edge.MeteredStore, queue *edge.Outbox, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bundle != nil && !bundle.Valid() {
			http.Error(w, "edge policy lease expired", http.StatusServiceUnavailable)
			return
		}
		if !metered.Ready() {
			http.Error(w, "local metering unavailable", http.StatusServiceUnavailable)
			return
		}
		if queue != nil {
			if pending, err := queue.Count(r.Context()); err != nil || pending >= 100000 {
				http.Error(w, "edge metadata queue unavailable or full", http.StatusServiceUnavailable)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Plugin contributes extensions and observers to the edge's tool gateway. It
// runs once at startup; closeFn (may be nil) runs at shutdown.
type Plugin func(logger *slog.Logger) (exts []edge.Extension, obs []edge.Observer, closeFn func(), err error)

// edgeMCP builds the customer-side tool gateway: MCP connectors, plugin
// extensions and the tool-check endpoints used by harness hooks.
//
//	DESCLES_EDGE_MCP_FILE   connectors (URL + local token file) and clearances
func edgeMCP(logger *slog.Logger, spans *edge.MeteredStore, holder *policy.Holder, bundle *edge.BundleState, keys *edge.Keyring, plugins []Plugin) (*edge.MCPGateway, func(), error) {
	var closers []func()
	closeAll := func() {
		for _, c := range closers {
			c()
		}
	}
	mcpFile := strings.TrimSpace(os.Getenv("DESCLES_EDGE_MCP_FILE"))
	g := &edge.MCPGateway{Config: &edge.MCPConfig{}, Policy: holder, Spans: spans, Logger: logger}
	if mcpFile != "" {
		cfg, err := edge.LoadMCPConfig(mcpFile)
		if err != nil {
			return nil, closeAll, err
		}
		g.Config = cfg
	}
	if bundle != nil {
		g.Resolve = bundle.Resolve
		g.GroupOf = func(agentID string) string { grant, _ := bundle.AgentGrant(agentID); return grant.GroupName }
		g.ToolAllowed = bundle.ToolAllowed
		g.ToolPermitted = bundle.ToolPermitted
		g.ConnectorPermitted = bundle.ConnectorPermitted
		g.BundleLabel = bundle.ContextLabels
	} else {
		g.Resolve = keys.Resolve
	}
	taken := map[string]bool{}
	for _, c := range g.Config.Connectors {
		taken[c.ID] = true
	}
	for _, plugin := range plugins {
		exts, obs, closeFn, err := plugin(logger)
		if err != nil {
			closeAll()
			return nil, func() {}, err
		}
		if closeFn != nil {
			closers = append(closers, closeFn)
		}
		for _, e := range exts {
			if taken[e.ID()] {
				closeAll()
				return nil, func() {}, fmt.Errorf("extension %q collides with a connector or another extension", e.ID())
			}
			taken[e.ID()] = true
		}
		g.Extensions = append(g.Extensions, exts...)
		g.Observers = append(g.Observers, obs...)
	}
	logger.Info("edge tool gateway ready", "connectors", len(g.Config.Connectors), "extensions", len(g.Extensions), "observers", len(g.Observers))
	return g, closeAll, nil
}

func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func edgeSecret(name string) (string, error) {
	value, path := os.Getenv(name), os.Getenv(name+"_FILE")
	if value != "" && path != "" {
		return "", fmt.Errorf("set %s or %s_FILE, not both", name, name)
	}
	if path == "" {
		return strings.TrimSpace(value), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", name, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// Main is the edge process entry point: load config, log as JSON, serve until
// SIGINT/SIGTERM. It returns the process exit code.
func Main(plugins ...Plugin) int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		return 1
	}
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := Run(ctx, cfg, logger, plugins...); err != nil {
		logger.Error("edge stopped", "err", err)
		return 1
	}
	return 0
}
