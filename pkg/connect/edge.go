// Package connect points agent harnesses (Claude Code, Codex, any
// OpenAI-compatible agent such as Hermes) at a customer's Descles edge, and
// implements the harness-side hooks that put client-native tools (shell,
// file edits) under the edge's policy.
//
// Nothing here talks to Descles-hosted services: the only endpoint is the
// customer's own edge.
package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Edge is a customer-run Descles edge and the agent key used against it.
type Edge struct {
	URL    string // e.g. https://descles.internal
	Key    string
	Client *http.Client
}

// NormalizeURL validates an edge base URL and strips a trailing slash.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" {
		return "", fmt.Errorf("edge URL must be http(s)://host[:port]")
	}
	if u.Scheme == "http" && !isLocalHost(u.Hostname()) {
		fmt.Fprintln(os.Stderr, "warning: plain HTTP to a non-local edge sends the agent key unencrypted")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func isLocalHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasSuffix(h, ".localhost")
}

func (e Edge) client() *http.Client {
	if e.Client != nil {
		return e.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (e Edge) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, e.URL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+e.Key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tid, ok := ctx.Value(traceKey{}).(string); ok && tid != "" {
		req.Header.Set("X-Descles-Trace-Id", tid)
	}
	resp, err := e.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("edge rejected the agent key")
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("edge %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

type traceKey struct{}

// WithTrace tags edge requests with a harness session id so the edge groups
// one session's calls into one trace.
func WithTrace(ctx context.Context, session string) context.Context {
	var b strings.Builder
	for _, c := range session {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteRune(c)
		}
	}
	s := b.String()
	if len(s) > 120 {
		s = s[:120]
	}
	return context.WithValue(ctx, traceKey{}, s)
}

// Connectors asks the edge which MCP connectors this agent may use. It is
// also the reachability and key check `connect` runs before writing config.
func (e Edge) Connectors(ctx context.Context) ([]string, error) {
	var out struct {
		Connectors []string `json:"connectors"`
	}
	if err := e.do(ctx, http.MethodGet, "/mcp", nil, &out); err != nil {
		return nil, err
	}
	return out.Connectors, nil
}

// Verdict mirrors the edge's tool-check answer.
type Verdict struct {
	Decision string `json:"decision"`
	Tool     string `json:"tool"`
	Reason   string `json:"reason"`
}

func (e Edge) Check(ctx context.Context, client, tool string, input map[string]any, session string) (Verdict, error) {
	var v Verdict
	err := e.do(ctx, http.MethodPost, "/v1/tool-check", map[string]any{"client": client, "tool": tool, "input": input, "session": session}, &v)
	return v, err
}

func (e Edge) Report(ctx context.Context, client, tool, outcome, session string) error {
	return e.do(ctx, http.MethodPost, "/v1/tool-report", map[string]any{"client": client, "tool": tool, "outcome": outcome, "session": session}, nil)
}

// KeyFile is where `connect` stores the agent key: outside every project, so
// it is never committed, and readable only by the user.
func KeyFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".descles", "agent-key"), nil
}

func SaveKey(path, key string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.TrimSpace(key)+"\n"), 0o600)
}

func LoadKey(path string) (string, error) {
	if k := strings.TrimSpace(os.Getenv("DESCLES_AGENT_KEY")); k != "" {
		return k, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("no agent key: set DESCLES_AGENT_KEY or run `descles connect` (%w)", err)
	}
	return strings.TrimSpace(string(data)), nil
}
