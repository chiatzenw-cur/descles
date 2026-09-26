package connect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Check results.
const (
	CheckOK   = "ok"
	CheckWarn = "warn"
	CheckFail = "fail"
	CheckSkip = "skip"
)

// Check is one doctor finding, with what to do about it.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// DoctorOptions says what to check. Empty paths are looked up in the user's
// home directory; a missing harness config is reported as skipped.
type DoctorOptions struct {
	Edge           Edge
	AdminToken     string // optional: enables the trace round-trip check
	Home           string
	ClaudeSettings string
	CodexConfig    string
	KeyFile        string
	GOOS           string
}

// Doctor runs the onboarding checks, in the order a person would debug them.
func Doctor(ctx context.Context, o DoctorOptions) []Check {
	var out []Check
	add := func(c Check) { out = append(out, c) }
	client := o.Edge.client()

	// 1. Edge reachable.
	resp, err := client.Get(o.Edge.URL + "/healthz")
	switch {
	case err != nil:
		add(Check{"edge reachable", CheckFail, err.Error(), "check the URL, that the edge is running (descles edge up), and that this machine can reach it"})
		return out
	case resp.StatusCode != http.StatusOK:
		resp.Body.Close()
		add(Check{"edge reachable", CheckFail, fmt.Sprintf("/healthz answered HTTP %d", resp.StatusCode), "a 503 means the policy lease expired or local metering failed: see the edge logs"})
		return out
	default:
		resp.Body.Close()
		add(Check{"edge reachable", CheckOK, o.Edge.URL, ""})
	}

	// 2. Agent key accepted.
	connectors, err := o.Edge.Connectors(ctx)
	if err != nil {
		add(Check{"agent key accepted", CheckFail, err.Error(), "use the agent key from `descles edge init` (standalone) or the control plane; re-run `descles connect`"})
		return out
	}
	add(Check{"agent key accepted", CheckOK, fmt.Sprintf("connectors: %s", strings.Join(connectors, ", ")), ""})

	// 3. Tool policy reachable.
	v, err := o.Edge.Check(ctx, "doctor", "Read", map[string]any{"file_path": "README.md"}, "")
	if err != nil {
		add(Check{"tool-check", CheckFail, err.Error(), "the edge rejected /v1/tool-check: check the edge version and logs"})
	} else {
		add(Check{"tool-check", CheckOK, fmt.Sprintf("a read of README.md is %s (%s)", v.Decision, v.Tool), ""})
	}

	// 4. Trace linkage, end to end (needs the edge admin token).
	if o.AdminToken == "" {
		add(Check{"trace linkage", CheckSkip, "pass --admin-token-file to verify that records carry your trace and playbook ids", ""})
	} else {
		add(traceRoundTrip(ctx, o))
		add(approvalSweepCheck(ctx, o))
	}

	// 5. Claude Code.
	out = append(out, claudeChecks(o)...)
	// 6. Codex.
	out = append(out, codexCheck(o))
	// 7. Environment that would bypass the edge.
	for _, name := range []string{"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"} {
		if v := os.Getenv(name); v != "" && !strings.HasPrefix(v, o.Edge.URL) {
			add(Check{"environment", CheckWarn, fmt.Sprintf("%s=%s in this shell points somewhere other than the edge", name, v), "unset it in the shells where agents run, or they may bypass the edge"})
		}
	}
	return out
}

// approvalSweepCheck reads /admin/info: expired approval arguments must be
// erasable, so a failing sweep is reported rather than silent.
func approvalSweepCheck(ctx context.Context, o DoctorOptions) Check {
	const name = "approval erasure"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, o.Edge.URL+"/admin/info", nil)
	req.Header.Set("Authorization", "Bearer "+o.AdminToken)
	resp, err := o.Edge.client().Do(req)
	if err != nil {
		return Check{name, CheckFail, err.Error(), ""}
	}
	defer resp.Body.Close()
	var info struct {
		Sweep *struct {
			Interval  string `json:"interval"`
			LastError string `json:"last_error"`
			Failures  int    `json:"consecutive_failures"`
		} `json:"approval_sweep"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&info) != nil || info.Sweep == nil {
		return Check{name, CheckSkip, "this edge does not report its expiry sweep", "update the edge"}
	}
	if info.Sweep.Failures > 0 {
		return Check{name, CheckFail, fmt.Sprintf("the expiry sweep failed %d times in a row: %s", info.Sweep.Failures, info.Sweep.LastError),
			"expired approval arguments are not being erased: check the approvals database volume (disk full, permissions) and the edge log"}
	}
	return Check{name, CheckOK, "expired approval arguments are swept every " + info.Sweep.Interval, ""}
}

func traceRoundTrip(ctx context.Context, o DoctorOptions) Check {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	trace := "doctor-" + hex.EncodeToString(b)
	playbook := "doctor-check"
	err := o.Edge.Report(WithPlaybook(WithTrace(ctx, trace), playbook), "doctor", "Read", "ok", "")
	if err != nil {
		return Check{"trace linkage", CheckFail, err.Error(), "the edge rejected /v1/tool-report"}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, o.Edge.URL+"/admin/traces/"+trace, nil)
	req.Header.Set("Authorization", "Bearer "+o.AdminToken)
	var body struct {
		Records []struct {
			Tool     string `json:"tool"`
			Playbook string `json:"playbook_version"`
		} `json:"records"`
	}
	for i := 0; i < 10; i++ {
		resp, err := o.Edge.client().Do(req.Clone(ctx))
		if err != nil {
			return Check{"trace linkage", CheckFail, err.Error(), ""}
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return Check{"trace linkage", CheckFail, fmt.Sprintf("admin API answered HTTP %d", resp.StatusCode), "use the admin token from config/secrets/admin-token; approvals (and the admin API) need DESCLES_EDGE_ADMIN_TOKEN on the edge"}
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if len(body.Records) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(body.Records) == 0 {
		return Check{"trace linkage", CheckFail, "a test record sent with a trace id was not found under it", "the edge and the hooks disagree on the trace header; update both to the same release"}
	}
	if body.Records[0].Playbook != playbook {
		return Check{"trace linkage", CheckWarn, "records carry the trace id but not the playbook version", "update the edge: it does not record X-Descles-Playbook-Version yet"}
	}
	return Check{"trace linkage", CheckOK, "a test record came back under its trace id with its playbook version (" + trace + ")", ""}
}

func claudeChecks(o DoctorOptions) []Check {
	path := o.ClaudeSettings
	if path == "" {
		path = filepath.Join(o.Home, ".claude", "settings.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return []Check{{"claude code", CheckSkip, "no " + path, "run `descles connect claude-code` if agents here use Claude Code"}}
	}
	var s struct {
		Env          map[string]string `json:"env"`
		APIKeyHelper string            `json:"apiKeyHelper"`
		Hooks        map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return []Check{{"claude code settings", CheckFail, path + ": " + err.Error(), "fix the JSON, then re-run `descles connect claude-code`"}}
	}
	var out []Check
	want := o.Edge.URL + "/anthropic"
	if got := s.Env["ANTHROPIC_BASE_URL"]; got != want {
		out = append(out, Check{"claude code model traffic", CheckFail, fmt.Sprintf("ANTHROPIC_BASE_URL is %q, not %q", got, want), "re-run `descles connect claude-code --edge " + o.Edge.URL + "`"})
	} else {
		out = append(out, Check{"claude code model traffic", CheckOK, "goes to " + want, ""})
	}
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		found := false
		for _, e := range s.Hooks[event] {
			for _, h := range e.Hooks {
				if strings.Contains(h.Command, " hook claude-code ") && strings.Contains(h.Command, o.Edge.URL) {
					found = true
				}
			}
		}
		if found {
			out = append(out, Check{"claude code " + event + " hook", CheckOK, "installed", ""})
		} else {
			out = append(out, Check{"claude code " + event + " hook", CheckFail, "no Descles hook for this edge", "re-run `descles connect claude-code`; without it shell and file tools are not checked"})
		}
	}
	switch {
	case s.APIKeyHelper == "":
		out = append(out, Check{"claude code key", CheckWarn, "no apiKeyHelper", "re-run `descles connect claude-code` so the key is not stored in settings"})
	case o.GOOS == "windows" && strings.HasPrefix(s.APIKeyHelper, "'"):
		// Found in a live run: cmd.exe cannot run a single-quoted path.
		out = append(out, Check{"claude code key", CheckFail, "apiKeyHelper uses single quotes, which cmd.exe cannot run on Windows", "update descles and re-run `descles connect claude-code`"})
	default:
		keyFile := o.KeyFile
		if _, err := os.Stat(keyFile); keyFile != "" && err != nil {
			out = append(out, Check{"claude code key", CheckFail, "key file " + keyFile + " missing", "re-run `descles connect claude-code --key <agent key>`"})
		} else {
			out = append(out, Check{"claude code key", CheckOK, "apiKeyHelper set; key not stored in settings", ""})
		}
	}
	if pv := s.Env["DESCLES_PLAYBOOK_VERSION"]; pv == "" {
		out = append(out, Check{"claude code playbook version", CheckWarn, "not set", "add --playbook-version to `descles connect` so evaluations can compare configurations"})
	} else {
		out = append(out, Check{"claude code playbook version", CheckOK, pv, ""})
	}
	return out
}

func codexCheck(o DoctorOptions) Check {
	path := o.CodexConfig
	if path == "" {
		path = filepath.Join(o.Home, ".codex", "config.toml")
	}
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), codexBegin) {
		return Check{"codex", CheckSkip, "no Descles block in " + path, "run `descles connect codex` if agents here use Codex"}
	}
	if !strings.Contains(string(raw), `base_url = "`+o.Edge.URL+`/v1"`) {
		return Check{"codex", CheckFail, "the Descles block points at a different edge", "re-run `descles connect codex --edge " + o.Edge.URL + "`"}
	}
	if os.Getenv("DESCLES_AGENT_KEY") == "" {
		return Check{"codex", CheckWarn, "configured, but DESCLES_AGENT_KEY is not set in this shell", `export DESCLES_AGENT_KEY="$(descles key)" before running codex --profile descles`}
	}
	return Check{"codex", CheckOK, "profile descles goes to " + o.Edge.URL + "/v1 (built-in shell is not pre-checked by the edge)", ""}
}
