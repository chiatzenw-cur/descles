# Connect any agent to your Descles edge

Keep the agents your teams already use: Claude Code, Codex, Hermes, or your own SDK agents. Point them at
the Descles edge in your network and they all get one identity model, one policy, one budget and one
audit trail. Provider keys stay on the edge ([what goes where](DATA-FLOWS.md)). Each developer holds only an **agent
virtual key**, which the edge can revoke.

```bash
go install github.com/chiatzenw-cur/descles/cmd/descles@latest
```

## 0. Stand up an edge (once per network)

```bash
descles edge init --dir acme-edge          # interactive; --yes plus flags for CI
# put the provider key in acme-edge/config/secrets/anthropic-key (and/or openai-key)
descles edge up --dir acme-edge            # docker compose up + health check
```

`edge init` only writes files: `edge.env`, `compose.yml`, `config/policy.yaml`, `config/edge-mcp.yaml`
and empty secret placeholders (`--org-context` adds organization-context config for the enterprise edge
image). Review them and commit them to your own
infra repo (secrets and data are git-ignored), or translate them to Helm/Terraform. It deploys nothing
and never sees a credential.

- `--mode standalone` (default): no Descles cloud at all. Agent keys are generated locally and stored as
  hashes in `config/keys.json`, and nothing is reported anywhere (`DESCLES_EDGE_REPORT_URL=off`).
- `--mode hosted`: pulls the signed policy and agent grants from your Descles control plane and reports
  metadata only. Pass `--control-plane`, `--org` and `--bundle-key` (the key must come from a trusted
  channel).
- The generated compose file marks an unpinned image. Pin it by digest before production.
  `Dockerfile` builds the edge-only image (no control-plane code) if you build your own.

## What each harness gets

| | Claude Code | Codex CLI | Hermes / OpenAI-compatible agents |
|---|---|---|---|
| Model traffic → routing, budgets, audit | ✅ `/anthropic` | ✅ `/v1` (responses) | ✅ `/v1` (chat, responses) |
| Edge MCP connectors (and extensions such as enterprise `org` context) | ✅ | ✅ | ✅ (configure the URLs) |
| Model-proposed tool calls checked against policy | ✅ | ✅ | ✅ |
| **Built-in shell / file tools checked before they run** | ✅ PreToolUse hook | ❌ no pre-execution hook | via `/v1/tool-check` if the agent calls it |
| Execution recorded after it runs | ✅ PostToolUse hook | — | via `/v1/tool-report` |

## Claude Code

```bash
descles connect claude-code --edge https://descles.internal --key <agent key>
```

- `--scope user` (default) writes `~/.claude/settings.json`. `--scope project` writes
  `.claude/settings.local.json`, which is not committed. The previous file is kept as `.bak`. Your
  own settings and hooks are preserved, and re-running replaces only the Descles entries.
- Model traffic goes through the edge (`ANTHROPIC_BASE_URL`). The key is supplied by
  `apiKeyHelper` → `descles key`, so it never sits in a settings file; it is stored in
  `~/.descles/agent-key` with mode 0600.
- Edge MCP connectors are registered with `claude mcp add` (stored in your local Claude config, not the
  repo).
- Every tool call runs the `descles hook` first:

| Edge decision | What Claude Code does |
|---|---|
| `allow` | Nothing extra: Claude Code's own permission rules still apply. The edge can only tighten them. |
| `require_approval` | Asks you (`permissionDecision: ask`). You are the approver. |
| `deny` | Blocks the tool and tells the model why. |
| edge unreachable | Blocks (fail-closed). `DESCLES_HOOK_FAIL_OPEN=1` or `--fail-open` allows instead. |

Use `--dry-run` to see the exact changes first.

## Codex CLI

```bash
descles connect codex --edge https://descles.internal --key <agent key> [--model <model>]
export DESCLES_AGENT_KEY="$(descles key)"
codex --profile descles
```

This adds a managed block to `~/.codex/config.toml`: a `descles` model provider (`wire_api =
"responses"`), a `descles` profile, and one MCP server per edge connector. Everything outside the block
is left alone. Codex has no pre-execution hook, so **its built-in shell is not checked by the edge**.
Keep Codex's sandbox on, and expose sensitive systems (prod DBs, cloud, payments) only through edge
MCP connectors, where every call is enforced.

## Hermes and other OpenAI-compatible agents

```bash
descles connect openai --edge https://descles.internal --key <agent key>
```

This prints the base URL, the MCP server URLs and the tool-check contract. It does not edit any file,
because config formats vary by agent. An agent that runs its own tools can call:

```http
POST /v1/tool-check   {"client":"hermes","tool":"terminal","input":{"command":"..."}}
→ {"decision":"allow|deny|require_approval","tool":"local.bash","reason":"..."}
POST /v1/tool-report  {"client":"hermes","tool":"terminal","outcome":"ok|error"}
```

## Human approvals on the edge

Policy can mark a tool `require_approval` (for example `stripe.create_refund`). On an MCP call to it, the
edge does not execute. It records a request and tells the agent an approval id. A person decides at
`http://<edge>/admin/`, or:

```bash
descles approvals list --edge http://127.0.0.1:8081 --admin-token-file my-edge/config/secrets/admin-token
descles approvals approve apr_... --by alice --reason "ticket 42" --edge ... --admin-token-file ...
```

The approval covers **one execution of exactly that call**: the same agent, tool and arguments (by
canonical digest), within 15 minutes of the decision. Changed arguments, a second run or a late retry need
a new approval. Grants and policy are checked again when the approved call runs, so revoking the agent
still stops it. Arguments are shown only from the edge and erased once the approval closes.

For Claude Code's native tools, `require_approval` becomes Claude Code's own permission prompt: the
person at the keyboard approves.

## One policy for every harness

Tool names are normalized, so one rule covers Claude Code's `Bash`, Codex's `shell` and Hermes's
`terminal`:

| Normalized | From | Args available to rules |
|---|---|---|
| `local.bash` | Bash, shell, exec_command, terminal | `command` |
| `local.write` | Edit, MultiEdit, Write, apply_patch | `path` |
| `local.read` | Read, Glob, Grep, LS | `path`, `pattern` |
| `local.web` | WebFetch, WebSearch | `url`, `query` |
| `mcp.<server>.<tool>` | MCP servers not routed through the edge | tool arguments |

```yaml
defaults:
  require_approval: [local.write]
  arg_tools:
    - {tool: local.bash, args: {command: ["*rm -rf*", "*push --force*", "*kubectl delete*"]}, decision: deny}
    - {tool: local.read, args: {path: ["*.env", "*/secrets/*"]}, decision: deny}
```

With a signed bundle, an agent's grant also caps which tool names it may use at all (`local.*`,
`github.*`, ...).

Shell rules match what the model asks to run. They are guardrails, not a sandbox: an obfuscated command
can slip past a pattern. Keep the harness's sandbox for hard isolation, and put anything that must never
be bypassed behind an edge MCP connector, whose credential the agent never holds.

## What leaves your network

For every checked or executed tool the edge reports one metadata record: `kind=tool`, the normalized
tool name, the decision, the outcome, the timing and the session as trace id. Commands, paths, file
contents and results are not reported.
