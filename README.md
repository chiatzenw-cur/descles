# Descles edge

**Run your AI agents through a gateway you control, in your own network.**

Your teams already use Claude Code, Codex, Hermes and in-house agents. The Descles edge puts all of them
behind one gateway that you run. Provider keys and tool credentials stay on it, every model and tool call
is checked against your policy, and everything is recorded locally. This repository is the open-source
edge, published so you can check exactly what it does with your data. See
[docs/DATA-FLOWS.md](docs/DATA-FLOWS.md).

```
Claude Code ─┐                          ┌─▶ Anthropic / OpenAI / any OpenAI-compatible model
Codex ───────┼─▶   Descles edge   ──────┤
Hermes ──────┤   keys · policy ·        └─▶ your MCP servers (GitHub, Stripe, internal)
your agents ─┘   audit · budgets
```

## What it does

- **Model gateway**: OpenAI-compatible (`/v1/chat/completions`, `/v1/responses`) and Anthropic
  (`/anthropic/v1/messages`), with streaming, routing and per-agent budgets. Egress is limited to the
  providers you configure.
- **Governed MCP**: agents call `POST /mcp/<connector>`. Each tool call is checked against policy and
  executed with a credential only the edge holds. Agents never see it.
- **Native tools too**: Claude Code hooks send shell and file tools to `POST /v1/tool-check` before they
  run, so one policy covers `rm -rf`, `git push --force` and reading `.env` in every harness.
- **Local audit**: every decision and execution is recorded on the edge. Tool input and prompts are not
  stored.
- **Trace format**: `pkg/trajectory` is the open schema for agent runs, so what your agents did stays
  readable and portable.

## Quick start

```bash
go install github.com/chiatzenw-cur/descles/cmd/descles@latest

descles edge init --dir my-edge                 # config, policy, compose file, secret placeholders
echo "$ANTHROPIC_API_KEY" > my-edge/config/secrets/anthropic-key
descles edge up --dir my-edge                   # docker compose up + health check

descles connect claude-code --edge http://127.0.0.1:8081 --key <agent key printed by init>
```

See [docs/CONNECT-AGENTS.md](docs/CONNECT-AGENTS.md) for Codex, Hermes and other agents, and for the
tool names policies match on.

## Standalone or managed

- **Standalone** (`DESCLES_EDGE_REPORT_URL=off`): no connection to Descles at all. Keys are stored as
  hashes in a file, and policy is a YAML file.
- **Managed**: the edge pulls a signed, time-leased policy and agent-grant bundle from a Descles control
  plane and reports only the metadata fields listed in [DATA-FLOWS.md](docs/DATA-FLOWS.md). A test keeps
  that list and the code identical.

Descles' commercial offering (central identity and policy across teams, approvals, SSO, organization
context, learning from agent runs, compliance) plugs into this edge through `pkg/edge/extension.go` and
the managed-edge protocol. It is not part of this repository.

## Layout

| Path | What |
|---|---|
| `cmd/edge` | The edge server |
| `cmd/descles` | Developer CLI: `edge init`/`up`, `connect`, harness hooks |
| `pkg/edgeapp` | Edge wiring and startup |
| `pkg/proxy`, `pkg/provider`, `pkg/translate` | Model gateway |
| `pkg/edge` | Keys, signed bundles, grants, MCP gateway, tool-check, outbound metadata |
| `pkg/policy` | Policy engine |
| `pkg/trajectory` | Open trace format |

## License

[Elastic License 2.0](LICENSE). You may use, modify and self-host this edge, including in production and
inside commercial products. You may not offer it to third parties as a hosted or managed service.

Copyright 2026 the Descles authors.
