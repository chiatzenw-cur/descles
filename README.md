# Descles edge

**Run your AI agents through a gateway you control, in your own network.**

![A real Claude Code session is asked to run rm -rf; the Descles edge denies it before it runs](docs/descles-demo.gif)

*Released binaries, a real Claude Code session and a real model. The denial on screen comes from the edge,
not from the model.*

**Measured:** agents answering from organization context used 69–76% fewer tokens than agents calling
CRM, billing and support themselves, with the same answers and every boundary holding.
[Method, results, limits and raw evidence](docs/benchmarks/ORG-CONTEXT-BENCHMARK.md).

The Descles edge sits between your agents (Claude Code, Codex, Hermes, your own) and the models and tools
they use. Provider keys and tool credentials stay on the edge, calls are checked against your policy, and
decisions are recorded on the edge. Its source is available under ELv2 so you can inspect the code and outbound data contract:
see [docs/DATA-FLOWS.md](docs/DATA-FLOWS.md).

```
Claude Code ─┐                          ┌─▶ Anthropic / OpenAI / OpenAI-compatible models
Codex ───────┼─▶   Descles edge   ──────┤
Hermes ──────┤   keys · policy ·        └─▶ your MCP servers (GitHub, Stripe, internal)
your agents ─┘   approvals · audit
```

## What each integration gets

| | Claude Code | Hermes Agent | Codex CLI | Other OpenAI-compatible agents |
|---|---|---|---|---|
| Model calls routed, budgeted, recorded | yes | yes | yes | yes |
| MCP tools run by the edge with credentials only it holds | yes | yes | yes | yes |
| Built-in shell/file tools checked **before** they run | yes, via hooks | yes, via hooks | no: Codex has no pre-execution hook | only if the agent calls `/v1/tool-check` |
| `require_approval` on MCP tools | waits at `/admin/` | waits at `/admin/` | waits at `/admin/` | waits at `/admin/` |

Limits worth knowing:

- Shell rules match the command the model asks to run. They are guardrails, not a sandbox: an obfuscated
  command can slip past a pattern. Keep the harness's own sandbox, and put anything that must never be
  bypassed behind an MCP connector, whose credential the agent never holds.
- An approval lets the edge forward **one attempt of the exact call** (same agent, tool and argument
  digest, before it expires). It does not make the downstream operation idempotent.
- Only the metadata fields listed in DATA-FLOWS are reported, and label values are limited to names the
  edge knows. That is a field and value policy enforced by tests, not a proof against every side channel.
  For zero reporting, run standalone.
- Records on the edge hold decisions and metadata, not prompts or tool input. The exception is the
  arguments of a call awaiting approval, which are kept on the edge so an approver can review them, and
  erased when the approval closes.

## Install

```bash
go install github.com/chiatzenw-cur/descles/cmd/descles@latest   # CLI: edge init/up, connect, doctor, approvals
```

The edge runs as a container (`ghcr.io/chiatzenw-cur/descles-edge`, pin it by digest) or as the `edge`
binary. Signed binaries are on [Releases](https://github.com/chiatzenw-cur/descles/releases). To check that a
release is what this source builds, see [docs/VERIFY-RELEASE.md](docs/VERIFY-RELEASE.md).

Use the generated Compose file to run the edge on a host you control.

No server of your own? [deploy/aws](deploy/aws/README.md) runs the edge in your AWS account from one
CloudFormation stack, on your domain or on a CloudFront address with no domain needed.

## 1. Standalone edge (no Descles account)

Standalone mode sends no reports to Descles. Requests still reach the model providers and tool servers
you configure. Agent keys are stored as hashes in a file, and policy is a YAML file.

```bash
descles edge init --yes --dir my-edge --providers anthropic   # prints an agent key once; writes config,
                                                              # policy, compose file and an admin token
echo "$ANTHROPIC_API_KEY" > my-edge/config/secrets/anthropic-key
descles edge up --dir my-edge                                 # docker compose up + health check
```

Then connect an agent and check it:

```bash
descles connect claude-code --edge http://127.0.0.1:8081 --key <agent key>
descles doctor --edge http://127.0.0.1:8081 --admin-token-file my-edge/config/secrets/admin-token
```

- **Policy**: `my-edge/config/policy.yaml`. The generated file already denies `rm -rf`, `push --force`,
  `kubectl delete` and reading `.env` files, and marks `stripe.create_refund` as `require_approval`.
- **MCP connectors**: `my-edge/config/edge-mcp.yaml` (or `descles edge init --connector github=https://...`).
- **Approvals**: open `http://127.0.0.1:8081/admin/` with the token in `my-edge/config/secrets/admin-token`,
  or use `descles approvals list | approve <id> | deny <id> --edge ... --admin-token-file ...`.
  To notify approvers, set `DESCLES_EDGE_APPROVAL_WEBHOOK_FILE` in `my-edge/.env` (arguments are not sent).

## 2. Team: your own control plane, one edge for everyone

For a team, the organization runs one edge and one Team control plane, both in its own network. The
control plane manages agent identities and policy and signs a short-lived bundle that the edge pulls;
the edge keeps provider keys, tool credentials and records, and reports nothing to Descles. The Team
control plane and the organization-context edge are paid, delivered as images that verify an offline
signed subscription file. This public edge works without one. [Contact us](mailto:outreach@descles.com).

### For org admins

1. **Run the control plane** behind your internal TLS ingress (below: `https://control.internal`), with
   the delivered `compose.control.yml`, an admin token, a master key and the license file. Then:

   ```bash
   C=https://control.internal; H="Authorization: Bearer $ADMIN_TOKEN"
   curl -H "$H" -d '{"name":"Acme","slug":"acme"}' $C/control/orgs                    # → "id": $ORG
   curl -H "$H" -d '{"scopes":["edge.sync"]}' $C/control/orgs/$ORG/keys               # edge sync token, shown once
   curl $C/edge/bundle-key                                                            # check it over a trusted channel
   ```

2. **Deploy the edge** and point it at the control plane:

   ```bash
   descles edge init --yes --dir acme-edge --mode selfhost --providers anthropic      --control-plane https://control.internal --org $ORG --bundle-key <public_key>
   echo "<sync token>"       > acme-edge/config/secrets/report-token   # legacy name; nothing is reported
   echo "$ANTHROPIC_API_KEY" > acme-edge/config/secrets/anthropic-key
   descles edge up --dir acme-edge
   ```

   Put your TLS ingress in front of it (below: `https://descles.internal`). That is the URL your members
   connect to. The edge refuses any bundle not signed by the key you pinned.

3. **Set the policy.** Same YAML as the standalone `policy.yaml`, signed into every bundle:

   ```bash
   jq -Rs '{raw: .}' policy.yaml | curl -H "$H" --data-binary @- $C/control/policy
   ```

   The edge's own `acme-edge/config/policy.yaml` still applies, as a floor: every decision is the
   stricter of the two and every budget the lower cap. The control plane can tighten what your edge
   enforces but never loosen it, so a rule you must keep belongs in that local file.

4. **Give each member's agent an identity and a key** (shown once), and hand the key over:

   ```bash
   curl -H "$H" -d '{"name":"dev-laptop-claude","kind":"agent"}' $C/control/orgs/$ORG/agents   # → "id"
   curl -H "$H" -d '{}' $C/control/agents/<id>/keys                                          # → "key"
   ```

5. **Operate.** `curl -H "$H" -X POST $C/control/agents/<id>/revoke` disables an agent and expires its
   keys; edges drop it at the next bundle refresh. An edge that cannot reach the control
   plane keeps its last bundle until the lease ends (10 minutes by default), then stops accepting calls.
   Approvals are decided on the edge at `https://descles.internal/admin/` (admin token in
   `acme-edge/config/secrets/admin-token`); arguments are shown only there. If the subscription lapses,
   running agents keep working and revocations, approvals and bundle refreshes continue; only new
   management changes pause until a renewed license file is installed.

### For members

Nobody installs an edge of their own: the organization runs one, and you change an endpoint.

**Endpoint only, nothing to install.** Set the base URL and your agent key, and point MCP clients at
the edge:

```bash
export ANTHROPIC_BASE_URL=https://descles.internal/anthropic   # or OPENAI_BASE_URL=https://descles.internal/v1
export ANTHROPIC_AUTH_TOKEN=<key>
# MCP: https://descles.internal/mcp/<connector>, header Authorization: Bearer <key>
```

**With the `descles` CLI** (a single binary, not a service), shell and file actions are also checked
before they run in Claude Code and Hermes, and the settings are written for you:

```bash
descles connect claude-code --edge https://descles.internal --key <key>   # settings, hooks, MCP
descles connect codex       --edge https://descles.internal --key <key>   # model provider, MCP
descles connect hermes      --edge https://descles.internal --key <key>   # prints settings to paste
descles doctor --edge https://descles.internal
```

`doctor` checks that the edge is reachable, that your key works, that hooks are installed, and that no
`ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` in your shell points around the edge.

A denied tool shows `Descles: denied` with the reason. A call that needs approval returns an approval
id; after someone approves it, repeat the same call. Per-harness details: [docs/CONNECT-AGENTS.md](docs/CONNECT-AGENTS.md).

## Edge endpoints

| Endpoint | For |
|---|---|
| `/v1/chat/completions`, `/v1/responses`, `/v1/models` | OpenAI-compatible agents (`OPENAI_BASE_URL=<edge>/v1`) |
| `/anthropic/v1/messages` | Anthropic-compatible agents (`ANTHROPIC_BASE_URL=<edge>/anthropic`) |
| `POST /mcp/<connector>`, `GET /mcp` | MCP clients. `GET /mcp` lists the connectors your key may use |
| `POST /v1/tool-check`, `POST /v1/tool-report` | Harness hooks, before and after a built-in tool runs |
| `/admin/`, `/admin/approvals`, `/admin/traces/{id}`, `/admin/info` | Approvers and operators (edge admin token) |
| `/healthz` | Load balancers |

Agents authenticate with their key (`Authorization: Bearer <key>`).
The optional headers `X-Descles-Trace` and `X-Descles-Playbook-Version` group records by task and by
configuration (`descles connect claude-code --playbook-version team@1` sets the second).

## Layout

| Path | What |
|---|---|
| `cmd/edge` | The edge server |
| `cmd/descles` | CLI: `edge init`/`up`, `connect`, `doctor`, `approvals`, harness hooks |
| `pkg/edgeapp` | Edge wiring and startup |
| `pkg/proxy`, `pkg/provider`, `pkg/translate` | Model gateway |
| `pkg/edge` | Keys, signed bundles, grants, MCP gateway, tool-check, approvals, outbound metadata |
| `pkg/policy` | Policy engine |
| `pkg/trajectory` | Open trace format |

The paid Descles offering builds on this edge through `pkg/edge/extension.go` and the
signed-bundle protocol. Its source is maintained in a separate private repository.
The premium edge and Team control plane both run in the customer's network. The public
edge is independently buildable and does not require a paid license.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md) (outreach@descles.com).

## License

[Elastic License 2.0](LICENSE). You may use, modify and self-host this edge, including in production and
inside commercial products. You may not offer it to third parties as a hosted or managed service.

Copyright 2026 the Descles authors.
