# Descles edge

**Run your AI agents through a gateway you control, in your own network.**

![A real Claude Code session is asked to run rm -rf; the Descles edge denies it before it runs](docs/descles-demo.gif)

*Released binaries, a real Claude Code session and a real model. The denial on screen comes from the edge,
not from the model.*

The Descles edge sits between your agents (Claude Code, Codex, Hermes, your own) and the models and tools
they use. Provider keys and tool credentials stay on the edge, calls are checked against your policy, and
decisions are recorded on the edge. It is open source so you can check exactly what it does with your data:
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

## 2. Managed edge with the Descles control plane

The edge still runs in your network and still holds your provider keys and tool credentials. The Descles
control plane (`https://api.gw.descles.com`, console at [descles.com](https://descles.com)) manages
identities, delegation and policy, and signs a time-limited bundle that the edge pulls about every 30 s.
The edge sends back only the metadata in [DATA-FLOWS](docs/DATA-FLOWS.md). Agents talk to your edge,
never to Descles.

The API calls below authenticate with your console session: `Authorization: Bearer $SESSION`.

### For org admins

1. **Create the organization.** Sign up at [descles.com](https://descles.com). Your org id (`$ORG`) is shown
   in the console.

2. **Deploy the edge.** Create a token that can only fetch bundles and report metadata (it cannot call
   models or change anything), and fetch the key that signs your bundles:

   ```bash
   curl -X POST https://api.gw.descles.com/control/orgs/$ORG/keys \
     -H "Authorization: Bearer $SESSION" -d '{"scopes":["edge.sync","edge.report"]}'
   # → "token": shown once

   curl https://api.gw.descles.com/edge/bundle-key
   # → "public_key": check it against the value shown in the console before pinning it
   ```

   ```bash
   descles edge init --yes --dir acme-edge --mode hosted --providers anthropic \
     --control-plane https://api.gw.descles.com --org $ORG --bundle-key <public_key>
   echo "<token>"            > acme-edge/config/secrets/report-token
   echo "$ANTHROPIC_API_KEY" > acme-edge/config/secrets/anthropic-key
   descles edge up --dir acme-edge
   ```

   Put your internal TLS ingress in front of it (below: `https://descles.internal`). That is the URL your
   members connect to. The edge refuses any bundle not signed by the key you pinned.

3. **Set the policy.** It is written in the same YAML as the standalone `policy.yaml` and is signed into
   every bundle:

   ```bash
   jq -Rs '{raw: .}' policy.yaml | curl -X POST https://api.gw.descles.com/control/policy \
     -H "Authorization: Bearer $SESSION" --data-binary @-
   ```

4. **Invite members.** Each invitation sets a ceiling (the tools the member's agents may use, such as
   `github.*` or `*`, a resource, and a daily budget). Members can delegate only within it.

   ```bash
   curl -X POST https://api.gw.descles.com/control/team/invites -H "Authorization: Bearer $SESSION" \
     -d '{"email":"dev@acme.com","name":"Dev","permission":"*","resource":"*","daily_budget_cents":2000}'
   ```

5. **Operate.**
   - `GET /control/team/members` lists members. `DELETE /control/team/members/{id}` revokes one. Connected
     edges drop a revoked identity at the next refresh. An edge that cannot reach the control plane keeps
     its last bundle until the lease ends (10 minutes by default), then stops accepting calls.
   - Approvals are decided on the edge (`https://descles.internal/admin/`, admin token in
     `acme-edge/config/secrets/admin-token`). Arguments are shown only there.

### For members

1. **Accept the invitation.** Open it and sign in at [descles.com](https://descles.com) with the invited email.

2. **Create a key for your agent**, within the ceiling your admin set. It is shown once:

   ```bash
   curl -X POST https://api.gw.descles.com/control/team/subagents -H "Authorization: Bearer $SESSION" \
     -d '{"name":"laptop-claude","permission":"*","resource":"*","daily_budget_cents":500,"expires_at":"2026-12-31T00:00:00Z"}'
   # → "id"
   curl -X POST https://api.gw.descles.com/control/team/subagents/<id>/key -H "Authorization: Bearer $SESSION"
   # → "key"
   ```

   `GET /control/team/access` shows what your admin granted you.

3. **Connect your agent to your company's edge** (not to Descles):

   ```bash
   descles connect claude-code --edge https://descles.internal --key <key>   # settings, hooks, MCP
   descles connect codex       --edge https://descles.internal --key <key>   # model provider, MCP
   descles connect hermes      --edge https://descles.internal --key <key>   # prints settings to paste
   descles doctor --edge https://descles.internal
   ```

   `doctor` checks that the edge is reachable, that your key works, that hooks are installed, and that
   no `ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` in your shell points around the edge. Each
   failure comes with a fix.

4. **Work as usual.** A denied tool shows `Descles: denied` with the reason. A call that needs approval
   returns an approval id. After someone approves it, repeat the same call.

Per-harness details, and the tool names that policies match on: [docs/CONNECT-AGENTS.md](docs/CONNECT-AGENTS.md).

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

The paid Descles offering (the hosted control plane, organization context, evaluation across agent
configurations) builds on this edge through `pkg/edge/extension.go` and the managed-edge protocol. It is not
in this repository.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md) (outreach@descles.com).

## License

[Elastic License 2.0](LICENSE). You may use, modify and self-host this edge, including in production and
inside commercial products. You may not offer it to third parties as a hosted or managed service.

Copyright 2026 the Descles authors.
