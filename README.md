# Descles edge

**One gateway for your agents' model calls, MCP tools, policy, approvals, and local audit.** Run it in your own network. Provider keys and MCP credentials stay on the edge; agents use revocable edge keys.

![A Claude Code session has a destructive command denied by the edge](docs/descles-demo.gif)

Descles works with Claude Code, Codex CLI, Hermes Agent, and clients that speak an OpenAI-compatible API. The edge is source-available under [Elastic License 2.0](LICENSE). You can inspect and self-host the free edge without a Descles account or license key.

**New here?** Follow [the first-time setup](#first-time-setup) below. It runs on your own computer and gives you a browser console. You do not need to write code or create a Descles account. You do need a model provider API key; the provider may charge for model use.

**Want to try the Team edition?** We are looking for design partners for a **free, time-limited pilot** of the paid, self-hosted control plane and organization-context features. We will help with setup and use your feedback to shape the product. You bring your own model provider account and machine or infrastructure. [Email us about a pilot](mailto:outreach@descles.com?subject=Descles%20design%20partner%20pilot). The standalone edge in this repository remains free to self-host without joining a pilot.

| Capability | Claude Code | Codex CLI | Hermes Agent | API client |
|---|---|---|---|---|
| Route model calls and record usage | Yes | Yes | Yes | Yes |
| Use edge-hosted MCP connectors | Yes | Yes | Yes | If the client supports MCP |
| Check built-in shell/file calls before execution | Via hooks | No pre-execution hook | Via hooks | Only if integrated with `/v1/tool-check` |
| Human approval for edge MCP calls | At the edge console | At the edge console | At the edge console | At the edge console |

The edge enforces calls that actually pass through it. A model URL change alone does not intercept an agent's built-in tools. Codex has no pre-execution hook, so keep its sandbox enabled and route sensitive operations through edge MCP connectors. Shell pattern rules are guardrails, not a sandbox.

## First-time setup

This walkthrough runs one free edge on your computer. You need:

1. **Docker Desktop**, installed and running. Use Docker's instructions for [Windows](https://docs.docker.com/desktop/setup/install/windows-install/), [Mac](https://docs.docker.com/desktop/setup/install/mac-install/), or [Linux](https://docs.docker.com/desktop/setup/install/linux/). Wait until Docker says its engine is running.
2. A **model provider API key**. For this walkthrough, create one in the [Claude Console](https://platform.claude.com/docs/en/manage-claude/authentication) under **Settings → API keys**. This is separate from a Claude chat subscription. Keep the key private; you will enter it in your own edge console.
3. The **Descles CLI** for your operating system from [Releases](https://github.com/chiatzenw-cur/descles/releases). Under the newest release's **Assets**, choose the file beginning `descles-` (the CLI, not `descles-edge-`) and ending in your OS and CPU type: `windows-amd64.exe` for most Windows PCs, `darwin-arm64` for Apple Silicon Macs, `darwin-amd64` for Intel Macs, or `linux-amd64` for most Linux PCs. Put it in a new folder named `Descles` in your Documents folder. Rename the downloaded file to `descles.exe` on Windows or `descles` on Mac/Linux.

Open a terminal **in that Descles folder**. On Windows, open the folder in File Explorer, right-click empty space, and choose **Open in Terminal**. On Mac/Linux, open Terminal and change to the folder (for example, `cd ~/Documents/Descles`). The `.` at the start of the commands below means “run the file in this folder.” Paste commands one at a time.

**Windows PowerShell:**

```powershell
.\descles.exe edge init --yes --dir my-edge --providers anthropic
```

**Mac or Linux:**

```bash
chmod +x ./descles
./descles edge init --yes --dir my-edge --providers anthropic
```

The command creates a `my-edge` folder and prints an **agent key once**. Copy that key somewhere private. It also creates an admin token in `my-edge/config/secrets/admin-token`.

Start the edge in the same terminal. You can leave the generated provider key placeholder empty and add a provider from the browser console:

```powershell
# Windows
.\descles.exe edge up --dir my-edge
```

```bash
# Mac or Linux
./descles edge up --dir my-edge
```

When you see `edge healthy`, open **[http://127.0.0.1:8081/admin/](http://127.0.0.1:8081/admin/)** in a browser on that computer. Paste the **admin token** from `my-edge/config/secrets/admin-token` when asked. Open **Providers**, enter `anthropic` as the name, `https://api.anthropic.com` as the base URL, `claude-*` as the model pattern, and paste your Claude API key. The key is encrypted in the edge's local data volume using the admin token; it is not returned by list pages. You can also use the original `my-edge/config/secrets/anthropic-key` file instead. See the [console guide](docs/EDGE-CONSOLE.md) for teams, agent keys, policy, traces and storage.

| Secret | Where it comes from | What it is for |
|---|---|---|
| Provider API key | Claude Console | Lets the edge call the model provider; enter it in Providers or the generated local secret file |
| Agent key | Printed once by `edge init` | Lets your agent call the edge; use it with `descles connect` |
| Admin token | `my-edge/config/secrets/admin-token` | Opens the local console and approves calls; do not give it to agents |

To use OpenAI instead of Claude, run `edge init` with `--providers openai`, create an [OpenAI API key](https://platform.openai.com/docs/quickstart/make-your-first-api-request), then enter `openai`, `https://api.openai.com/v1`, and that key on the **Providers** page. For another OpenAI-compatible provider, use its HTTPS base URL and optional model patterns there. To build the CLI from source instead of downloading it, install Go 1.27+ and run `go install github.com/chiatzenw-cur/descles/cmd/descles@latest`.

This local setup publishes port `8081` only to your own computer. Standalone mode sends **no reports to Descles**. Model requests still go to the provider you configure. The edge records decisions and usage, not prompts or model responses; pending approval arguments are stored locally until the approval closes. See [data flows](docs/DATA-FLOWS.md). For a shared production deployment, use your own TLS ingress and access controls, and pin the container image by digest.

## Connect an agent

First install the agent you want to use. Return to the terminal in your `Descles` folder and use the **agent key** printed by `edge init`, not the Claude API key or console admin token. Replace `PASTE_AGENT_KEY_HERE` with your saved agent key. Choose **one** of these commands:

```powershell
# Windows: choose one line
.\descles.exe connect claude-code --edge http://127.0.0.1:8081 --key "PASTE_AGENT_KEY_HERE"
.\descles.exe connect codex       --edge http://127.0.0.1:8081 --key "PASTE_AGENT_KEY_HERE"
.\descles.exe connect hermes      --edge http://127.0.0.1:8081 --key "PASTE_AGENT_KEY_HERE"
.\descles.exe connect openai      --edge http://127.0.0.1:8081 --key "PASTE_AGENT_KEY_HERE"
```

On Mac/Linux, use the same line with `./descles` in place of `.\descles.exe`. `claude-code` writes model, hook, and MCP settings. `codex` writes a model-provider profile and MCP settings; it cannot add a shell pre-execution hook. `hermes` and `openai` print settings for you to copy into those clients. After connecting, make a model or tool call in your agent and refresh **Model traces** or **Tool traces** in the edge console. For exact client settings and limitations, see [Connect agents](docs/CONNECT-AGENTS.md).

Any API client can also use the edge directly. Send the agent key as a bearer token. These are optional checks; replace the placeholder with your saved agent key:

```bash
# Mac or Linux
curl -H "Authorization: Bearer PASTE_AGENT_KEY_HERE" http://127.0.0.1:8081/v1/models
```

```powershell
# Windows PowerShell
curl.exe -H "Authorization: Bearer PASTE_AGENT_KEY_HERE" http://127.0.0.1:8081/v1/models
```

Set an OpenAI-compatible client's base URL to `http://127.0.0.1:8081/v1`, or an Anthropic client's base URL to `http://127.0.0.1:8081/anthropic`. The edge serves `/v1/chat/completions`, `/v1/responses`, `/v1/models`, and `/anthropic/v1/messages`. Choose a model your configured provider serves, or set a model alias on the edge. A client that executes its own tools must call `/v1/tool-check` before execution and `/v1/tool-report` afterward if it wants those actions governed and recorded.

## Policy, tools, and approvals

Edit `my-edge/config/policy.yaml` to set budgets, deny tools, or require a human approval. The generated policy includes examples for destructive shell commands and sensitive files. The console's Policy panel shows the effective rules and lets you check a proposed call. Restart the edge after changing local config files.

Define MCP connectors in `my-edge/config/edge-mcp.yaml`. Their credentials live in local secret files; agents call `POST /mcp/<connector>` with an edge key and never receive the connector credential. `GET /mcp` lists connectors available to that key. The edge applies policy to each mediated call.

When policy requires approval, open the **Approvals** tab at `/admin/`, or use `descles approvals list`, `approve`, and `deny` with the edge admin token. An approval covers one attempt with the same agent, tool, and argument digest before it expires. The edge checks current grants and policy again when the agent retries. The console and its admin API are local to the edge; do not expose them publicly without your own access controls.

## Free edge, paid Team, and design partners

| Option | What you get | Cost from Descles |
|---|---|---|
| **Free edge** | One self-hosted gateway, local console, policy, approvals, and local records | Free; no Descles account or license key |
| **Team** | Customer-hosted control plane for shared identities, grants and policy, plus optional organization context and learning on premium edges | Paid subscription with an offline signed license |
| **Design-partner pilot** | Hands-on help trying Team and shaping its workflow in your own environment | No Descles software fee during an agreed pilot period |

The paid control plane and premium edge run in **your** network. The edge fetches signed policy bundles from your control plane without reporting to Descles. You keep your provider keys, tool credentials and execution records. The pilot does not cover charges from model providers or your own infrastructure. We are especially interested in teams running more than one agent or needing shared approvals, scoped access, or organizational context. [Tell us what you are building](mailto:outreach@descles.com?subject=Descles%20design%20partner%20pilot). See [self-hosted mode in the CLI guide](docs/CONNECT-AGENTS.md) for the technical path.

In Team self-hosted mode, the **full workspace** is served by your edge at `http://127.0.0.1:8081/`, using a customer control-plane admin or organization token to sign in. Management stays on your control plane; usage and traces come from that edge. `/admin/` remains available for local traces, policy inspection and approvals with its separate edge admin token. In free standalone mode, `/admin/` includes provider credentials, teams, agent keys, policy editing and audit/activity views; visiting `/` opens it.

The free edge console shows the premium Data integration, Organization context, Trace mining, and Deterministic workflows pages with contact links for a paid deployment or a free design-partner pilot. In a licensed premium edge, the local console can inspect context and source sync, mine selected local traces into a draft, collect a human review with argument bindings, and run an approved deterministic workflow under an agent key. A draft never executes before review; edge policy and approvals still apply. The `descles-loop` CLI remains available for automation.

## If something does not work

| What you see | What to try |
|---|---|
| `docker not found` or `docker engine is not reachable` | Start Docker Desktop, wait for its engine to finish starting, then run `edge up` again. |
| “Empty secret” or provider authentication failure | Check that `my-edge/config/secrets/anthropic-key` contains your **provider API key** as plain text, with no quotes or `.txt` extension. |
| The browser cannot open the console | Wait for `edge healthy`, then visit `http://127.0.0.1:8081/admin/` on the same computer. A manually started edge also needs an admin token configured. |
| “Wrong admin token” | Use the file `my-edge/config/secrets/admin-token`, not the agent or provider key. |
| Activity is empty | That is normal until you connect an agent and make a call through the edge. |

If you need more detail, open the generated `my-edge/README.md`, run `descles doctor` with your local CLI path, or [contact us](mailto:outreach@descles.com?subject=Descles%20setup%20help).

## Reference

- [Connect Claude Code, Codex, Hermes, and other clients](docs/CONNECT-AGENTS.md)
- [Data flows and outbound boundaries](docs/DATA-FLOWS.md)
- [Verify a release](docs/VERIFY-RELEASE.md)
- [Customer-operated AWS edge template](deploy/aws/README.md) (optional; runs in your account)
- [Security reporting](SECURITY.md)

This repository contains the free edge and CLI, not the paid control plane or license issuer. Under [ELv2](LICENSE), you may use, modify, and self-host the edge, including commercially; you may not offer it to third parties as a hosted or managed service.
