# Customer-hosted edge console

The standalone edge serves its own web console at `http://127.0.0.1:8081/admin/`. The edge is the server; no Descles cloud account or AWS instance is involved. Keep it on loopback for a single-machine setup, or put customer-managed TLS and access controls in front before opening it to a network.

## First-time setup

1. Install the `descles` CLI and a container runtime with Docker Compose support.
2. Run `descles edge init --dir my-edge --mode standalone`. Save the agent key printed once. The command also creates `my-edge/config/secrets/admin-token`.
3. Run `descles edge up --dir my-edge` and wait for `edge healthy`.
4. Open `http://127.0.0.1:8081/admin/` and paste the **admin token**, not the agent key. The token stays in the browser tab's session storage.
5. Open **Providers** and enter your model provider's name, base URL, API key, and optional model patterns. You can leave the generated provider secret placeholder empty and add its key here instead.
6. Open **Teams** if you want group policy, then **Agents & keys** to issue a key. Copy the key before closing its dialog; the edge retains only its hash.
7. Connect an agent with `descles connect openai --edge http://127.0.0.1:8081 --key <agent-key>` or use the Claude Code/Codex instructions in [CONNECT-AGENTS.md](CONNECT-AGENTS.md).

The **Overview**, **Model traces**, **Tool traces**, **Audit**, and **Approvals** pages populate as traffic reaches the edge. **Policy** shows the active rules, lets you test a tool call, and lets a standalone administrator save a new YAML/JSON policy. New policy, provider, team, and key changes take effect without restarting. The edge persists console-managed state under `my-edge/data/`; back up that directory and the deployment's `config/secrets/` directory.

Provider keys saved in the console are encrypted at rest using a key derived from the edge admin token. Keep the admin token separately from backups of `data/`. Changing that token requires re-entering console-managed provider keys before the edge can start. Provider keys from `edge.env` remain in their existing secret files; saving the same provider name in the console overrides the environment entry, and removing the override restores it.

**Audit** combines recent model/tool spans, approval records, and a local configuration-change history. The configuration history is not tamper-evident and does not provide per-person attribution: standalone mode has one shared edge admin token. The paid customer-hosted Team control plane provides individual identities and wider governance across edges.

The navigation also includes **Data integration**, **Organization context**, **Trace mining**, and **Deterministic workflows**. On the free edge these pages show contact links for premium and the free design-partner pilot; they do not expose premium data or operations. On a licensed premium edge, Data integration shows source-sync status and lets an administrator run a configured source sync immediately. Organization context searches cited entities, labels and conflicts, and records an administrator finding with explicit clearance labels. Trace mining selects local tool traces and creates an inert draft. Deterministic workflows lets an administrator inspect that draft, bind inputs, record an explicit approval or rejection, and run an approved plan under a separately entered agent key. Runs stop on failures, and a held tool call waits for a decision in **Approvals**. The agent key is used for that run and is not saved by the console.

The premium workflow library is stored under the premium edge's organization-context data directory. Drafts cannot execute until their review digest matches the plan. Source tool and extractor definitions still come from the customer-managed `orgctx-extractors.yaml`; the console shows their status and can trigger a configured sync. The premium API requires the local admin token and a current offline signed license with the relevant `org_context` or `learning` feature.

On a managed Team edge, the full workspace is at `/` and uses the customer control-plane token; `/admin/` uses the separate local edge admin token for local administration and premium operations. The **Upgrade plan** page includes a design-partner contact.
