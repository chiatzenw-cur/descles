# Where your data goes

Descles processes agent traffic inside your environment. This page lists every kind of data the edge
handles, where it is sent, and what it keeps. The claim is not that Descles never touches your data:
a gateway has to read requests to route and govern them. The claim is that **business content is
processed in your environment, and exactly what goes to your model providers and what goes to a
Descles control plane is listed here and checkable in the code**.

Standalone edges (`DESCLES_EDGE_REPORT_URL=off`) send nothing to Descles.

## Data the edge handles

| Data | Goes to | Kept on the edge | Sent to Descles |
|---|---|---|---|
| Provider API keys | Only the configured provider, in the request header | In memory, read from a local file | Never |
| Prompts and model responses | Only the provider you configured. Egress to any other upstream is refused. The edge does **not** redact prompts. | Not stored | Never |
| MCP connector tokens | Only that connector's URL | In memory, read from a local file | Never |
| MCP tool arguments and results | Only the connector's MCP server, then back to the agent | Not stored by the open-core edge. Extensions (enterprise organization context) may store claims extracted from results. | Never |
| Native tool input from harness hooks (shell commands, file paths) | The edge's `/v1/tool-check`, used for the policy decision | Not stored. Only the normalized tool name and the decision are recorded. | Never |
| Tool evidence in model requests (tools the model called and their results) | — | Tool name, resource (file path or URL), operation, result length and SHA-256. The first ~180 characters of the result are kept only when `DESCLES_LOG_PAYLOADS=true`. | Never |
| Arguments of calls that need a human approval | The approver's browser or CLI, from the edge's `/admin/` (your network) | In the local approvals database while pending or approved; erased when the approval is used or denied, and within about one minute of expiry when database writes succeed (failures are logged and exposed in admin info; swept at startup and every minute; never shown after expiry; SQLite `secure_delete` overwrites them in the file, but backups or volume snapshots you took earlier keep what they captured). The SHA-256 digest, tool, agent, approver name and times remain. | Never |
| Approval notifications (optional) | The webhook the edge admin configures (e.g. Slack) | — | Never. The notice carries the tool name, agent id, approval id, argument digest and a link to `/admin/`. Arguments are included only with `DESCLES_EDGE_APPROVAL_WEBHOOK_ARGS=true` |
| Playbook/config version (`X-Descles-Playbook-Version`) | Recorded with local model and tool records, for evaluation grouping | Yes, as a label restricted to letters, digits and `._-:@+/` | Never (not part of the metadata contract) |
| Agent virtual keys | Developer machine → your edge | SHA-256 hash only | Hash only, in managed mode, where the control plane issued the key |
| Process logs (stdout) | Wherever you ship logs | Method, path, status, trace header, duration, error messages. No request or response bodies. | Never |

## What a managed edge sends to Descles

Metadata only, from `pkg/edge/metadata.go`. The hosted ingest rejects any field not in this list, and a
test fails if this list and the code disagree:

<!-- metadata-fields:begin -->
- `edge_id`: your edge's configured id
- `span_id`: random id of the record
- `trace_id`: one-way hash of the local trace id (the raw id, which may be a harness session id, stays on the edge)
- `kind`: empty for a model call, `tool` for a tool call
- `tool`: a tool your MCP server declared in `tools/list` (for example `github.create_issue`), an extension's own tool, or a local tool class (`local.bash`, `local.write`, `local.read`, `local.web`). Any other name an agent sends is reported as `<connector>.other`, `local.other` or `mcp.other`.
- `agent_id`, `user_id`: the ids your control plane issued
- `model`, `provider`: only names on the edge's approved list are reported: the public model ids in the built-in price table, exact model names in your provider config, `DESCLES_EDGE_REPORT_MODELS`, and your configured provider names. Anything else is reported as `other`.
- `status`: `ok`, `error` or `cancelled`
- `policy_decision`: `allow`, `deny`, `require_approval` or `rate_limit`
- `input_tokens`, `output_tokens`, `cached_tokens`, `usage_known`: token counts as reported by the provider
- `tool_calls_requested`: how many tool calls the model proposed
- `cost_usd`, `cost_source`: estimated cost and how it was computed
- `started_at`, `ended_at`: timing
<!-- metadata-fields:end -->

Things to know about these fields:

- **Field names alone do not keep content out.** A client chooses the model name and tool name it sends,
  so both are mapped to approved identifiers before they leave; the original stays in the local record.
- **Connector ids are yours.** A connector you name `acme-payroll` appears as `acme-payroll.export`
  (declared tools) or `acme-payroll.other`. Choose connector ids with that in mind.
- **Not a covert-channel guarantee.** Timing, call counts and token counts still leave a managed edge.
  A customer that must rule out every side channel should run the edge standalone.

## What Descles sends to a managed edge

A signed, time-leased bundle: your policy, and for each agent its key hash, agent and user ids, group
name, permission pattern, resource, daily budget, allowed providers and context labels. Your admins
entered these in the control plane, so they are already held there. The edge verifies the signature
against a public key you pin, and stops serving when the lease expires.

## How to check

- Read `pkg/edge/metadata.go` (`Metadata`, `Validate`) and `pkg/edge/outbox.go` (`Reporter`): the only
  code that sends anything to Descles.
- Read `pkg/edgeapp/edgeapp.go`: egress to model providers is limited to the origins you configured.
- Run `go test ./pkg/edge -run DataFlow`: it checks this page against the code, and checks that tool
  input and trace ids do not leave the edge.
- Watch the edge's network traffic: in standalone mode it connects only to your providers and MCP
  servers.

Signed images, SBOMs and reproducible builds show where a binary came from and what it contains. They
do not prove its behaviour. That comes from reading the code above and observing its traffic.
