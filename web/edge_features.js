"use strict";
// Customer-edge pages. Premium operations use the edge's separate local admin
// token; the local console provides mining, review and execution in the GUI.
const edgeTokenKey = "descles-edge-admin";
const edgeToken = () => sessionStorage.getItem(edgeTokenKey) || "";
const edgeConnect = () => {
  const value = prompt("Edge admin token (from config/secrets/admin-token)") || "";
  if (value.trim()) sessionStorage.setItem(edgeTokenKey, value.trim());
  return !!value.trim();
};
async function edgeAPI(path) {
  const response = await fetch(path, {headers: {Authorization: "Bearer " + edgeToken()}});
  if (response.status === 401) {
    sessionStorage.removeItem(edgeTokenKey);
    throw Error("Edge admin token rejected. Connect again with the token from this edge.");
  }
  if (response.status === 402) throw Error("The organization context subscription has expired on this edge.");
  if (!response.ok) throw Error(`Edge request failed (${response.status}).`);
  return response.json();
}
const edgeGate = () => `<section class="card"><h2>Connect this edge</h2><p>These records stay on the customer edge. Enter its local admin token to inspect source sync, context and tool traces. The Team workspace token is separate.</p><button data-edge-connect>Connect edge</button></section>`;
const edgeUnavailable = () => `<section class="card"><h2>Organization context is not installed</h2><p>Source sync and unified context require a premium edge with the <code>org_context</code> license feature. The free edge and Team control plane continue to work without it.</p><a href="/admin/#plans">See upgrade options ↗</a></section>`;
async function contextReady() {
  if (!edgeToken()) return false;
  const panels = await edgeAPI("/admin/panels");
  return (panels.panels || []).some(panel => panel.id === "context");
}
function edgeError(error) {
  return `<section class="error-panel"><h2>Edge unavailable</h2><p>${esc(error.message)}</p><button data-edge-connect>Reconnect edge</button></section>`;
}

async function integrationsView() {
  if (!edgeToken()) return edgeGate();
  try {
    if (!(await contextReady())) return edgeUnavailable();
    const sync = await edgeAPI("/admin/context/sync");
    const rows = sync.tools || [];
    return `<div class="note">Configured source tools run through this edge's MCP connectors. Results are mapped to cited claims by <code>config/orgctx-extractors.yaml</code>; provider and connector credentials remain on the edge. <a href="/admin/#integrations">Manage source sync on this edge ↗</a></div>
      <section class="card table-card"><div class="card-head"><h2>Source sync</h2>${pill(sync.configured ? "Configured" : "Not configured", sync.configured ? "ok" : "warn")}</div>
      ${rows.length ? table(["Source tool", "Last run", "Pages", "Claims", "Result"], rows.map(row => `<tr><td>${esc(row.tool)}</td><td>${esc(date(row.last_run))}</td><td>${num(row.pages)}</td><td>${num(row.claims)}</td><td>${row.error ? pill(row.error, "err") : pill("Completed", "ok")}</td></tr>`)) : empty(sync.configured ? "Waiting for a source run" : "No source sync configured", sync.configured ? "Refresh after the first scheduled run." : "Add sync entries and extractors to config/orgctx-extractors.yaml, then restart the premium edge. Context can also grow from governed agent tool results when learning is enabled.")}</section>
      <section class="card"><h2>What is ingested?</h2><p>Each mapped tool result creates claims with a source, asserting identity, observed time and labels. Open Unified context to inspect the resolved entity and any conflicting claims.</p><a href="#context">Explore unified context ↗</a></section>`;
  } catch (error) { return edgeError(error); }
}

async function unifiedContextView() {
  if (!edgeToken()) return edgeGate();
  try {
    if (!(await contextReady())) return edgeUnavailable();
    return `<div class="note">Search the permission-aware entity graph on this edge. The local admin token can see all labels; enter labels below to preview what a restricted agent would see. <a href="/admin/#context">Manage context findings on this edge ↗</a></div>
      <section class="card"><h2>Find an entity</h2><div class="filters"><input id="context-query" aria-label="Search context" placeholder="Customer, person, email or system ID"><input id="context-labels" aria-label="Preview clearance labels" placeholder="Preview labels (optional)"><button data-context-search>Search</button></div><p class="muted">Identity keys unify records deterministically. Conflicting source claims remain visible and the selected value keeps its provenance.</p></section><div id="context-results"></div>`;
  } catch (error) { return edgeError(error); }
}
async function contextSearch() {
  const query = $("context-query").value.trim();
  const target = $("context-results");
  if (!query) { target.innerHTML = '<section class="card">Enter a search term.</section>'; return; }
  const labels = $("context-labels").value.trim();
  target.innerHTML = '<div class="loading">Searching this edge…</div>';
  try {
    const params = new URLSearchParams({q: query});
    if (labels) params.set("labels", labels);
    const result = await edgeAPI("/admin/context/search?" + params);
    target.innerHTML = `<section class="card table-card"><div class="card-head"><h2>Visible entities</h2></div>${result.hits?.length ? table(["Kind", "Name", "ID"], result.hits.map(hit => `<tr><td>${esc(hit.kind)}</td><td><button class="text-button" data-context-entity="${esc(hit.id)}">${esc(hit.name || hit.id)}</button></td><td>${esc(hit.id)}</td></tr>`)) : empty("No visible matches", "Try another identifier or preview clearance.")}</section>`;
  } catch (error) { target.innerHTML = edgeError(error); }
}
async function contextEntity(id) {
  const labels = $("context-labels")?.value.trim() || "";
  const params = labels ? "?labels=" + encodeURIComponent(labels) : "";
  try {
    const result = await edgeAPI("/admin/context/entity/" + encodeURIComponent(id) + params);
    const entity = result.entity;
    const facts = entity.attributes || [];
    const factRows = facts.map(attribute => `<tr><td>${esc(attribute.predicate)}${attribute.conflicts?.length ? " " + pill(attribute.conflicts.length + " conflict(s)", "warn") : ""}</td><td>${esc(JSON.stringify(attribute.fact.value ?? attribute.fact.ref ?? ""))}</td><td>${esc(attribute.fact.source)}</td><td>${esc(attribute.fact.asserter)}</td><td>${esc(date(attribute.fact.observed_at))}</td><td>${esc((attribute.fact.labels || []).join(", "))}</td></tr>`);
    const conflicts = facts.flatMap(attribute => (attribute.conflicts || []).map(fact => ({predicate: attribute.predicate, fact})));
    const conflictRows = conflicts.map(({predicate, fact}) => `<tr><td>${esc(predicate)}</td><td>${esc(JSON.stringify(fact.value ?? fact.ref ?? ""))}</td><td>${esc(fact.source)}</td><td>${esc(date(fact.observed_at))}</td></tr>`);
    const related = (result.related || []).map(link => `<li>${esc(link.predicate)} → ${esc(link.kind)} ${esc(link.name || link.entity)}</li>`).join("");
    dialog("Unified entity", `<p><strong>${esc(entity.kind)} · ${esc(entity.name || entity.id)}</strong><br>${esc((entity.keys || []).map(key => key.namespace + "=" + key.value).join(" · "))}</p>${facts.length ? table(["Claim", "Selected value", "Source", "Asserted by", "Observed", "Labels"], factRows) : empty("No visible claims", "Try a different clearance preview.")}${conflicts.length ? `<details><summary>${conflicts.length} conflicting source claim(s)</summary>${table(["Claim", "Other value", "Source", "Observed"], conflictRows)}</details>` : ""}${related ? `<details><summary>Related entities</summary><ul>${related}</ul></details>` : ""}<p class="muted">Selected values are resolved by confidence and recency; the other claims stay visible.</p>`);
  } catch (error) { toast(error.message); }
}

async function miningView() {
  if (!edgeToken()) return edgeGate();
  try {
    const data = await edgeAPI("/admin/activity?limit=500&kind=tool");
    const groups = new Map();
    for (const row of data.records || []) {
      if (!row.trace) continue;
      const group = groups.get(row.trace) || {id: row.trace, at: row.at, agent: row.agent, tools: []};
      group.tools.push(row.name || "tool");
      groups.set(row.trace, group);
    }
    const runs = [...groups.values()];
    return `<div class="note">The Learning add-on mines recorded tool names and order from selected traces. The edge does not record tool arguments. A person must bind arguments and approve the draft before any deterministic run. <a href="/admin/#mining">Open the local mining console ↗</a></div>
      <section class="card table-card"><div class="card-head"><h2>Recent tool traces</h2>${pill(runs.length + " trace(s)")}</div>${runs.length ? table(["Select", "Trace", "Agent", "Tool steps"], runs.map(run => `<tr><td><input type="checkbox" class="mine-trace" value="${esc(run.id)}" aria-label="Select trace ${esc(run.id)}"></td><td>${esc(run.id)}<small>${esc(date(run.at))}</small></td><td>${esc(run.agent || "—")}</td><td>${esc(run.tools.join(" → "))}</td></tr>`)) : empty("No tool traces yet", "Route repeated tasks through this edge, with an X-Descles-Trace per task.")}</section>
      <section class="card"><h2>Mine and review in the browser</h2><p>Open the edge console with its local admin token to select traces, create a draft, bind inputs and record a review. The command builder below remains available for automation.</p><a class="cta" href="/admin/#mining">Open trace mining ↗</a><div class="filters"><input id="mine-name" aria-label="Workflow name" placeholder="workflow-name"><button data-build-mine>Build CLI command</button></div><pre id="mine-command" aria-live="polite">Select at least two traces.</pre></section>`;
  } catch (error) { return edgeError(error); }
}
function buildMineCommand() {
  const name = $("mine-name").value.trim();
  const ids = [...document.querySelectorAll(".mine-trace:checked")].map(input => input.value);
  const target = $("mine-command");
  if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(name)) { target.textContent = "Use a lowercase workflow name with letters, digits and hyphens."; return; }
  if (ids.length < 2 || ids.some(id => !/^[a-zA-Z0-9_-]+$/.test(id))) { target.textContent = "Select at least two traces with safe IDs."; return; }
  target.textContent = `descles-loop mine --edge ${location.origin} --admin-token-file <edge-admin-token-file> --trace-ids ${ids.join(",")} --name ${name} --out skill/${name}`;
}

async function workflowsView() {
  let registered = [];
  try { registered = (await api("/skills/")).skills || []; } catch (_) { /* registry may be unavailable */ }
  return `<div class="note">A mined draft is not executable. Review binds every input, approves or rejects the plan, and pins the workflow digest. The runner checks that review before making any tool call; edge policy and approvals still apply. <a href="/admin/#workflows">Open the local workflow console ↗</a></div>
    <div class="grid-two"><section class="card"><h2>1 · Review a draft</h2><p>After mining, inspect <code>SKILL.md</code> and <code>workflow.json</code>. Supply the missing argument bindings in a review file.</p><pre>descles-loop skill review --skill skill/my-workflow --review review.yaml</pre></section><section class="card"><h2>2 · Run deterministically</h2><p>The reviewed straight-line MCP workflow executes without a model. It stops on a failed or unexpected step.</p><pre>descles-loop skill run --skill skill/my-workflow --edge ${esc(location.origin)} --key-file agent-key --input customer_id=...</pre></section></div>
    <section class="card table-card"><div class="card-head"><h2>Registered capabilities</h2><a href="#skills">Open library ↗</a></div>${registered.length ? table(["Capability", "Version", "State", "Source runs"], registered.map(skill => `<tr><td>${esc(skill.name)}</td><td>${esc(skill.current_version)}</td><td>${pill(skill.status, skill.status === "published" ? "ok" : "warn")}</td><td>${num(skill.provenance?.generated_from?.length)}</td></tr>`)) : empty("No capabilities registered", "Local reviewed workflow files are not automatically published to the control-plane registry.")}</section>
    <section class="card"><h2>Measure before adopting</h2><p>Compare success, interventions, completion time and cost on equivalent tasks. The local edge console can mine, review and run workflows in your environment; the <code>descles-loop</code> CLI remains available for automation.</p><a class="cta" href="/admin/#workflows">Open deterministic workflows ↗</a></section>`;
}

pages.integrations = ["⇄", "Data integration", "CUSTOMER-SIDE SOURCES", "Source sync and claim extraction on this edge."];
pages.context = ["◈", "Unified context", "CITED ORGANIZATION KNOWLEDGE", "Search entities, sources, conflicts and clearance labels."];
pages.mining = ["⌁", "Trace mining", "REPEATED RUNS", "Select local tool traces for a reviewed skill draft."];
pages.workflows = ["▤", "Workflows", "DETERMINISTIC EXECUTION", "Review, pin and run a predictable tool procedure."];
loaders.integrations = integrationsView;
loaders.context = unifiedContextView;
loaders.mining = miningView;
loaders.workflows = workflowsView;
buildNav();
navigate();
document.addEventListener("click", event => {
  const button = event.target.closest("[data-edge-connect],[data-context-search],[data-context-entity],[data-build-mine]");
  if (!button) return;
  if (button.hasAttribute("data-edge-connect")) { if (edgeConnect()) load(); return; }
  if (button.hasAttribute("data-context-search")) { contextSearch(); return; }
  if (button.hasAttribute("data-context-entity")) { contextEntity(button.dataset.contextEntity); return; }
  if (button.hasAttribute("data-build-mine")) buildMineCommand();
});
