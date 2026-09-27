package edge

// adminPage is the edge's local console. It talks only to this edge (see the
// Content-Security-Policy set with it) and builds the DOM with textContent,
// never innerHTML, so recorded values cannot inject markup.
const adminPage = `<!doctype html><meta charset="utf-8"><title>Descles edge console</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#fafaf7;--fg:#1d1d1b;--mut:#6b6b66;--line:#e2e1da;--ok:#2f6b3a;--no:#9b2c2c;--warn:#8a5a00;--card:#fff;--acc:#1d4f73}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--mut:#9a9992;--line:#2c2c2a;--ok:#7fc28d;--no:#e08b8b;--warn:#e0b060;--card:#1f1f1d;--acc:#8cc4ec}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:18px 0 8px}p.mut{color:var(--mut);margin:0 0 16px}
nav{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 18px;border-bottom:1px solid var(--line)}
nav button{border:0;border-bottom:2px solid transparent;border-radius:0;background:none;padding:8px 12px}
nav button[aria-pressed=true]{border-bottom-color:var(--acc);color:var(--acc);font-weight:600}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:0 0 12px}
.tool{font-weight:600;font-family:ui-monospace,monospace}
.meta{color:var(--mut);font-size:13px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;max-height:320px;font-size:13px;margin:8px 0}
button{font:inherit;border-radius:8px;border:1px solid var(--line);padding:6px 14px;cursor:pointer;background:var(--card);color:var(--fg)}
button.ok{border-color:var(--ok);color:var(--ok)}button.no{border-color:var(--no);color:var(--no)}
button:focus-visible,input:focus-visible,textarea:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
input,textarea{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg)}
textarea{width:100%;box-sizing:border-box;font-family:ui-monospace,monospace;font-size:13px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}
.table{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap}th{color:var(--mut);font-weight:500}
.d-deny{color:var(--no)}.d-require_approval{color:var(--warn)}.d-allow{color:var(--ok)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}
</style>
<main>
<h1>Edge console</h1>
<p class="mut">Served by your Descles edge, from its own records. Nothing here passes through Descles.</p>
<nav id="tabs" aria-label="Console sections"></nav>
<section id="view"></section>
</main>
<script>
const tokenKey="descles-edge-admin";
function token(){let t="";try{t=sessionStorage.getItem(tokenKey)||""}catch(e){}
 if(!t){t=prompt("Edge admin token")||"";try{sessionStorage.setItem(tokenKey,t)}catch(e){}}return t}
async function api(path,opts){opts=opts||{};opts.headers=Object.assign({"Authorization":"Bearer "+token()},opts.headers||{});
 const r=await fetch(path,opts);if(r.status===401){try{sessionStorage.removeItem(tokenKey)}catch(e){};throw new Error("Wrong admin token")}
 if(!r.ok)throw new Error(await r.text());return r.json()}
function el(tag,attrs,text){const e=document.createElement(tag);Object.assign(e,attrs||{});if(text!==undefined&&text!==null)e.textContent=text;return e}
function table(cols,rows){const wrap=el("div",{className:"table"}),t=el("table"),h=el("tr");
 for(const c of cols)h.append(el("th",{},c[0]));t.append(h);
 for(const r of rows){const tr=el("tr");for(const c of cols){const v=c[1](r);const td=el("td",{},v==null?"":String(v));if(c[2])td.className=c[2](r);tr.append(td)}t.append(tr)}
 wrap.append(t);return wrap}
const when=t=>t?new Date(t).toLocaleString():"";
const view=()=>document.getElementById("view");
function fail(e){view().textContent="";view().append(el("p",{className:"mut"},e.message))}

async function approvals(){const v=view();v.textContent="Loading…";
 const top=el("div",{className:"row"});const by=el("input",{placeholder:"Your name",autocomplete:"name"});
 try{by.value=localStorage.getItem("descles-approver")||""}catch(e){}
 by.onchange=()=>{try{localStorage.setItem("descles-approver",by.value)}catch(_){}};
 const reload=el("button",{},"Refresh");reload.onclick=approvals;top.append(by,reload);
 const d=await api("/admin/approvals?state=pending");v.textContent="";v.append(top);
 if(!d.approvals.length){v.append(el("p",{className:"mut"},"Nothing is waiting for a decision."));return}
 for(const a of d.approvals){const c=el("div",{className:"card"});
  c.append(el("div",{className:"tool"},a.tool));
  c.append(el("div",{className:"meta"},"agent "+a.agent_id+(a.user_id?" for "+a.user_id:"")+" · requested "+when(a.created_at)+" · decide by "+new Date(a.expires_at).toLocaleTimeString()));
  let args=a.args;try{args=JSON.stringify(a.args,null,2)}catch(e){}
  c.append(el("pre",{},args||"(no arguments)"));
  const reason=el("input",{placeholder:"Reason (optional)"});
  const ok=el("button",{className:"ok"},"Approve"),no=el("button",{className:"no"},"Deny");
  for(const [b,dec] of [[ok,"approve"],[no,"deny"]])b.onclick=async()=>{const who=by.value.trim();
   if(!who){alert("Enter your name first");return}
   try{await api("/admin/approvals/"+encodeURIComponent(a.id)+"/"+dec,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({by:who,reason:reason.value})});approvals()}catch(e){alert(e.message)}};
  const row=el("div",{className:"row"});row.append(reason,ok,no);c.append(row);v.append(c)}}

async function activity(){const v=view();v.textContent="Loading…";
 const d=await api("/admin/activity?limit=200");v.textContent="";
 const model=d.records.filter(r=>r.kind==="model"),tools=d.records.filter(r=>r.kind==="tool");
 const tok=model.reduce((s,r)=>s+(r.input_tokens||0)+(r.output_tokens||0),0),cost=model.reduce((s,r)=>s+(r.cost_usd||0),0);
 v.append(el("p",{className:"mut"},d.records.length+" recent calls · "+model.length+" model calls, "+tok.toLocaleString()+" tokens, $"+cost.toFixed(4)+" · "+tools.length+" tool calls, "+tools.filter(r=>r.decision==="deny").length+" denied"));
 v.append(table([["Time",r=>when(r.at)],["Agent",r=>r.agent],["Call",r=>r.name||r.kind],["Decision",r=>r.decision,r=>"d-"+r.decision],["Status",r=>r.status],["Tokens",r=>r.kind==="model"?(r.input_tokens||0)+(r.output_tokens||0):""],["Trace",r=>r.trace]],d.records))}

async function policyPanel(){const v=view();v.textContent="Loading…";
 const d=await api("/admin/policy");v.textContent="";
 const g=el("div",{className:"grid"});
 const rules=el("div",{className:"card"});rules.append(el("div",{className:"tool"},d.floor?"Control plane policy":"Policy"),el("pre",{},JSON.stringify(d.rules,null,2)));g.append(rules);
 if(d.floor){const f=el("div",{className:"card"});f.append(el("div",{className:"tool"},"Local floor (this edge's policy.yaml)"),el("div",{className:"meta"},"Every decision is the stricter of the two; the control plane cannot loosen this. Read at startup: restart the edge after editing policy.yaml."),el("pre",{},JSON.stringify(d.floor,null,2)));g.append(f)}
 v.append(g);
 const chk=el("div",{className:"card"});chk.append(el("div",{className:"tool"},"Check a call"));
 const agent=el("input",{placeholder:"agent id"}),tool=el("input",{placeholder:"connector.tool or local.bash"}),args=el("textarea",{rows:3,placeholder:'{"command": "rm -rf build"}'});
 const go=el("button",{},"Check"),out=el("div",{className:"meta"});
 go.onclick=async()=>{let a={};try{a=args.value.trim()?JSON.parse(args.value):{}}catch(e){out.textContent="Arguments must be JSON";return}
  try{const r=await api("/admin/policy/check",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({agent:agent.value,tool:tool.value,args:a})});
   out.textContent="Decision: "+r.decision+" (rules: "+r.rules+(r.floor?", floor: "+r.floor:"")+")";out.className="meta d-"+r.decision}catch(e){out.textContent=e.message}};
 const row=el("div",{className:"row"});row.append(agent,tool);chk.append(row,args,el("div",{className:"row"}),go,out);v.append(chk);
 const rp=await api("/admin/policy/replay?limit=500");const c=el("div",{className:"card"});
 c.append(el("div",{className:"tool"},"Recent tool calls under today's policy"),el("div",{className:"meta"},rp.checked+" calls re-checked; "+rp.changed.length+" would now be decided differently. Arguments are not recorded, so argument rules are checked without them."));
 if(rp.changed.length)c.append(table([["Time",r=>when(r.at)],["Agent",r=>r.agent],["Tool",r=>r.tool],["Then",r=>r.recorded,r=>"d-"+r.recorded],["Now",r=>r.now,r=>"d-"+r.now]],rp.changed));
 v.append(c)}

async function contextPanel(){const v=view();v.textContent="";
 const q=el("input",{placeholder:"email, name, id…"}),labels=el("input",{placeholder:"preview as labels (optional)"}),go=el("button",{},"Search");
 const row=el("div",{className:"row"});row.append(q,labels,go);v.append(row);
 const res=el("div");v.append(res);
 const lab=()=>labels.value.trim()?"&labels="+encodeURIComponent(labels.value.trim()):"";
 async function open(id){res.textContent="Loading…";try{const d=await api("/admin/context/entity/"+encodeURIComponent(id)+"?"+lab().slice(1));res.textContent="";
   const c=el("div",{className:"card"});c.append(el("div",{className:"tool"},d.entity.kind+" · "+(d.entity.name||d.entity.id)));
   c.append(el("div",{className:"meta"},(d.entity.keys||[]).map(k=>k.namespace+"="+k.value).join(" · ")));
   c.append(table([["Fact",a=>a.predicate+((a.conflicts||[]).length?" (conflicting sources)":"")],["Value",a=>JSON.stringify(a.fact.value)],["Source",a=>a.fact.source],["By",a=>a.fact.asserter],["Seen",a=>when(a.fact.observed_at)],["Labels",a=>(a.fact.labels||[]).join(",")]],d.entity.attributes||[]));
   if((d.related||[]).length){c.append(el("h2",{},"Related"));for(const r of d.related){const b=el("button",{},(r.direction==="in"?"← ":"")+r.predicate+" → "+r.kind+" "+(r.name||r.entity));b.onclick=()=>open(r.entity);c.append(b," ")}}
   res.append(c)}catch(e){res.textContent=e.message}}
 go.onclick=async()=>{res.textContent="Searching…";try{const d=await api("/admin/context/search?q="+encodeURIComponent(q.value)+lab());res.textContent="";
   if(!d.hits.length){res.append(el("p",{className:"mut"},"No visible entity matches."));return}
   for(const h of d.hits){const b=el("button",{},h.kind+" · "+(h.name||h.id));b.onclick=()=>open(h.id);res.append(b," ")}}catch(e){res.textContent=e.message}};
 try{const s=await api("/admin/context/sync");const c=el("div",{className:"card"});c.append(el("div",{className:"tool"},"Sync"));
  if(!s.configured)c.append(el("div",{className:"meta"},"No sync configured: context grows only from calls agents make. Add a sync: section to the extractor file."));
  else c.append(table([["Tool",r=>r.tool],["Last run",r=>when(r.last_run)],["Pages",r=>r.pages],["Claims",r=>r.claims],["Error",r=>r.error||"",r=>r.error?"d-deny":""]],s.tools));
  v.append(c)}catch(e){}}

const panels={approvals:approvals,activity:activity,policy:policyPanel,context:contextPanel};
async function show(id){for(const b of document.querySelectorAll("#tabs button"))b.setAttribute("aria-pressed",b.dataset.id===id?"true":"false");
 try{location.hash=id}catch(e){}
 try{await (panels[id]||(()=>{view().textContent="This panel is not available in this page version."}))()}catch(e){fail(e)}}
(async()=>{let list=[{id:"approvals",title:"Approvals"}];
 try{list=(await api("/admin/panels")).panels}catch(e){fail(e);return}
 const nav=document.getElementById("tabs");
 for(const p of list){const b=el("button",{type:"button"},p.title);b.dataset.id=p.id;b.onclick=()=>show(p.id);nav.append(b)}
 const want=(location.hash||"").slice(1);show(list.some(p=>p.id===want)?want:list[0].id)})();
</script>`
