package edge

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// ApprovalAdmin serves approvers on the customer's network: an API and a
// small page at /admin/. Details of pending calls are shown from the edge's
// own store and never pass through Descles.
//
// Authentication is one edge admin token (DESCLES_EDGE_ADMIN_TOKEN). The
// approver's name is recorded as given; per-person identity (SSO) comes from
// a managed control plane, not from this token.
type ApprovalAdmin struct {
	Store *ApprovalStore
	Token string
}

// Register mounts the admin routes. Without a token they are not served.
func (a *ApprovalAdmin) Register(mux *http.ServeMux) {
	if a == nil || a.Token == "" || a.Store == nil {
		return
	}
	mux.HandleFunc("GET /admin/{$}", a.page)
	mux.Handle("GET /admin/approvals", a.auth(http.HandlerFunc(a.list)))
	mux.Handle("POST /admin/approvals/{id}/{decision}", a.auth(http.HandlerFunc(a.decide)))
}

func (a *ApprovalAdmin) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(a.Token)) != 1 {
			http.Error(w, "edge admin token required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *ApprovalAdmin) list(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	switch state {
	case "", ApprovalPending, ApprovalApproved, ApprovalDenied, ApprovalUsed, ApprovalExpired:
	default:
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}
	list, err := a.Store.List(r.Context(), state, 200)
	if err != nil {
		http.Error(w, "approvals unavailable", http.StatusServiceUnavailable)
		return
	}
	if list == nil {
		list = []Approval{}
	}
	writeJSONBody(w, map[string]any{"approvals": list})
}

func (a *ApprovalAdmin) decide(w http.ResponseWriter, r *http.Request) {
	decision := r.PathValue("decision")
	if decision != "approve" && decision != "deny" {
		http.Error(w, "decision must be approve or deny", http.StatusBadRequest)
		return
	}
	var in struct {
		By     string `json:"by"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in); err != nil {
		http.Error(w, "JSON body with \"by\" required", http.StatusBadRequest)
		return
	}
	in.By, in.Reason = strings.TrimSpace(in.By), strings.TrimSpace(in.Reason)
	if in.By == "" || len(in.By) > 120 || len(in.Reason) > 1000 {
		http.Error(w, "\"by\" (1-120 chars) required; reason up to 1000 chars", http.StatusBadRequest)
		return
	}
	out, err := a.Store.Decide(r.Context(), r.PathValue("id"), decision == "approve", in.By, in.Reason)
	switch {
	case errors.Is(err, ErrApprovalNotPending):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(w, "approval not found", http.StatusNotFound)
	default:
		writeJSONBody(w, out)
	}
}

func (a *ApprovalAdmin) page(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	_, _ = io.WriteString(w, adminPage)
}

const adminPage = `<!doctype html><meta charset="utf-8"><title>Descles edge approvals</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#fafaf7;--fg:#1d1d1b;--mut:#6b6b66;--line:#e2e1da;--ok:#2f6b3a;--no:#9b2c2c;--card:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--mut:#9a9992;--line:#2c2c2a;--ok:#7fc28d;--no:#e08b8b;--card:#1f1f1d}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:24px 16px}
h1{font-size:20px;margin:0 0 4px}p.mut{color:var(--mut);margin:0 0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:0 0 12px}
.tool{font-weight:600;font-family:ui-monospace,monospace}
.meta{color:var(--mut);font-size:13px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;max-height:260px;font-size:13px}
button{font:inherit;border-radius:8px;border:1px solid var(--line);padding:6px 14px;cursor:pointer;background:var(--card);color:var(--fg)}
button.ok{border-color:var(--ok);color:var(--ok)}button.no{border-color:var(--no);color:var(--no)}
input{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}
</style>
<main>
<h1>Pending approvals</h1>
<p class="mut">Served by your Descles edge. Call details come from this edge only.</p>
<div class="row" style="margin-bottom:16px"><input id="by" placeholder="Your name" autocomplete="name"><button id="reload">Refresh</button></div>
<div id="list"></div>
</main>
<script>
const tokenKey="descles-edge-admin";
function token(){let t="";try{t=sessionStorage.getItem(tokenKey)||""}catch(e){}
 if(!t){t=prompt("Edge admin token")||"";try{sessionStorage.setItem(tokenKey,t)}catch(e){}}return t}
async function api(path,opts){opts=opts||{};opts.headers=Object.assign({"Authorization":"Bearer "+token()},opts.headers||{});
 const r=await fetch(path,opts);if(r.status===401){try{sessionStorage.removeItem(tokenKey)}catch(e){};throw new Error("Wrong admin token")}
 if(!r.ok)throw new Error(await r.text());return r.json()}
function el(tag,attrs,text){const e=document.createElement(tag);Object.assign(e,attrs||{});if(text!==undefined)e.textContent=text;return e}
async function load(){const list=document.getElementById("list");list.textContent="Loading…";
 try{const d=await api("/admin/approvals?state=pending");list.textContent="";
  if(!d.approvals.length){list.append(el("p",{className:"mut"},"Nothing is waiting for a decision."));return}
  for(const a of d.approvals){const c=el("div",{className:"card"});
   c.append(el("div",{className:"tool"},a.tool));
   c.append(el("div",{className:"meta"},"agent "+a.agent_id+(a.user_id?" for "+a.user_id:"")+" · requested "+new Date(a.created_at).toLocaleString()+" · decide by "+new Date(a.expires_at).toLocaleTimeString()));
   let args=a.args;try{args=JSON.stringify(a.args,null,2)}catch(e){}
   c.append(el("pre",{},args||"(no arguments)"));
   const reason=el("input",{placeholder:"Reason (optional)"});
   const ok=el("button",{className:"ok"},"Approve");const no=el("button",{className:"no"},"Deny");
   for(const [b,dec] of [[ok,"approve"],[no,"deny"]])b.onclick=async()=>{const by=document.getElementById("by").value.trim();
    if(!by){alert("Enter your name first");return}
    try{await api("/admin/approvals/"+encodeURIComponent(a.id)+"/"+dec,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({by:by,reason:reason.value})});load()}catch(e){alert(e.message)}};
   const row=el("div",{className:"row"});row.append(reason,ok,no);c.append(row);list.append(c)}
 }catch(e){list.textContent=e.message}}
try{document.getElementById("by").value=localStorage.getItem("descles-approver")||""}catch(e){}
document.getElementById("by").onchange=e=>{try{localStorage.setItem("descles-approver",e.target.value)}catch(_){}};
document.getElementById("reload").onclick=load;load();
</script>`
