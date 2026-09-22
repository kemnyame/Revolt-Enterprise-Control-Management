window.addEventListener("unhandledrejection",e=>{console.error("Unhandled promise rejection",e.reason);const t=document.querySelector("#toast");if(t){t.textContent="An action failed. Please retry.";t.classList.add("show");setTimeout(()=>t.classList.remove("show"),2500)}});
const state={
  token:localStorage.getItem("revolt_token")||"",user:null,permissions:[],
  dashboard:null,progress:null,controls:[],evidence:[],assessments:[],findings:[],integrations:[],automation:[],library:[],report:[],frameworkCoverage:[],evidenceFreshness:null,assuranceSummary:null,audit:[],users:[],organization:null,
  page:"overview",currentControl:null
};
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const fmtDate=v=>v?new Date(v).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"}):"—";
const fmtTime=v=>v?new Date(v).toLocaleString("en-GB",{day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit"}):"—";
const initials=name=>String(name||"RX").split(/\s+/).slice(0,2).map(x=>x[0]).join("").toUpperCase();
const humanRole=r=>String(r||"").replace(/_/g," ").replace(/\b\w/g,m=>m.toUpperCase());
const has=p=>state.permissions.includes(p);
const tag=v=>'<span class="tag '+String(v||"").toLowerCase().replace(/\s+/g,"-")+'">'+esc(v||"—")+"</span>";
function toast(msg){const t=$("#toast");t.textContent=msg;t.classList.add("show");setTimeout(()=>t.classList.remove("show"),2500)}
async function api(url,opt={}){
  const headers={...(opt.headers||{})};if(!(opt.body instanceof FormData))headers["Content-Type"]="application/json";if(state.token)headers.Authorization="Bearer "+state.token;
  const r=await fetch(url,{...opt,headers});let data=null;const ct=r.headers.get("content-type")||"";
  try{data=ct.includes("json")?await r.json():await r.text()}catch{data=null}
  if(r.status===401&&url!=="/api/auth/login"){logout();throw new Error("Session expired")}
  if(!r.ok)throw new Error(data?.error||data||"Request failed");return data;
}
function modal(html,wide=false){$("#modalBody").innerHTML=html;$("#modal").classList.remove("hidden");$(".modal-card").classList.toggle("wide",wide);bindModalClose()}
function closeModal(){$("#modal").classList.add("hidden");$("#modalBody").innerHTML="";$(".modal-card").classList.remove("wide")}
function bindModalClose(){$$("[data-close-modal]").forEach(b=>b.onclick=closeModal)}
function loginView(show){$("#loginView").classList.toggle("hidden",!show);$("#appView").classList.toggle("hidden",show)}
async function login(e){
  e.preventDefault();$("#loginMessage").textContent="";
  try{
    const d=await api("/api/auth/login",{method:"POST",body:JSON.stringify({email:$("#loginEmail").value,password:$("#loginPassword").value})});
    state.token=d.token;state.user=d.user;state.permissions=d.permissions;localStorage.setItem("revolt_token",state.token);loginView(false);setupUser();await loadAll();
  }catch(err){$("#loginMessage").textContent=err.message}
}
function logout(){localStorage.removeItem("revolt_token");state.token="";state.user=null;loginView(true)}
function setupUser(){
  $("#userName").textContent=state.user?.name||"User";$("#userRole").textContent=humanRole(state.user?.role);$("#userInitials").textContent=initials(state.user?.name);
  $$("[data-permission]").forEach(el=>el.classList.toggle("hidden",!has(el.dataset.permission)));
}
async function restore(){
  if(!state.token)return loginView(true);
  try{const d=await api("/api/auth/me");state.user=d.user;state.permissions=d.permissions;loginView(false);setupUser();await loadAll()}catch{logout()}
}
async function loadAll(){
  document.body.classList.add("loading");
  try{
    const jobs=[
      api("/api/dashboard"),api("/api/dashboard/progress?period=quarter"),api("/api/controls"),api("/api/evidence"),api("/api/assessments"),api("/api/findings"),api("/api/integrations"),
      api("/api/automation"),api("/api/control-library"),api("/api/reports/control-health"),api("/api/reports/framework-coverage"),api("/api/reports/evidence-freshness"),api("/api/reports/assurance-summary"),
      has("audit.read")?api("/api/audit"):Promise.resolve([]),has("users.read")?api("/api/users"):Promise.resolve([]),has("settings.read")?api("/api/settings/organization"):Promise.resolve(null)
    ];
    const [dashboard,progress,controls,evidence,assessments,findings,integrations,automation,library,report,frameworkCoverage,evidenceFreshness,assuranceSummary,audit,users,organization]=await Promise.all(jobs);
    Object.assign(state,{dashboard,progress,controls,evidence,assessments,findings,integrations,automation,library,report,frameworkCoverage,evidenceFreshness,assuranceSummary,audit,users,organization});renderAll();
  }catch(e){toast(e.message)}finally{document.body.classList.remove("loading")}
}
async function refresh(parts=["dashboard","controls","evidence","assessments","findings","integrations","automation","library","audit","users"]){
  const routes={dashboard:"/api/dashboard",progress:"/api/dashboard/progress?period=quarter",controls:"/api/controls",evidence:"/api/evidence",assessments:"/api/assessments",findings:"/api/findings",integrations:"/api/integrations",automation:"/api/automation",library:"/api/control-library",report:"/api/reports/control-health",frameworkCoverage:"/api/reports/framework-coverage",evidenceFreshness:"/api/reports/evidence-freshness",assuranceSummary:"/api/reports/assurance-summary",audit:"/api/audit",users:"/api/users"};
  for(const p of parts){if((p==="audit"&&!has("audit.read"))||(p==="users"&&!has("users.read")))continue;state[p]=await api(routes[p])}
  renderAll();
}
function go(page){
  state.page=page;$$(".page").forEach(x=>x.classList.add("hidden"));$("#"+page+"Page")?.classList.remove("hidden");
  $$("[data-page]").forEach(b=>b.classList.toggle("active",b.dataset.page===page));
  const titles={overview:"IT controls overview",controls:"Control register",evidence:"Evidence vault",assessments:"Testing & assurance",findings:"Issues & remediation",integrations:"Integrations",library:"Control library",audit:"Audit trail",settings:"Settings & team",users:"Settings & team",manual:"User manual",reports:"Control health",controlDetail:"Control record"};
  $("#pageTitle").textContent=titles[page]||"IT Controls";$(".sidebar").classList.remove("open");window.scrollTo(0,0);
}
function safeRender(name,fn){try{fn()}catch(err){console.error("Render failure:",name,err);toast(name+" could not render. Other pages remain available.")}}
function renderAll(){
  [
    ["Dashboard",renderDashboard],["Progress",renderProgress],["Controls",renderControls],["Evidence Vault",renderEvidence],["Testing",renderAssessments],
    ["Findings",renderFindings],["Integrations",renderIntegrations],["Automation",renderAutomation],["Control Library",renderLibrary],
    ["Control Health",renderReports],["Audit Trail",renderAudit],["Users",renderUsers],["Settings",renderSettings],["Filters",populateFilters]
  ].forEach(([name,fn])=>safeRender(name,fn));
  safeRender("User Manual",()=>renderManual("start"));
}
function renderDashboard(){
  const d=state.dashboard||{},c=d.controls||{},a=d.assessments||{},e=d.evidence||{},f=d.findings||{};
  const metrics=[
    ["Active controls",c.total||0,(c.high_risk||0)+" high risk","☷"],
    ["Test effectiveness",(d.effectiveness||0)+"%",(a.total||0)+" tests recorded","✓"],
    ["Evidence items",e.total||0,"source records in vault","▣"],
    ["Open issues",f.open||0,(f.high_open||0)+" high severity","!"],
    ["Integrations",state.integrations.filter(i=>i.status==="Connected").length,state.integrations.length+" available connectors","⌁"]
  ];
  $("#metricGrid").innerHTML=metrics.map(m=>'<div class="metric"><div class="metric-top"><small>'+esc(m[0])+'</small><span class="metric-icon">'+m[3]+'</span></div><strong>'+esc(m[1])+'</strong><p>'+esc(m[2])+'</p></div>').join("");
  const cats=d.categories||[],max=Math.max(1,...cats.map(x=>Number(x.total)));
  $("#categoryChart").innerHTML=cats.length?cats.slice(0,10).map(x=>'<div class="bar-row"><span title="'+esc(x.category)+'">'+esc(x.category)+'</span><div class="bar-track"><i style="width:'+(Number(x.total)/max*100)+'%"></i></div><b>'+x.total+'</b></div>').join(""):'<div class="empty-state">No controls yet.</div>';
  $("#activityList").innerHTML=(d.recentActivity||[]).length?(d.recentActivity||[]).map(x=>'<div class="activity-item"><span>↺</span><div><b>'+esc(x.action)+" "+esc(x.entity_type)+'</b><small>'+esc(x.name||"System")+'</small></div><time>'+fmtTime(x.created_at)+'</time></div>').join(""):'<div class="empty-state">No activity yet.</div>';
  const open=state.findings.filter(x=>!["Closed","Resolved"].includes(x.status)).slice(0,6);
  $("#overviewFindings").innerHTML=open.length?'<div class="table-card"><table><thead><tr><th>Issue</th><th>Control</th><th>Severity</th><th>Owner</th><th>Due</th><th>Status</th></tr></thead><tbody>'+open.map(x=>'<tr><td class="control-name"><b>'+esc(x.title)+'</b></td><td>'+esc(x.control_code||"—")+'</td><td>'+tag(x.severity)+'</td><td>'+esc(x.owner||"Unassigned")+'</td><td>'+fmtDate(x.due_date)+'</td><td>'+tag(x.status)+'</td></tr>').join("")+'</tbody></table></div>':'<div class="empty-state">No open issues.</div>';
}
async function loadProgress(){
  if(!$("#progressPanel"))return;
  const period=$("#progressPeriod")?.value||"quarter",frequency=$("#progressFrequency")?.value||"",officer=$("#progressOfficer")?.value||"";
  try{
    const qs=new URLSearchParams({period});
    if(frequency)qs.set("frequency",frequency);
    if(officer)qs.set("assignee_id",officer);
    state.progress=await api("/api/dashboard/progress?"+qs.toString());
    renderProgress();
  }catch(e){toast(e.message)}
}
function renderProgress(){
  if(!$("#progressSummary"))return;
  const p=state.progress||{summary:{},by_frequency:[],by_officer:[],items:[],label:"Current period"},s=p.summary||{};
  $("#progressSummary").innerHTML=[
    ["Period",p.label||"—","Selected reporting period"],["Completion",(s.completion_percent||0)+"%",(s.completed||0)+" completed"],
    ["In progress",s.in_progress||0,"Evidence/work started"],["Overdue",s.overdue||0,"Past control due date"],
    ["Not started",s.not_started||0,"No period activity"],["Activity",(s.activity_percent||0)+"%","Weighted work progress"]
  ].map(x=>'<div class="progress-kpi"><small>'+esc(x[0])+'</small><strong>'+esc(x[1])+'</strong><p>'+esc(x[2])+'</p></div>').join("");
  $("#progressFrequencyGrid").innerHTML=(p.by_frequency||[]).length?p.by_frequency.map(x=>{const pct=x.total?Math.round(x.completed/x.total*100):0;return '<div class="progress-row"><span>'+esc(x.frequency)+' · '+x.completed+'/'+x.total+' done</span><div class="track"><i style="width:'+pct+'%"></i></div><b>'+pct+'%</b></div>'}).join(""):'<div class="empty-state">No frequency data.</div>';
  $("#progressOfficerGrid").innerHTML=(p.by_officer||[]).length?p.by_officer.map(x=>{const pct=x.total?Math.round(x.completed/x.total*100):0;return '<div class="progress-row"><span>'+esc(x.name)+' · '+x.completed+'/'+x.total+' done</span><div class="track"><i style="width:'+pct+'%"></i></div><b>'+pct+'%</b></div>'}).join(""):'<div class="empty-state">No officer assignments yet.</div>';
  $("#progressBody").innerHTML=(p.items||[]).length?p.items.map(x=>'<tr><td class="control-name"><b>'+esc(x.control_code)+' · '+esc(x.title)+'</b><span>'+esc(x.category)+'</span></td><td>'+esc(x.assigned_user_name||"Unassigned")+'</td><td>'+esc(x.frequency)+'</td><td>'+tag(x.risk_level)+'</td><td><span class="work-status '+String(x.work_status).toLowerCase().replace(/\s+/g,"-")+'">'+esc(x.work_status)+'</span></td><td>'+esc(x.period_evidence||0)+'</td><td>'+esc(x.open_findings||0)+'</td><td>'+fmtDate(x.next_due)+'</td><td><button class="action-btn" data-progress-control="'+x.id+'">Open</button></td></tr>').join(""):'<tr><td colspan="10" class="empty-state">No controls in the selected scope.</td></tr>';
  $("[data-progress-control]").forEach(b=>b.onclick=()=>openControl(Number(b.dataset.progressControl)));
  if($("#progressOfficer")){
    const old=$("#progressOfficer").value;
    const users=(state.users||[]).filter(u=>["control_manager","control_officer"].includes(u.role));
    $("#progressOfficer").innerHTML='<option value="">All officers</option>'+users.map(u=>'<option value="'+u.id+'">'+esc(u.name)+'</option>').join("");
    if(old&&users.some(u=>String(u.id)===old))$("#progressOfficer").value=old;
    if(state.user?.role==="control_officer"){
      $("#progressOfficer").innerHTML='<option value="'+state.user.id+'">'+esc(state.user.name)+'</option>';
      $("#progressOfficer").disabled=true;
    }
  }
}
function filteredControls(){
  const q=$("#controlSearch")?.value?.toLowerCase()||"",cat=$("#categoryFilter")?.value||"",risk=$("#riskFilter")?.value||"";
  return state.controls.filter(c=>(!q||(c.control_code+" "+c.title).toLowerCase().includes(q))&&(!cat||c.category===cat)&&(!risk||c.risk_level===risk));
}
function renderControls(){
  const rows=filteredControls();
  $("#controlsBody").innerHTML=rows.length?rows.map(c=>'<tr><td class="control-name"><b>'+esc(c.control_code)+" · "+esc(c.title)+'</b><span>'+esc(c.framework_ref||"No framework mapping")+'</span></td><td>'+esc(c.category)+'</td><td>'+esc(c.assigned_user_name||"Unassigned")+'</td><td>'+esc(c.owner||"—")+'</td><td>'+esc(c.frequency)+'</td><td>'+tag(c.risk_level)+'</td><td>'+tag(c.latest_result||"Not Tested")+'</td><td>'+esc(c.evidence_count||0)+'</td><td>'+esc(c.open_findings||0)+'</td><td><div class="row-actions"><button class="action-btn" data-view-control="'+c.id+'">Open</button>'+(has("assessments.write")?'<button class="action-btn dark" data-test-control="'+c.id+'">Test control</button>':'')+'</div></td></tr>').join(""):'<tr><td colspan="9" class="empty-state">No controls match the current filters.</td></tr>';
  $$("[data-view-control]").forEach(b=>b.onclick=()=>openControl(Number(b.dataset.viewControl)));
  $$("[data-test-control]").forEach(b=>b.onclick=()=>openTestControl(Number(b.dataset.testControl)));
}
function renderEvidence(){
  $("#evidenceGrid").innerHTML=state.evidence.length?state.evidence.map(e=>'<article class="evidence-card"><div class="evidence-card-head"><span class="doc-icon">'+(e.file_id?"FILE":"SRC")+'</span>'+tag(e.review_status||e.status)+'</div><h3>'+esc(e.title)+'</h3><p>'+esc(e.control_code)+" · "+esc(e.control_title)+'</p><div class="evidence-meta"><div><small>SOURCE</small><b>'+esc(e.source)+'</b></div><div><small>PERIOD</small><b>'+esc(e.period||"—")+'</b></div><div><small>COLLECTED</small><b>'+fmtDate(e.collected_at||e.created_at)+'</b></div><div><small>TYPE</small><b>'+esc(e.evidence_type)+'</b></div></div>'+(e.sha256?'<div class="fingerprint">SHA-256 '+esc(e.sha256)+'</div>':'')+'<div class="evidence-actions">'+(e.file_id?'<button class="action-btn" data-download-file="'+e.file_id+'">Download source</button><button class="action-btn" data-verify-evidence="'+e.id+'">Verify integrity</button>':'')+(e.url?'<button class="action-btn" data-open-url="'+esc(e.url)+'">Open source</button>':'')+(has("evidence.write")?'<button class="action-btn dark" data-review-evidence="'+e.id+'">Review</button>':'')+'</div></article>').join(""):'<div class="empty-state">No evidence has been added yet.</div>';
  $("[data-download-file]").forEach(b=>b.onclick=()=>downloadEvidence(Number(b.dataset.downloadFile)));
  $("[data-verify-evidence]").forEach(b=>b.onclick=()=>verifyEvidence(Number(b.dataset.verifyEvidence)));
  $("[data-open-url]").forEach(b=>b.onclick=()=>window.open(b.dataset.openUrl,"_blank","noopener"));
  $("[data-review-evidence]").forEach(b=>b.onclick=()=>reviewEvidence(Number(b.dataset.reviewEvidence)));
}
function renderAssessments(){
  $("#assessmentsBody").innerHTML=state.assessments.length?state.assessments.map(a=>'<tr><td class="control-name"><b>'+esc(a.control_code)+" · "+esc(a.control_title)+'</b></td><td>'+esc(a.period)+'</td><td>'+tag(a.result)+'</td><td><b>'+esc(a.score??"—")+(a.score!=null?"%":"")+'</b></td><td>'+esc(a.tester_name||"—")+'</td><td>'+tag(a.review_status)+'</td><td>'+fmtDate(a.tested_at)+'</td><td>'+(has("assessments.review")?'<button class="action-btn" data-review-test="'+a.id+'">Review</button>':'')+'</td></tr>').join(""):'<tr><td colspan="8" class="empty-state">No control tests recorded.</td></tr>';
  $("[data-review-test]").forEach(b=>b.onclick=()=>reviewAssessment(Number(b.dataset.reviewTest)));
}
function renderFindings(){
  const cols=[["Open",x=>x.status==="Open"],["In Progress",x=>["In Progress","Remediation"].includes(x.status)],["Closed",x=>["Closed","Resolved"].includes(x.status)]];
  $("#findingBoard").innerHTML=cols.map(([name,test])=>{const items=state.findings.filter(test);return '<section class="finding-column"><div class="finding-column-head"><b>'+name+'</b><span>'+items.length+'</span></div>'+items.map(f=>'<article class="finding-card" data-open-finding="'+f.id+'"><div>'+tag(f.severity)+'</div><h3>'+esc(f.title)+'</h3><p>'+esc(f.control_code||"No linked control")+(f.description?" · "+esc(f.description):"")+'</p><div class="finding-card-foot"><span>'+esc(f.owner||"Unassigned")+' · '+fmtDate(f.due_date)+'</span>'+(has("findings.write")?'<select data-finding-status="'+f.id+'"><option '+(f.status==="Open"?"selected":"")+'>Open</option><option '+(["In Progress","Remediation"].includes(f.status)?"selected":"")+'>In Progress</option><option '+(["Closed","Resolved"].includes(f.status)?"selected":"")+'>Resolved</option></select>':tag(f.status))+'</div></article>').join("")+'</section>'}).join("");
  $("[data-finding-status]").forEach(s=>{s.onclick=e=>e.stopPropagation();s.onchange=()=>updateFinding(Number(s.dataset.findingStatus),s.value)});$("[data-open-finding]").forEach(card=>card.onclick=()=>openFinding(Number(card.dataset.openFinding)));
}
function openFinding(id){
  const f=state.findings.find(x=>x.id===id);if(!f)return;
  modal('<span class="caps">REMEDIATION WORKSPACE</span><h2>'+esc(f.title)+'</h2><p>'+esc(f.control_code||"No linked control")+' · '+esc(f.control_title||"")+'</p><form class="form" id="remediationForm"><label>Description<textarea name="description">'+esc(f.description||"")+'</textarea></label><div class="form-grid"><label>Owner<input name="owner" value="'+esc(f.owner||"")+'"></label><label>Due date<input name="due_date" type="date" value="'+(f.due_date?String(f.due_date).slice(0,10):"")+'"></label><label>Status<select name="status">'+["Open","In Progress","Resolved"].map(x=>'<option '+((f.status==="Closed"?"Resolved":f.status)===x?"selected":"")+'>'+x+'</option>').join("")+'</select></label><label>Severity<input value="'+esc(f.severity)+'" disabled></label></div><div class="manual-tip">Resolving a linked finding requires a passing Effective retest after the finding was raised.</div><div class="form-actions">'+(f.control_id&&has("assessments.write")?'<button type="button" class="btn outline" id="retestFindingBtn">Retest control</button>':'')+'<button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Save remediation</button></div></form>');
  $("#retestFindingBtn")?.addEventListener("click",()=>{closeModal();openTestControl(Number(f.control_id))});
  $("#remediationForm").onsubmit=async e=>{
    e.preventDefault();
    const d=Object.fromEntries(new FormData(e.target).entries());d.due_date=d.due_date||null;
    try{await api("/api/findings/"+id,{method:"PUT",body:JSON.stringify(d)});closeModal();toast("Remediation updated");await refresh(["findings","dashboard","audit"]);await loadProgress()}
    catch(err){toast(err.message)}
  };
}
async function updateFinding(id,status){
  try{await api("/api/findings/"+id,{method:"PUT",body:JSON.stringify({status})});toast("Issue updated");await refresh(["findings","dashboard","audit"])}
  catch(e){toast(e.message);renderFindings()}
}
function renderIntegrations(){
  const os=state.integrations.find(i=>i.provider_key==="revolt-os");
  if(os&&$("#osConnectionState")){
    $("#osConnectionState").innerHTML='<div class="connection-state">Status: <strong>'+esc(os.status)+'</strong>'+(os.tenant_ref?' · Workspace: <strong>'+esc(os.tenant_ref)+'</strong>':'')+(os.last_sync_at?' · Last sync: '+fmtTime(os.last_sync_at):'')+'</div>';
    $("#osActions").innerHTML=!has("integrations.write")?"":(os.status==="Connected"?'<button class="btn outline" id="syncOsBtn">Sync context</button><button class="btn outline" id="disconnectOsBtn">Disconnect</button>':'<button class="btn outline" id="connectOsBtn">Connect OS</button>');
    $("#connectOsBtn")?.addEventListener("click",()=>connectProvider("revolt-os"));
    $("#syncOsBtn")?.addEventListener("click",()=>syncProvider("revolt-os"));
    $("#disconnectOsBtn")?.addEventListener("click",()=>disconnectProvider("revolt-os"));
  }
  const gh=state.integrations.find(i=>i.provider_key==="github");
  if(gh){
    $("#githubConnectionState").innerHTML='<div class="connection-state">Status: <strong>'+esc(gh.status)+'</strong>'+(gh.tenant_ref?' · Account: <strong>'+esc(gh.tenant_ref)+'</strong>':'')+(gh.last_sync_at?' · Last sync: '+fmtTime(gh.last_sync_at):'')+'</div>';
    $("#githubActions").innerHTML=!has("integrations.write")?"":(gh.status==="Connected"
      ?'<button class="btn outline" id="manageGithubBtn">Repositories</button><button class="btn outline" id="syncGithubBtn">Sync now</button><button class="btn outline" id="disconnectGithubBtn">Disconnect</button>'
      :'<button class="btn outline" id="connectGithubBtn">Connect GitHub</button>');
    $("#connectGithubBtn")?.addEventListener("click",connectGithub);
    $("#manageGithubBtn")?.addEventListener("click",manageGithubRepos);
    $("#syncGithubBtn")?.addEventListener("click",syncGithub);
    $("#disconnectGithubBtn")?.addEventListener("click",disconnectGithub);
  }
  const connected=state.integrations.filter(i=>i.status==="Connected").length,configured=state.integrations.filter(i=>i.status==="Configured").length,live=state.integrations.filter(i=>i.connector_live||i.provider_key==="github").length;
  $("#integrationSummary").innerHTML=[
    ["Connector catalogue",state.integrations.length,"available source types"],
    ["Live adapters",live,"credential-validated connectors"],
    ["Connected",connected,"active source connections"],
    ["Configured",configured,"setup started"]
  ].map(x=>'<div class="metric"><small>'+esc(x[0])+'</small><strong>'+esc(x[1])+'</strong><p>'+esc(x[2])+'</p></div>').join("");
  const q=$("#integrationSearch")?.value?.toLowerCase()||"",cat=$("#integrationCategory")?.value||"",status=$("#integrationStatus")?.value||"";
  const rows=state.integrations.filter(i=>!["github","revolt-os"].includes(i.provider_key)&&(!q||(i.name+" "+i.category+" "+(i.capabilities||[]).join(" ")).toLowerCase().includes(q))&&(!cat||i.category===cat)&&(!status||i.status===status));
  $("#integrationGrid").innerHTML=rows.map(i=>{
    const live=!!i.connector_live;
    const action=!has("integrations.write")?"":live
      ?(i.status==="Connected"
        ?'<button data-provider-sync="'+esc(i.provider_key)+'">Sync now</button><button data-provider-disconnect="'+esc(i.provider_key)+'">Disconnect</button>'
        :'<button data-provider-connect="'+esc(i.provider_key)+'">Connect</button>')
      :'<button data-provider-info="'+esc(i.name)+'">Connector details</button>';
    return '<article class="integration-card"><div class="integration-card-head"><span class="integration-logo">'+initials(i.name)+'</span>'+tag(i.status)+'</div><h3>'+esc(i.name)+(live?' <span class="tag connected">LIVE</span>':'')+'</h3><p>'+esc(i.category)+' · '+esc(i.auth_type)+'</p><div class="capabilities">'+(Array.isArray(i.capabilities)?i.capabilities:[]).slice(0,6).map(x=>'<span>'+esc(x)+'</span>').join("")+'</div><div class="integration-foot"><span>'+(i.last_sync_at?'Synced '+fmtTime(i.last_sync_at):(live?"Live adapter ready":"Connector catalogue"))+'</span><span class="row-actions">'+action+'</span></div></article>';
  }).join("");
  $$("[data-provider-connect]").forEach(b=>b.onclick=()=>connectProvider(b.dataset.providerConnect));
  $$("[data-provider-sync]").forEach(b=>b.onclick=()=>syncProvider(b.dataset.providerSync));
  $$("[data-provider-disconnect]").forEach(b=>b.onclick=()=>disconnectProvider(b.dataset.providerDisconnect));
  $$("[data-provider-info]").forEach(b=>b.onclick=()=>modal('<span class="caps">CONNECTOR CATALOGUE</span><h2>'+esc(b.dataset.providerInfo)+'</h2><p>This source is mapped in the enterprise connector catalogue, but its direct cloud adapter is not enabled yet. It will not be marked Connected until credential validation and live evidence collection are implemented.</p><div class="manual-tip">On-premise and private-network systems will use the Revolt-X Connector Agent rather than allowing the public web service to access internal network addresses.</div><div class="form-actions"><button class="btn dark" data-close-modal>Close</button></div>'));
}

function connectorFieldHtml(field,prefix){
  const [key,label,type,placeholder]=field;
  const optional=String(label).toLowerCase().includes("(optional)");return '<label>'+esc(label)+'<input name="'+prefix+'__'+esc(key)+'" type="'+esc(type||"text")+'" '+((type||"text")==="password"?'autocomplete="new-password"':'')+' placeholder="'+esc(placeholder||"")+'" '+(optional?"":"required")+'></label>';
}
function connectProvider(provider){
  const item=state.integrations.find(i=>i.provider_key===provider);if(!item||!item.connector_live)return;
  const fields=item.connector_fields||{credentials:[],config:[]};
  modal('<span class="caps">LIVE CONNECTOR</span><h2>Connect '+esc(item.name)+'</h2><p>The application validates these credentials against the provider before the connection is marked Connected. Secrets are encrypted before storage.</p><form class="form" id="providerConnectForm">'+
    (fields.config||[]).map(f=>connectorFieldHtml(f,"config")).join("")+
    (fields.credentials||[]).map(f=>connectorFieldHtml(f,"credential")).join("")+
    '<div class="manual-tip">Use a dedicated read-only or least-privilege integration identity wherever the provider supports one.</div><div class="form-actions"><button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Validate & connect</button></div></form>');
  $("#providerConnectForm").onsubmit=async e=>{
    e.preventDefault();const fd=new FormData(e.target),credentials={},config={};
    for(const [k,v] of fd.entries()){const [kind,key]=String(k).split("__");if(kind==="credential")credentials[key]=v;else if(kind==="config")config[key]=v}
    try{const d=await api("/api/integrations/"+encodeURIComponent(provider)+"/connect",{method:"POST",body:JSON.stringify({credentials,config})});closeModal();toast(item.name+" connected as "+(d.identity||"validated source"));await refresh(["integrations","audit"])}
    catch(err){toast(err.message)}
  };
}
async function syncProvider(provider){
  const item=state.integrations.find(i=>i.provider_key===provider);if(!item)return;
  if(!confirm("Collect fresh "+item.name+" evidence now?"))return;
  try{const d=await api("/api/integrations/"+encodeURIComponent(provider)+"/sync",{method:"POST",body:"{}"});toast(item.name+": "+d.evidenceCreated+" evidence item(s), "+d.findingsCreated+" finding(s)");await refresh(["integrations","evidence","findings","controls","dashboard","audit"])}
  catch(e){toast(e.message)}
}
async function disconnectProvider(provider){
  const item=state.integrations.find(i=>i.provider_key===provider);if(!item)return;
  if(!confirm("Disconnect "+item.name+"? Historical evidence will remain."))return;
  try{await api("/api/integrations/"+encodeURIComponent(provider)+"/connection",{method:"DELETE"});toast(item.name+" disconnected");await refresh(["integrations","audit"])}
  catch(e){toast(e.message)}
}
function renderAutomation(){
  if(!$("#automationBody"))return;
  $("#automationBody").innerHTML=state.automation.length?state.automation.map(a=>'<tr><td class="control-name"><b>'+esc(a.name)+'</b><span>'+esc(a.evidence_type)+'</span></td><td>'+esc(a.control_code)+' · '+esc(a.control_title)+'</td><td>'+esc(a.integration_name)+'</td><td>'+esc(a.schedule)+'</td><td>'+tag(a.integration_status)+'</td><td>'+fmtTime(a.last_run_at)+'</td><td><button class="action-btn" data-run-rule="'+a.id+'" '+(a.integration_status==="Connected"?"":"disabled")+'>Run now</button></td></tr>').join(""):'<tr><td colspan="7" class="empty-state">No evidence automation rules configured.</td></tr>';
  $$("[data-run-rule]").forEach(b=>b.onclick=async()=>{const a=state.automation.find(x=>x.id===Number(b.dataset.runRule));if(a?.integration_name==="GitHub")return syncGithub();try{const r=await api("/api/automation/"+b.dataset.runRule+"/run",{method:"POST",body:"{}"});toast(r.message||"Automation completed")}catch(e){toast(e.message)}});
}
function renderReports(){
  if(!$("#reportSummary"))return;
  const rows=state.report||[],tested=rows.filter(r=>r.latest_result!=="Not Tested"),avg=tested.length?Math.round(tested.reduce((s,r)=>s+Number(r.score||0),0)/tested.length):0,summary=state.assuranceSummary||{},fresh=state.evidenceFreshness||{};
  $("#reportSummary").innerHTML=[["Average tested score",avg+"%","Across tested controls"],["Testing coverage",(summary.testing_coverage||0)+"%",(summary.tested_controls||0)+" controls tested"],["Automation coverage",(summary.automation_coverage||0)+"%",(summary.automated_controls||0)+" controls mapped"],["High issues",summary.high_findings||0,"High-severity open issues"]].map(x=>'<div class="metric"><small>'+esc(x[0])+'</small><strong>'+esc(x[1])+'</strong><p>'+esc(x[2])+'</p></div>').join("");
  if($("#frameworkCoverage")){const fw=state.frameworkCoverage||[],max=Math.max(1,...fw.map(x=>Number(x.controls||0)));$("#frameworkCoverage").innerHTML=fw.map(x=>'<div class="bar-row"><span>'+esc(x.framework)+'</span><div class="bar-track"><i style="width:'+(Number(x.controls)/max*100)+'%"></i></div><b>'+esc(x.controls)+'</b></div>').join("")}
  if($("#evidenceFreshness"))$("#evidenceFreshness").innerHTML='<div class="mini-stats"><div><small>Fresh</small><strong>'+esc(fresh.fresh||0)+'</strong></div><div><small>Expiring soon</small><strong>'+esc(fresh.expiring_soon||0)+'</strong></div><div><small>Expired</small><strong>'+esc(fresh.expired||0)+'</strong></div></div>';
  if($("#reportBody"))$("#reportBody").innerHTML=rows.map(r=>'<tr><td class="control-name"><b>'+esc(r.control_code)+' · '+esc(r.title)+'</b><span>'+esc(r.owner||"Unassigned")+'</span></td><td>'+esc(r.category)+'</td><td>'+tag(r.risk_level)+'</td><td>'+esc(r.score||"—")+'</td><td>'+tag(r.latest_result)+'</td><td>'+esc(r.current_evidence)+'</td><td>'+esc(r.open_findings)+'</td><td>'+fmtDate(r.next_due)+'</td></tr>').join("");
}
function renderLibrary(){
  if(!$("#libraryGrid"))return;
  const q=$("#librarySearch")?.value?.toLowerCase()||"",cat=$("#libraryCategory")?.value||"",risk=$("#libraryRisk")?.value||"";
  const rows=(state.library||[]).filter(x=>(!q||(x.code+" "+x.title+" "+x.description+" "+x.framework).toLowerCase().includes(q))&&(!cat||x.category===cat)&&(!risk||x.risk===risk));
  $("#libraryGrid").innerHTML=rows.length?rows.map(x=>'<article class="library-card"><div class="integration-card-head"><span class="control-code">'+esc(x.code)+'</span>'+tag(x.risk)+'</div><h3>'+esc(x.title)+'</h3><p>'+esc(x.description)+'</p><div class="library-meta"><span>'+esc(x.category)+'</span><span>'+esc(x.framework)+'</span></div><div class="library-foot"><span>'+esc(x.frequency)+'</span>'+(x.active?'<span class="active-in-register">✓ In register</span>':'<button class="action-btn" data-add-library="'+esc(x.code)+'">Add to register</button>')+'</div></article>').join(""):'<div class="empty-state">No library controls match the current filters.</div>';
  $$("[data-add-library]").forEach(b=>b.onclick=async()=>{try{await api("/api/control-library/"+encodeURIComponent(b.dataset.addLibrary)+"/add",{method:"POST",body:"{}"});toast("Control added to register");await refresh(["controls","library","dashboard","audit"])}catch(e){toast(e.message)}});
}
function renderAudit(){
  if(!$("#auditBody"))return;
  const search=$("#auditSearch")?.value?.toLowerCase()||"",action=$("#auditAction")?.value||"",entity=$("#auditEntity")?.value||"";
  const rows=(state.audit||[]).filter(a=>(!search||(String(a.user_name||"")+" "+String(a.email||"")+" "+String(a.action||"")+" "+String(a.entity_type||"")+" "+JSON.stringify(a.details||{})).toLowerCase().includes(search))&&(!action||a.action===action)&&(!entity||a.entity_type===entity));
  $("#auditBody").innerHTML=rows.length?rows.map(a=>'<tr><td>'+fmtTime(a.created_at)+'</td><td class="control-name"><b>'+esc(a.user_name||"System")+'</b><span>'+esc(a.email||"")+'</span></td><td><b>'+esc(a.action)+'</b></td><td>'+esc(a.entity_type)+'</td><td>'+esc(a.entity_id??"—")+'</td><td>'+esc(JSON.stringify(a.details||{}).slice(0,180))+'</td></tr>').join(""):'<tr><td colspan="6" class="empty-state">No audit activity matches the current filters.</td></tr>';
  if($("#auditAction")){
    const old=$("#auditAction").value,vals=[...new Set((state.audit||[]).map(x=>x.action))].sort();
    $("#auditAction").innerHTML='<option value="">All actions</option>'+vals.map(x=>'<option>'+esc(x)+'</option>').join("");
    $("#auditAction").value=old;
  }
  if($("#auditEntity")){
    const old=$("#auditEntity").value,vals=[...new Set((state.audit||[]).map(x=>x.entity_type))].sort();
    $("#auditEntity").innerHTML='<option value="">All entities</option>'+vals.map(x=>'<option>'+esc(x)+'</option>').join("");
    $("#auditEntity").value=old;
  }
}
function renderUsers(){
  $("#usersBody").innerHTML=state.users.length?state.users.map(u=>'<tr><td class="control-name"><b>'+esc(u.name)+'</b></td><td>'+esc(u.email)+'</td><td>'+tag(humanRole(u.role))+'</td><td>'+tag(u.status)+'</td><td>'+fmtDate(u.created_at)+'</td><td>'+(has("users.write")&&u.id!==state.user?.id?'<button class="action-btn" data-user-status="'+u.id+'" data-next-status="'+(u.status==="active"?"disabled":"active")+'">'+(u.status==="active"?"Disable":"Enable")+'</button>':'')+'</td></tr>').join(""):'<tr><td colspan="6" class="empty-state">No users available.</td></tr>';
  $("[data-user-status]").forEach(b=>b.onclick=()=>setUserStatus(Number(b.dataset.userStatus),b.dataset.nextStatus));
}
function renderSettings(){
  if(!state.organization||!$("#orgSettingsForm"))return;
  const f=$("#orgSettingsForm");["name","industry","country","timezone","contact_email"].forEach(k=>{if(f.elements[k])f.elements[k].value=state.organization[k]||""});
}
function populateFilters(){
  const cats=[...new Set(state.controls.map(c=>c.category))].sort();
  if($("#categoryFilter")){const old=$("#categoryFilter").value;$("#categoryFilter").innerHTML='<option value="">All control areas</option>'+cats.map(c=>'<option>'+esc(c)+'</option>').join("");$("#categoryFilter").value=old}
  if($("#integrationCategory")){const cats2=[...new Set(state.integrations.map(i=>i.category))].sort(),old=$("#integrationCategory").value;$("#integrationCategory").innerHTML='<option value="">All categories</option>'+cats2.map(c=>'<option>'+esc(c)+'</option>').join("");$("#integrationCategory").value=old}
  if($("#libraryCategory")){const lc=[...new Set((state.library||[]).map(i=>i.category))].sort(),old=$("#libraryCategory").value;$("#libraryCategory").innerHTML='<option value="">All control areas</option>'+lc.map(x=>'<option>'+esc(x)+'</option>').join("");$("#libraryCategory").value=old}
}
async function openControl(id){
  try{
    const d=await api("/api/controls/"+id);state.currentControl=d;
    const c=d.control;
    $("#controlDetail").innerHTML='<div class="control-detail-head"><div><span class="caps">CONTROL RECORD</span><h1>'+esc(c.control_code)+' · '+esc(c.title)+'</h1><p>'+esc(c.description)+'</p></div><div class="toolbar-actions"><button class="btn outline" data-back-register>Back</button>'+(has("controls.write")?'<button class="btn outline" data-edit-control="'+c.id+'">Edit</button>':'')+(has("assessments.write")?'<button class="btn dark" data-detail-test="'+c.id+'">Test control</button>':'')+'</div></div>'+
    '<div class="detail-grid"><div class="detail-card"><small>CONTROL AREA</small><b>'+esc(c.category)+'</b></div><div class="detail-card"><small>OWNER</small><b>'+esc(c.owner||"Unassigned")+'</b></div><div class="detail-card"><small>FREQUENCY</small><b>'+esc(c.frequency)+'</b></div><div class="detail-card"><small>RISK</small><b>'+tag(c.risk_level)+'</b></div><div class="detail-card"><small>FRAMEWORK</small><b>'+esc(c.framework_ref||"—")+'</b></div><div class="detail-card"><small>EVIDENCE EXPECTATION</small><b>'+esc(c.evidence_required||"—")+'</b></div></div>'+
    '<section class="detail-section panel"><div class="panel-head"><div><span class="caps">EVIDENCE</span><h3>Evidence attached to this control</h3></div></div>'+(d.evidence.length?d.evidence.map(e=>'<div class="activity-item"><span>▣</span><div><b>'+esc(e.title)+'</b><small>'+esc(e.source)+' · '+tag(e.review_status)+'</small></div><time>'+fmtDate(e.created_at)+'</time></div>').join(""):'<div class="empty-state">No evidence yet.</div>')+'</section>'+
    '<section class="detail-section panel"><div class="panel-head"><div><span class="caps">TEST HISTORY</span><h3>Recorded control tests</h3></div></div>'+(d.tests.length?d.tests.map(t=>'<div class="activity-item"><span>✓</span><div><b>'+esc(t.period)+' · '+esc(t.result)+'</b><small>'+esc(t.tester_name||"—")+' · Score '+esc(t.score??"—")+'%</small></div><time>'+fmtDate(t.tested_at)+'</time></div>').join(""):'<div class="empty-state">This control has not been tested.</div>')+'</section>'+
    '<section class="detail-section panel"><div class="panel-head"><div><span class="caps">ISSUES</span><h3>Findings and remediation</h3></div></div>'+(d.findings.length?d.findings.map(x=>'<div class="activity-item"><span>!</span><div><b>'+esc(x.title)+'</b><small>'+esc(x.owner||"Unassigned")+' · '+esc(x.status)+'</small></div><time>'+fmtDate(x.due_date)+'</time></div>').join(""):'<div class="empty-state">No findings linked to this control.</div>')+'</section>';
    go("controlDetail");$("[data-back-register]").onclick=()=>go("controls");if($("[data-detail-test]"))$("[data-detail-test]").onclick=()=>openTestControl(id);if($("[data-edit-control]"))$("[data-edit-control]").onclick=()=>editControl(c);
  }catch(e){toast(e.message)}
}
async function openTestControl(id){
  try{
    const d=await api("/api/controls/"+id),c=d.control;
    const ev=d.evidence||[];
    modal('<span class="caps">TEST CONTROL</span><h2>'+esc(c.control_code)+' · '+esc(c.title)+'</h2><p>Review available evidence, document the procedure performed, record the test result and raise a finding if an exception requires remediation.</p><form class="form" id="testControlForm"><div class="form-grid"><label>Testing period<input name="period" required placeholder="Q3 2026"></label><label>Score (0-100)<input name="score" type="number" min="0" max="100" required></label></div><label>Test objective<textarea name="test_objective" required placeholder="What are you testing and why?"></textarea></label><label>Test procedure<textarea name="test_procedure" required placeholder="Describe the sample and steps performed."></textarea></label><div class="form-grid"><label>Sample size<input name="sample_size" type="number" min="0"></label><label>Exceptions found<input name="exception_count" type="number" min="0" value="0"></label></div><label>Evidence used</label><div class="check-grid">'+(ev.length?ev.map(e=>'<label class="check-row"><input type="checkbox" name="evidence_ids" value="'+e.id+'"><span><b>'+esc(e.title)+'</b><br>'+esc(e.source)+' · '+esc(e.review_status)+'</span></label>').join(""):'<div class="manual-tip">No evidence is attached to this control yet. You can still document the test, but add evidence before review.</div>')+'</div><div class="form-grid"><label>Design effectiveness<select name="design_effective"><option value="">Not assessed</option><option value="true">Effective</option><option value="false">Ineffective</option></select></label><label>Operating effectiveness<select name="operating_effective"><option value="">Not assessed</option><option value="true">Effective</option><option value="false">Ineffective</option></select></label></div><label>Overall result<select name="result"><option>Effective</option><option>Partially Effective</option><option>Ineffective</option></select></label><label>Tester notes<textarea name="notes" placeholder="Document observations, exceptions and conclusion."></textarea></label><label class="check-row"><input type="checkbox" id="raiseFinding" name="raise_finding"><span><b>Raise a finding from this test</b><br>Create a remediation issue when the result is not Effective.</span></label><div id="findingFields" class="hidden"><label>Finding title<input name="finding_title"></label><label>Finding severity<select name="finding_severity"><option>High</option><option selected>Medium</option><option>Low</option></select></label></div><div class="form-actions"><button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Save control test</button></div></form>',true);
    $("#raiseFinding").onchange=e=>$("#findingFields").classList.toggle("hidden",!e.target.checked);
    $("#testControlForm").onsubmit=async e=>{
      e.preventDefault();const fd=new FormData(e.target),ids=fd.getAll("evidence_ids").map(Number);
      const bool=v=>v===""?null:v==="true";
      const payload={period:fd.get("period"),score:Number(fd.get("score")),test_objective:fd.get("test_objective"),test_procedure:fd.get("test_procedure"),sample_size:fd.get("sample_size")===""?null:Number(fd.get("sample_size")),exception_count:Number(fd.get("exception_count")||0),evidence_ids:ids,design_effective:bool(fd.get("design_effective")),operating_effective:bool(fd.get("operating_effective")),result:fd.get("result"),notes:fd.get("notes")||"",raise_finding:fd.get("raise_finding")==="on",finding_title:fd.get("finding_title")||undefined,finding_severity:fd.get("finding_severity")||undefined};
      try{await api("/api/controls/"+id+"/test",{method:"POST",body:JSON.stringify(payload)});closeModal();toast("Control test recorded");await refresh(["controls","assessments","findings","dashboard","audit"]);if(state.page==="controlDetail")openControl(id)}catch(err){toast(err.message)}
    };
  }catch(e){toast(e.message)}
}
function startGenericTest(){
  modal('<span class="caps">TEST CONTROL</span><h2>Select the control to test</h2><p>Choose an active control. The next step will load its evidence and testing record.</p><form class="form" id="selectTestForm"><label>Control<select name="control_id" required><option value="">Select control</option>'+state.controls.map(c=>'<option value="'+c.id+'">'+esc(c.control_code+" · "+c.title)+'</option>').join("")+'</select></label><div class="form-actions"><button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Continue</button></div></form>');
  $("#selectTestForm").onsubmit=e=>{e.preventDefault();const id=Number(new FormData(e.target).get("control_id"));closeModal();openTestControl(id)};
}
function openUploadEvidence(){
  modal('<span class="caps">EVIDENCE VAULT</span><h2>Upload source evidence</h2><p>The file is stored in the private workspace and receives a SHA-256 fingerprint at upload.</p><form class="form" id="uploadEvidenceForm"><label>Control<select name="control_id" required><option value="">Select control</option>'+state.controls.map(c=>'<option value="'+c.id+'">'+esc(c.control_code+" · "+c.title)+'</option>').join("")+'</select></label><label>Evidence title<input name="title" required></label><div class="form-grid"><label>Period<input name="period" placeholder="Q3 2026"></label><label>Evidence type<select name="evidence_type"><option>Document</option><option>System Report</option><option>Screenshot</option><option>Approval</option><option>Log Extract</option></select></label></div><label>Source file<input name="file" type="file" required></label><div class="manual-tip">Maximum file size: 8 MB. The original file is preserved with its SHA-256 integrity fingerprint.</div><div class="form-actions"><button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Upload evidence</button></div></form>');
  $("#uploadEvidenceForm").onsubmit=async e=>{e.preventDefault();const fd=new FormData(e.target);try{await api("/api/evidence/upload",{method:"POST",body:fd});closeModal();toast("Evidence uploaded and fingerprinted");await refresh(["evidence","controls","dashboard","audit"])}catch(err){toast(err.message)}};
}
function openLinkEvidence(){
  modal('<span class="caps">EVIDENCE VAULT</span><h2>Register an evidence source</h2><p>Use this for an approved external repository or evidence link. For local source files, use Upload file.</p><form class="form" id="linkEvidenceForm"><label>Control<select name="control_id" required><option value="">Select control</option>'+state.controls.map(c=>'<option value="'+c.id+'">'+esc(c.control_code+" · "+c.title)+'</option>').join("")+'</select></label><label>Evidence title<input name="title" required></label><div class="form-grid"><label>Type<select name="evidence_type"><option>Document</option><option>System Report</option><option>Approval</option><option>Log Extract</option></select></label><label>Period<input name="period" placeholder="Q3 2026"></label></div><label>Source name<input name="source" placeholder="SharePoint / ServiceNow / Internal repository"></label><label>Evidence URL<input name="url" type="url" required placeholder="https://..."></label><div class="form-actions"><button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Register evidence</button></div></form>');
  $("#linkEvidenceForm").onsubmit=async e=>{e.preventDefault();const d=Object.fromEntries(new FormData(e.target).entries());d.control_id=Number(d.control_id);try{await api("/api/evidence",{method:"POST",body:JSON.stringify(d)});closeModal();toast("Evidence source registered");await refresh(["evidence","controls","dashboard","audit"])}catch(err){toast(err.message)}};
}
async function downloadEvidence(id){
  try{const r=await fetch("/api/evidence/files/"+id,{headers:{Authorization:"Bearer "+state.token}});if(!r.ok)throw new Error("Unable to download evidence");const blob=await r.blob(),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download="evidence";document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url)}catch(e){toast(e.message)}
}
function reviewEvidence(id){
  const e=state.evidence.find(x=>x.id===id);modal('<span class="caps">EVIDENCE REVIEW</span><h2>'+esc(e?.title||"Review evidence")+'</h2><form class="form" id="reviewEvidenceForm"><label>Decision<select name="review_status"><option>Approved</option><option>Needs Update</option><option>Rejected</option></select></label><label>Review notes<textarea name="review_notes" placeholder="Explain the review conclusion."></textarea></label><div class="form-actions"><button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Record review</button></div></form>');
  $("#reviewEvidenceForm").onsubmit=async ev=>{ev.preventDefault();const d=Object.fromEntries(new FormData(ev.target).entries());try{await api("/api/evidence/"+id+"/review",{method:"POST",body:JSON.stringify(d)});closeModal();toast("Evidence review recorded");await refresh(["evidence","audit"])}catch(err){toast(err.message)}};
}
async function verifyEvidence(id){
  try{
    const d=await api("/api/evidence/"+id+"/verify",{method:"POST",body:"{}"});
    toast(d.valid?"Integrity verified: SHA-256 matches":"Integrity verification failed");
    await refresh(["audit"]);
  }catch(e){toast(e.message)}
}
function reviewAssessment(id){
  const a=state.assessments.find(x=>x.id===id);
  modal('<span class="caps">TEST REVIEW</span><h2>Review control test</h2><p>'+esc(a?.control_code||"")+' · '+esc(a?.control_title||"")+' · '+esc(a?.period||"")+'</p><form class="form" id="reviewTestForm"><label>Review decision<select name="review_status"><option>Reviewed</option><option>Needs Rework</option><option>Rejected</option></select></label><label>Review notes<textarea name="review_notes" required placeholder="Document the reviewer conclusion."></textarea></label><div class="form-actions"><button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Record review</button></div></form>');
  $("#reviewTestForm").onsubmit=async e=>{
    e.preventDefault();
    const d=Object.fromEntries(new FormData(e.target).entries());
    try{await api("/api/assessments/"+id+"/review",{method:"POST",body:JSON.stringify(d)});closeModal();toast("Test review recorded");await refresh(["assessments","audit"])}
    catch(err){toast(err.message)}
  };
}
function editControl(control){
  const options=(values,current)=>values.map(x=>'<option '+(x===current?"selected":"")+'>'+x+'</option>').join("");
  modal('<span class="caps">CONTROL REGISTER</span><h2>Edit '+esc(control.control_code)+'</h2><form class="form" id="editControlForm"><label>Title<input name="title" required value="'+esc(control.title)+'"></label><label>Description<textarea name="description">'+esc(control.description||"")+'</textarea></label><div class="form-grid"><label>Control area<input name="category" value="'+esc(control.category)+'"></label><label>Framework mapping<input name="framework_ref" value="'+esc(control.framework_ref||"")+'"></label><label>Owner / function<input name="owner" value="'+esc(control.owner||"")+'"></label><label>Assigned officer<select name="assigned_user_id">'+officerOptions(control.assigned_user_id)+'</select></label><label>Frequency<select name="frequency">'+options(["Continuous","Daily","Weekly","Monthly","Quarterly","Semi-Annual","Annual"],control.frequency)+'</select></label><label>Risk<select name="risk_level">'+options(["High","Medium","Low"],control.risk_level)+'</select></label><label>Status<select name="status">'+options(["Active","Inactive"],control.status)+'</select></label></div><label>Required evidence<textarea name="evidence_required">'+esc(control.evidence_required||"")+'</textarea></label><div class="form-actions"><button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Save changes</button></div></form>');
  $("#editControlForm").onsubmit=async e=>{
    e.preventDefault();
    const d=Object.fromEntries(new FormData(e.target).entries());d.assigned_user_id=d.assigned_user_id?Number(d.assigned_user_id):null;
    try{await api("/api/controls/"+control.id,{method:"PUT",body:JSON.stringify(d)});closeModal();toast("Control updated");await refresh(["controls","dashboard","audit"]);await openControl(control.id)}
    catch(err){toast(err.message)}
  };
}
async function setUserStatus(id,status){
  if(!confirm((status==="disabled"?"Disable":"Enable")+" this user account?"))return;
  try{await api("/api/users/"+id+"/status",{method:"PUT",body:JSON.stringify({status})});toast("User status updated");await refresh(["users","audit"])}
  catch(e){toast(e.message)}
}
async function connectGithub(){
  modal('<span class="caps">GITHUB · LIVE CONNECTOR</span><h2>Connect GitHub</h2><p>Use a GitHub fine-grained personal access token or classic token with read access to the repositories you want to assess. The token is encrypted before it is stored.</p><form class="form" id="githubConnectForm"><label>GitHub token<input name="token" type="password" required autocomplete="off" placeholder="github_pat_..."></label><div class="manual-tip"><b>Recommended permissions:</b> repository metadata/read, contents/read, pull requests/read, actions/read, and security-event read permissions where your plan and repository permit them.</div><div class="form-actions"><button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Validate & connect</button></div></form>');
  $("#githubConnectForm").onsubmit=async e=>{e.preventDefault();const token=new FormData(e.target).get("token");try{await api("/api/integrations/github/connect",{method:"POST",body:JSON.stringify({token,repositories:[]})});closeModal();toast("GitHub connected");await refresh(["integrations","audit"]);await manageGithubRepos()}catch(err){toast(err.message)}};
}
async function manageGithubRepos(){
  try{
    const d=await api("/api/integrations/github/repositories");const selected=new Set(d.selected||[]);
    modal('<span class="caps">GITHUB REPOSITORIES</span><h2>Select repositories for control evidence</h2><p>Only selected repositories will be included in routine evidence collection. If none are selected, a sync scans up to 20 recent non-archived repositories.</p><form class="form" id="githubReposForm"><div class="check-grid">'+d.repositories.map(r=>'<label class="check-row"><input type="checkbox" name="repositories" value="'+esc(r.full_name)+'" '+(selected.has(r.full_name)?"checked":"")+'><span><b>'+esc(r.full_name)+'</b><br>'+(r.private?"Private":"Public")+' · default '+esc(r.default_branch)+'</span></label>').join("")+'</div><div class="form-actions"><button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Save selection</button></div></form>',true);
    $("#githubReposForm").onsubmit=async e=>{e.preventDefault();const repos=new FormData(e.target).getAll("repositories");try{await api("/api/integrations/github/config",{method:"PUT",body:JSON.stringify({repositories:repos})});closeModal();toast("GitHub repository selection saved");await refresh(["integrations","audit"])}catch(err){toast(err.message)}};
  }catch(e){toast(e.message)}
}
async function syncGithub(){
  const ok=confirm("Collect fresh GitHub control evidence from the selected repositories now?");if(!ok)return;
  try{toast("GitHub sync started");const d=await api("/api/integrations/github/sync",{method:"POST",body:"{}"});toast("GitHub sync complete: "+d.evidenceCreated+" evidence item(s), "+d.findingsCreated+" finding(s)");await refresh(["integrations","evidence","findings","controls","dashboard","audit"])}catch(e){toast(e.message)}
}
async function disconnectGithub(){
  if(!confirm("Disconnect GitHub? Existing evidence remains in the vault."))return;
  try{await api("/api/integrations/github/connection",{method:"DELETE"});toast("GitHub disconnected");await refresh(["integrations","audit"])}catch(e){toast(e.message)}
}
function officerOptions(selected=""){
  const users=(state.users||[]).filter(u=>["control_manager","control_officer"].includes(u.role)&&u.status==="active");
  if(state.user?.role==="control_officer"&&!users.some(u=>u.id===state.user.id))users.push(state.user);
  return '<option value="">Unassigned</option>'+users.map(u=>'<option value="'+u.id+'" '+(String(u.id)===String(selected)?"selected":"")+'>'+esc(u.name)+' · '+esc(humanRole(u.role))+'</option>').join("");
}
function createControlForm(){
  modal('<span class="caps">CONTROL REGISTER</span><h2>Create control</h2><form class="form" id="controlForm"><div class="form-grid"><label>Control code<input name="control_code" required placeholder="ITGC-013"></label><label>Risk<select name="risk_level"><option>High</option><option selected>Medium</option><option>Low</option></select></label></div><label>Title<input name="title" required></label><label>Description<textarea name="description"></textarea></label><div class="form-grid"><label>Area<input name="category" required></label><label>Framework mapping<input name="framework_ref"></label><label>Owner / function<input name="owner"></label><label>Assigned officer<select name="assigned_user_id">'+officerOptions()+'</select></label><label>Frequency<select name="frequency"><option>Continuous</option><option>Daily</option><option>Weekly</option><option>Monthly</option><option selected>Quarterly</option><option>Semi-Annual</option><option>Annual</option></select></label></div><label>Required evidence<textarea name="evidence_required"></textarea></label><div class="form-actions"><button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Create control</button></div></form>');
  $("#controlForm").onsubmit=async e=>{e.preventDefault();const d=Object.fromEntries(new FormData(e.target).entries());d.assigned_user_id=d.assigned_user_id?Number(d.assigned_user_id):null;try{await api("/api/controls",{method:"POST",body:JSON.stringify(d)});closeModal();toast("Control created");await refresh(["controls","dashboard","audit"])}catch(err){toast(err.message)}};
}
function createFindingForm(){
  modal('<span class="caps">ISSUES & REMEDIATION</span><h2>Create finding</h2><form class="form" id="findingForm"><label>Linked control<select name="control_id"><option value="">No linked control</option>'+state.controls.map(c=>'<option value="'+c.id+'">'+esc(c.control_code+" · "+c.title)+'</option>').join("")+'</select></label><label>Finding title<input name="title" required></label><label>Description<textarea name="description"></textarea></label><div class="form-grid"><label>Severity<select name="severity"><option>High</option><option selected>Medium</option><option>Low</option></select></label><label>Status<select name="status"><option>Open</option><option>In Progress</option></select></label><label>Owner<input name="owner"></label><label>Due date<input name="due_date" type="date"></label></div><div class="form-actions"><button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Create finding</button></div></form>');
  $("#findingForm").onsubmit=async e=>{e.preventDefault();const d=Object.fromEntries(new FormData(e.target).entries());d.control_id=d.control_id?Number(d.control_id):null;d.due_date=d.due_date||null;try{await api("/api/findings",{method:"POST",body:JSON.stringify(d)});closeModal();toast("Finding created");await refresh(["findings","dashboard","audit"])}catch(err){toast(err.message)}};
}
function createUserForm(){
  modal('<span class="caps">SETTINGS & TEAM</span><h2>Add user</h2><form class="form" id="userForm"><label>Full name<input name="name" required></label><label>Email<input name="email" type="email" required></label><label>Temporary password<input name="password" type="password" minlength="8" required></label><label>Role<select name="role"><option value="control_manager">Control Manager</option><option value="control_officer">Control Officer</option><option value="auditor">Auditor</option><option value="reviewer">Reviewer</option><option value="viewer">Viewer</option><option value="admin">Admin</option></select></label><div class="form-actions"><button type="button" class="btn outline" data-close-modal>Cancel</button><button class="btn dark">Create user</button></div></form>');
  $("#userForm").onsubmit=async e=>{e.preventDefault();const d=Object.fromEntries(new FormData(e.target).entries());try{await api("/api/users",{method:"POST",body:JSON.stringify(d)});closeModal();toast("User created");await refresh(["users","audit"])}catch(err){toast(err.message)}};
}
const manual={
start:['Getting started','Revolt-X Control is built around one assurance chain: define the control, collect evidence, test the control, record exceptions, remediate and retest.','<h3>Recommended first-day setup</h3><ol><li>Review Settings & team and confirm who can administer, manage controls, test, review and view.</li><li>Open Control register and tailor owners, frequency, risk and evidence expectations.</li><li>Connect approved source systems under Integrations.</li><li>Upload or collect evidence into Evidence vault.</li><li>Use Testing & assurance to test controls using the evidence collected.</li></ol><div class="manual-tip">A control should not be treated as compliant merely because it exists. Its assurance status comes from evidence and a documented test.</div>'],
controls:['Controls','The Control register is the organisation’s active set of IT controls. The Control library groups the same catalogue by area to help teams navigate it.','<h3>Working with a control</h3><ol><li>Open Control register.</li><li>Search by code or title, or filter by area and risk.</li><li>Select Open to see description, owner, evidence expectation, evidence, test history and findings.</li><li>Use Test control when evidence is ready.</li></ol><h3>Good control ownership</h3><p>Every control should have an accountable owner, a realistic test frequency and a clear statement of expected evidence.</p>'],
evidence:['Evidence vault','The Evidence vault stores uploaded source files, approved external links and structured evidence collected from connected systems.','<h3>Upload evidence</h3><ol><li>Select Upload file.</li><li>Choose the related control and period.</li><li>Select the original source file.</li><li>The platform calculates a SHA-256 fingerprint and records the upload in the audit trail.</li><li>A reviewer can mark evidence Approved, Needs Update or Rejected with review notes.</li></ol><div class="manual-tip">Do not edit a source file after it has been approved. Upload the revised file as new evidence so the chain remains traceable.</div>'],
testing:['Test Control','Test Control is the core operating-effectiveness workflow. It links the procedure performed to the evidence used and the conclusion reached.','<h3>How to test a control</h3><ol><li>Open Testing & assurance and choose Test control, or start from the control record.</li><li>Enter the testing period and test objective.</li><li>Document the exact procedure and sample size.</li><li>Select the evidence actually used.</li><li>Record design effectiveness, operating effectiveness, exception count, overall result and score.</li><li>If the result is not Effective, optionally create a finding directly from the test.</li></ol>'],
issues:['Findings & retesting','Findings track control exceptions through accountable remediation.','<h3>Closure rule</h3><p>For a finding linked to a control, the system requires a passing Effective retest after the finding was raised before the finding can be closed.</p><ol><li>Assign an owner and due date.</li><li>Move the issue to In Progress while remediation is underway.</li><li>Retest the related control after remediation.</li><li>Once a passing retest exists, close the finding.</li></ol>'],
github:['Integrations','Integrations collect evidence from the source system only after credentials are validated. Secrets are encrypted before storage and a connector is never shown as Connected merely because a form was saved.','<h3>Live direct connectors</h3><p>GitHub, Microsoft Entra, Microsoft 365, Jira, ServiceNow, Splunk, Tenable and CrowdStrike have live connection and evidence-sync adapters in the current release.</p><h3>Standard connection flow</h3><ol><li>Open Integrations.</li><li>Select Connect on a live adapter.</li><li>Use a dedicated read-only or least-privilege integration identity.</li><li>The platform validates the provider before saving the encrypted credential.</li><li>Select Sync now to create current evidence and any defined control findings.</li></ol><h3>GitHub evidence</h3><ul><li>Repository metadata and direct collaborators.</li><li>Default-branch protection and pull-request history.</li><li>Actions workflows and Actions permissions.</li><li>Secret-scanning, code-scanning and Dependabot alerts where the repository and token permit access.</li></ul><div class="manual-tip">Private-network systems must use the planned Revolt-X Connector Agent. The public cloud service intentionally refuses localhost and private-address connector URLs.</div>'],
audit:['Audit & reporting','The Audit trail records material activity across controls, evidence, testing, findings, integrations, users and exports.','<h3>Audit pack</h3><p>Use Download audit pack to export the control register with current testing, evidence and finding information for audit or management review.</p><p>Use the trail to establish who performed an action, when it occurred and which record was affected.</p>'],
roles:['Roles & access','Role-based access separates administration, control management, testing, review and read-only access.','<ul><li><b>Admin:</b> full workspace administration.</li><li><b>Control Manager:</b> control, testing, evidence and issue workflows.</li><li><b>Auditor:</b> testing, evidence and audit review.</li><li><b>Reviewer:</b> oversight and remediation review.</li><li><b>Viewer:</b> read-only assurance access.</li></ul><div class="manual-tip">Use the least-privilege role that allows the person to perform their assigned work.</div>']
};
function renderManual(key){
  if(!$("#manualContent"))return;const m=manual[key]||manual.start;$("#manualContent").innerHTML='<span class="caps">USER MANUAL</span><h2>'+m[0]+'</h2><p>'+m[1]+'</p>'+m[2];
  $$("[data-manual]").forEach(b=>b.classList.toggle("active",b.dataset.manual===key));
}
function bindPageLinks(){$$("[data-page-link]").forEach(b=>b.onclick=()=>go(b.dataset.pageLink))}
function bindOpenForms(){
  $$("[data-open-form]").forEach(b=>b.onclick=()=>{const t=b.dataset.openForm;if(t==="control")createControlForm();if(t==="evidence")openLinkEvidence();if(t==="finding")createFindingForm();if(t==="user")createUserForm()});
}
async function downloadFileFromApi(url,filename){
  try{
    const r=await fetch(url,{headers:{Authorization:"Bearer "+state.token}});
    if(!r.ok){let m="Download failed";try{const d=await r.json();m=d.error||m}catch{}throw new Error(m)}
    const blob=await r.blob(),obj=URL.createObjectURL(blob),a=document.createElement("a");
    a.href=obj;a.download=filename;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(obj);
  }catch(e){toast(e.message)}
}
async function downloadAuditPack(){await downloadFileFromApi("/api/reports/audit-pack.zip","revolt-x-it-controls-audit-pack.zip");toast("Full audit pack generated")}
async function downloadAuditCsv(){await downloadFileFromApi("/api/reports/audit-pack.csv","revolt-x-it-controls-controls.csv")}


$("#loginForm").addEventListener("submit",login);$("#logoutBtn").onclick=logout;$("#refreshBtn").onclick=loadAll;$("#menuBtn").onclick=()=>$(".sidebar").classList.toggle("open");
$$("[data-page]").forEach(b=>b.onclick=()=>go(b.dataset.page));
bindPageLinks();bindOpenForms();bindModalClose();
$("#modal").addEventListener("click",e=>{if(e.target.matches("[data-close-modal]"))closeModal()});
$("#uploadEvidenceBtn").onclick=openUploadEvidence;$("#startTestBtn").onclick=startGenericTest;$("#startTestBtn2").onclick=startGenericTest;$("#testControlTopBtn")?.addEventListener("click",startGenericTest);$("#manualBtn")?.addEventListener("click",()=>go("manual"));$("#auditPackBtn").onclick=downloadAuditPack;$("#auditCsvBtn")?.addEventListener("click",downloadAuditCsv);$("#healthAuditPackBtn")?.addEventListener("click",downloadAuditPack);
$("#orgSettingsForm")?.addEventListener("submit",async e=>{
  e.preventDefault();
  const d=Object.fromEntries(new FormData(e.target).entries());
  try{state.organization=await api("/api/settings/organization",{method:"PUT",body:JSON.stringify(d)});toast("Organisation settings saved")}
  catch(err){toast(err.message)}
});
$("#changePasswordForm")?.addEventListener("submit",async e=>{
  e.preventDefault();
  const d=Object.fromEntries(new FormData(e.target).entries());
  try{await api("/api/auth/change-password",{method:"POST",body:JSON.stringify(d)});e.target.reset();toast("Password changed")}
  catch(err){toast(err.message)}
});
$("[data-manual]").forEach(b=>b.onclick=()=>renderManual(b.dataset.manual));
["controlSearch","categoryFilter","riskFilter"].forEach(id=>$("#"+id)?.addEventListener(id==="controlSearch"?"input":"change",renderControls));
["integrationSearch","integrationCategory","integrationStatus"].forEach(id=>$("#"+id)?.addEventListener(id==="integrationSearch"?"input":"change",renderIntegrations));
["librarySearch","libraryCategory","libraryRisk"].forEach(id=>$("#"+id)?.addEventListener(id==="librarySearch"?"input":"change",renderLibrary));
["auditSearch","auditAction","auditEntity"].forEach(id=>$("#"+id)?.addEventListener(id==="auditSearch"?"input":"change",renderAudit));
["progressPeriod","progressFrequency","progressOfficer"].forEach(id=>$("#"+id)?.addEventListener("change",loadProgress));
restore();
