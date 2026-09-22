const state={token:localStorage.getItem("revolt_token")||"",user:null,permissions:[],controls:[],assessments:[],evidence:[],findings:[],integrations:[],automation:[],report:[],audit:[],users:[],dashboard:null,page:"overview"};
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const fmtDate=v=>v?new Date(v).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"}):"—";
const fmtTime=v=>v?new Date(v).toLocaleString("en-GB",{day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit"}):"—";
const tag=v=>'<span class="tag '+String(v||"").toLowerCase().replace(/\s+/g,"-")+'">'+esc(v||"—")+"</span>";
const has=p=>state.permissions.includes(p);
function toast(msg){const t=$("#toast");t.textContent=msg;t.classList.add("show");setTimeout(()=>t.classList.remove("show"),2200)}
async function api(url,opt={}){
  const headers={"Content-Type":"application/json",...(opt.headers||{})}; if(state.token)headers.Authorization="Bearer "+state.token;
  const r=await fetch(url,{...opt,headers}); let data={}; try{data=await r.json()}catch{}
  if(r.status===401&&url!=="/api/auth/login"){logout();throw new Error("Session expired")}
  if(!r.ok)throw new Error(data.error||"Request failed"); return data;
}
function initials(name){return String(name||"RX").split(/\s+/).slice(0,2).map(x=>x[0]).join("").toUpperCase()}
function humanRole(r){return String(r||"").replace(/_/g," ").replace(/\b\w/g,m=>m.toUpperCase())}
function loginView(show){$("#loginView").classList.toggle("hidden",!show);$("#appView").classList.toggle("hidden",show)}
async function login(e){
  e.preventDefault();$("#loginMessage").textContent="";
  try{
    const data=await api("/api/auth/login",{method:"POST",body:JSON.stringify({email:$("#loginEmail").value,password:$("#loginPassword").value})});
    state.token=data.token;state.user=data.user;state.permissions=data.permissions;localStorage.setItem("revolt_token",state.token);loginView(false);setupUser();await loadAll();
  }catch(err){$("#loginMessage").textContent=err.message}
}
function logout(){localStorage.removeItem("revolt_token");state.token="";state.user=null;loginView(true)}
function setupUser(){
  $("#userName").textContent=state.user?.name||"User";$("#userRole").textContent=humanRole(state.user?.role);$("#userInitials").textContent=initials(state.user?.name);
  $$("[data-permission]").forEach(el=>el.classList.toggle("hidden",!has(el.dataset.permission)));
}
async function restore(){
  if(!state.token)return loginView(true);
  try{const data=await api("/api/auth/me");state.user=data.user;state.permissions=data.permissions;loginView(false);setupUser();await loadAll()}catch{logout()}
}
async function loadAll(){
  document.body.classList.add("loading");
  try{
    const jobs=[api("/api/dashboard"),api("/api/controls"),api("/api/assessments"),api("/api/evidence"),api("/api/findings"),api("/api/integrations"),api("/api/automation"),api("/api/reports/control-health"),has("audit.read")?api("/api/audit"):Promise.resolve([]),has("users.read")?api("/api/users"):Promise.resolve([])];
    const [dashboard,controls,assessments,evidence,findings,integrations,automation,report,audit,users]=await Promise.all(jobs);
    Object.assign(state,{dashboard,controls,assessments,evidence,findings,integrations,automation,report,audit,users});renderAll();
  }catch(err){toast(err.message)}finally{document.body.classList.remove("loading")}
}
function renderAll(){renderDashboard();renderControls();renderAssessments();renderEvidence();renderIntegrations();renderAutomation();renderFindings();renderReports();renderAudit();renderUsers();populateFilters()}
function go(page){
  state.page=page;$$(".page").forEach(p=>p.classList.add("hidden"));$("#"+page+"Page")?.classList.remove("hidden");
  $$("[data-page]").forEach(b=>b.classList.toggle("active",b.dataset.page===page));
  const titles={overview:"Control Overview",controls:"Control Library",assessments:"Control Assessments",evidence:"Evidence Register",integrations:"Integration Hub",automation:"Evidence Automation",findings:"Findings & Remediation",reports:"Control Health",audit:"Audit Trail",users:"Users & Roles"};
  $("#pageTitle").textContent=titles[page]||"IT Controls";$(".sidebar").classList.remove("open");window.scrollTo(0,0);
}
function renderDashboard(){
  const d=state.dashboard||{};const c=d.controls||{},a=d.assessments||{},f=d.findings||{},e=d.evidence||{};
  const metrics=[
    ["Controls",c.total||0,(c.high_risk||0)+" high-risk","✓"],
    ["Effectiveness",(d.effectiveness||0)+"%",(a.total||0)+" assessments","◉"],
    ["Evidence",e.total||0,"registered items","▣"],
    ["Open findings",f.open||0,(f.high_open||0)+" high severity","!"],
    ["Tests completed",a.total||0,(a.ineffective||0)+" ineffective","↗"]
  ];
  $("#metricGrid").innerHTML=metrics.map(x=>'<div class="metric"><div class="metric-top"><small>'+esc(x[0])+'</small><span class="metric-icon">'+x[3]+'</span></div><strong>'+esc(x[1])+'</strong><p>'+esc(x[2])+'</p></div>').join("");
  const cats=d.categories||[],max=Math.max(1,...cats.map(x=>Number(x.total)));
  $("#categoryChart").innerHTML=cats.length?cats.slice(0,7).map(x=>'<div class="bar-row"><span title="'+esc(x.category)+'">'+esc(x.category)+'</span><div class="bar-track"><i style="width:'+(Number(x.total)/max*100)+'%"></i></div><b>'+x.total+"</b></div>").join(""):'<div class="empty-state">No control categories yet.</div>';
  $("#activityList").innerHTML=(d.recentActivity||[]).length?(d.recentActivity||[]).map(x=>'<div class="activity-item"><span>↺</span><div><b>'+esc(x.action)+" "+esc(x.entity_type)+'</b><small>'+esc(x.name||"System")+'</small></div><time>'+fmtTime(x.created_at)+"</time></div>").join(""):'<div class="empty-state">No activity yet.</div>';
  const open=state.findings.filter(x=>!["Closed","Resolved"].includes(x.status)).slice(0,5);
  $("#overviewFindings").innerHTML=open.length?'<div class="table-card"><table><thead><tr><th>Finding</th><th>Control</th><th>Severity</th><th>Owner</th><th>Due</th><th>Status</th></tr></thead><tbody>'+open.map(f=>'<tr><td class="control-name"><b>'+esc(f.title)+'</b></td><td>'+esc(f.control_code||"—")+'</td><td>'+tag(f.severity)+'</td><td>'+esc(f.owner||"Unassigned")+'</td><td>'+fmtDate(f.due_date)+'</td><td>'+tag(f.status)+'</td></tr>').join("")+"</tbody></table></div>":'<div class="empty-state">No open findings. Your control environment is clear of recorded exceptions.</div>';
}
function filteredControls(){
  const q=$("#controlSearch")?.value?.toLowerCase()||"",cat=$("#categoryFilter")?.value||"",risk=$("#riskFilter")?.value||"";
  return state.controls.filter(c=>(!q||(c.title+" "+c.control_code).toLowerCase().includes(q))&&(!cat||c.category===cat)&&(!risk||c.risk_level===risk));
}
function renderControls(){
  const rows=filteredControls();
  $("#controlsBody").innerHTML=rows.length?rows.map(c=>'<tr><td class="control-name"><b>'+esc(c.control_code)+" · "+esc(c.title)+'</b><span>'+esc(c.framework_ref||"No framework mapping")+'</span></td><td>'+esc(c.category)+'</td><td>'+esc(c.owner||"Unassigned")+'</td><td>'+esc(c.frequency)+'</td><td>'+tag(c.risk_level)+'</td><td>'+tag(c.latest_result||"Not Tested")+'</td><td>'+esc(c.evidence_count||0)+'</td><td>'+esc(c.open_findings||0)+"</td></tr>").join(""):'<tr><td colspan="8" class="empty-state">No controls match the current filters.</td></tr>';
}
function renderAssessments(){
  $("#assessmentsBody").innerHTML=state.assessments.length?state.assessments.map(a=>'<tr><td class="control-name"><b>'+esc(a.control_code)+" · "+esc(a.control_title)+'</b></td><td>'+esc(a.period)+'</td><td>'+tag(a.result)+'</td><td><b>'+esc(a.score??"—")+(a.score!=null?"%":"")+'</b></td><td>'+esc(a.tester_name||"—")+'</td><td>'+tag(a.review_status)+'</td><td>'+fmtDate(a.tested_at)+"</td></tr>").join(""):'<tr><td colspan="7" class="empty-state">No control assessments have been recorded yet.</td></tr>';
}
function renderEvidence(){
  $("#evidenceGrid").innerHTML=state.evidence.length?state.evidence.map(e=>'<article class="evidence-card"><div class="evidence-card-head"><span class="doc-icon">▣</span>'+tag(e.status)+'</div><h3>'+esc(e.title)+'</h3><p>'+esc(e.control_code)+" · "+esc(e.control_title)+'</p><div class="evidence-meta"><div><small>TYPE</small><b>'+esc(e.evidence_type)+'</b></div><div><small>SOURCE</small><b>'+esc(e.source)+'</b></div><div><small>PERIOD</small><b>'+esc(e.period||"—")+'</b></div><div><small>ADDED BY</small><b>'+esc(e.uploaded_by_name||"—")+"</b></div></div>"+(e.url?'<p><a href="'+esc(e.url)+'" target="_blank" rel="noopener">Open evidence source →</a></p>':"")+"</article>").join(""):'<div class="empty-state">No evidence has been registered yet.</div>';
}
function filteredIntegrations(){
  const q=$("#integrationSearch")?.value?.toLowerCase()||"",cat=$("#integrationCategory")?.value||"",status=$("#integrationStatus")?.value||"";
  return state.integrations.filter(i=>(!q||(i.name+" "+i.category+" "+(i.capabilities||[]).join(" ")).toLowerCase().includes(q))&&(!cat||i.category===cat)&&(!status||i.status===status));
}
function renderIntegrations(){
  const all=state.integrations, connected=all.filter(i=>i.status==="Connected").length, configured=all.filter(i=>i.status==="Configured").length;
  const automated=state.automation.length;
  $("#integrationSummary").innerHTML=[
    ["Available connectors",all.length,"Identity, cloud, ITSM, SIEM, endpoint and more"],
    ["Connected",connected,"Validated source connections"],
    ["Configured",configured,"Awaiting live connector validation"],
    ["Automation rules",automated,"Mapped control evidence rules"]
  ].map(x=>'<div class="metric"><small>'+esc(x[0])+'</small><strong>'+esc(x[1])+'</strong><p>'+esc(x[2])+'</p></div>').join("");
  const cats=[...new Set(all.map(i=>i.category))].sort(); if($("#integrationCategory")){const old=$("#integrationCategory").value;$("#integrationCategory").innerHTML='<option value="">All categories</option>'+cats.map(x=>'<option>'+esc(x)+'</option>').join("");$("#integrationCategory").value=old}
  const rows=filteredIntegrations();
  $("#integrationGrid").innerHTML=rows.length?rows.map(i=>{
    const caps=Array.isArray(i.capabilities)?i.capabilities:[];
    return '<article class="integration-card"><div class="integration-card-head"><span class="integration-logo">'+initials(i.name)+'</span>'+tag(i.status)+'</div><h3>'+esc(i.name)+'</h3><p>'+esc(i.category)+' · '+esc(i.auth_type)+'</p><div class="capabilities">'+caps.slice(0,6).map(x=>'<span>'+esc(x)+'</span>').join("")+'</div><div class="integration-foot"><span>'+esc(i.automation_count||0)+' automation rules</span>'+(has("integrations.write")?'<button data-integration-setup="'+i.id+'">'+(i.status==="Available"?"Configure":"Review setup")+' →</button>':"")+'</div></article>'
  }).join(""):'<div class="empty-state">No integrations match the current filters.</div>';
  $("[data-integration-setup]").forEach(b=>b.onclick=()=>openIntegration(Number(b.dataset.integrationSetup)));
}
function renderAutomation(){
  $("#automationBody").innerHTML=state.automation.length?state.automation.map(a=>'<tr><td class="control-name"><b>'+esc(a.name)+'</b><span>'+esc(a.evidence_type)+'</span></td><td>'+esc(a.control_code)+' · '+esc(a.control_title)+'</td><td>'+esc(a.integration_name)+'</td><td>'+esc(a.schedule)+'</td><td>'+tag(a.integration_status)+'</td><td>'+fmtTime(a.last_run_at)+'</td><td>'+tag(a.status)+'</td><td><button class="mini-action" data-run-automation="'+a.id+'" '+(a.integration_status==="Connected"?"":"disabled")+'>Run now</button></td></tr>').join(""):'<tr><td colspan="8" class="empty-state">No automation rules configured.</td></tr>';
  $("[data-run-automation]").forEach(b=>b.onclick=()=>runAutomation(Number(b.dataset.runAutomation)));
}
async function runAutomation(id){
  try{await api("/api/automation/"+id+"/run",{method:"POST"});toast("Automation completed");await refresh(["automation","evidence","dashboard","audit"])}
  catch(e){toast(e.message)}
}
function renderReports(){
  const rows=state.report||[], tested=rows.filter(r=>r.latest_result!=="Not Tested"), avg=tested.length?Math.round(tested.reduce((s,r)=>s+Number(r.score||0),0)/tested.length):0;
  const high=rows.filter(r=>r.risk_level==="High").length, notTested=rows.filter(r=>r.latest_result==="Not Tested").length, open=rows.reduce((s,r)=>s+Number(r.open_findings||0),0);
  $("#reportSummary").innerHTML=[["Average tested score",avg+"%","Across tested controls"],["High-risk controls",high,"Require stronger assurance"],["Not yet tested",notTested,"Controls awaiting assessment"],["Open findings",open,"Exceptions requiring action"]].map(x=>'<div class="metric"><small>'+esc(x[0])+'</small><strong>'+esc(x[1])+'</strong><p>'+esc(x[2])+'</p></div>').join("");
  $("#reportBody").innerHTML=rows.length?rows.map(r=>{const score=Number(r.score||0);const cls=score>=85?"good":score>=70?"warn":score>0?"bad":"";return '<tr><td class="control-name"><b>'+esc(r.control_code)+' · '+esc(r.title)+'</b><span>'+esc(r.owner||"Unassigned")+'</span></td><td>'+esc(r.category)+'</td><td>'+tag(r.risk_level)+'</td><td><span class="score-ring '+cls+'">'+(score?score:"—")+'</span></td><td>'+tag(r.latest_result)+'</td><td>'+esc(r.current_evidence)+'</td><td>'+esc(r.open_findings)+'</td><td>'+fmtDate(r.next_due)+'</td></tr>'}).join(""):'<tr><td colspan="8" class="empty-state">No control health data available.</td></tr>';
}
function openIntegration(id){
  const i=state.integrations.find(x=>x.id===id);if(!i)return;
  const caps=Array.isArray(i.capabilities)?i.capabilities:[];
  modal('<span class="eyebrow">INTEGRATION SETUP</span><h2>'+esc(i.name)+'</h2><p>This connector is designed for '+esc(i.category)+' evidence. Saving this form marks the connector as configured, not connected. A source is only shown as Connected after provider credentials and a live validation are completed.</p><div class="capabilities">'+caps.map(x=>'<span>'+esc(x)+'</span>').join("")+'</div><form class="form" id="integrationForm"><label>Authentication model<input value="'+esc(i.auth_type)+'" disabled></label><label>Tenant / account reference<input name="tenant_ref" value="'+esc(i.tenant_ref||"")+'" placeholder="Tenant, account or instance identifier"></label><label>Base URL (where applicable)<input name="base_url" value="'+esc(i.base_url||"")+'" placeholder="https://..."></label><div class="form-actions"><button type="button" class="btn secondary" data-close-modal>Cancel</button><button class="btn primary">Save configuration</button></div></form>');
  $("#integrationForm").onsubmit=async e=>{e.preventDefault();const d=Object.fromEntries(new FormData(e.target).entries());try{await api("/api/integrations/"+id,{method:"PUT",body:JSON.stringify({...d,status:"Configured"})});closeModal();toast("Integration configuration saved");await refresh(["integrations","automation","audit"])}catch(err){toast(err.message)}};
  $("[data-close-modal]").forEach(b=>b.onclick=closeModal);
}
function renderFindings(){
  const columns=[["Open",x=>x.status==="Open"],["In Progress",x=>["In Progress","Remediation"].includes(x.status)],["Closed",x=>["Closed","Resolved"].includes(x.status)]];
  $("#findingBoard").innerHTML=columns.map(([name,test])=>{const items=state.findings.filter(test);return '<section class="finding-column"><div class="finding-column-head"><b>'+name+'</b><span>'+items.length+'</span></div>'+items.map(f=>'<article class="finding-card"><div>'+tag(f.severity)+'</div><h3>'+esc(f.title)+'</h3><p>'+esc(f.control_code||"No linked control")+(f.description?" · "+esc(f.description):"")+'</p><div class="finding-card-foot"><span>'+esc(f.owner||"Unassigned")+' · '+fmtDate(f.due_date)+'</span>'+(has("findings.write")?'<select data-finding-status="'+f.id+'"><option '+(f.status==="Open"?"selected":"")+'>Open</option><option '+(["In Progress","Remediation"].includes(f.status)?"selected":"")+'>In Progress</option><option '+(["Closed","Resolved"].includes(f.status)?"selected":"")+'>Resolved</option></select>':tag(f.status))+"</div></article>").join("")+'</section>'}).join("");
  $$("[data-finding-status]").forEach(s=>s.onchange=()=>updateFinding(Number(s.dataset.findingStatus),s.value));
}
async function updateFinding(id,status){try{await api("/api/findings/"+id,{method:"PUT",body:JSON.stringify({status})});toast("Finding updated");await refresh(["findings","dashboard","audit"])}catch(e){toast(e.message)}}
function renderAudit(){
  $("#auditBody").innerHTML=state.audit.length?state.audit.map(a=>'<tr><td>'+fmtTime(a.created_at)+'</td><td class="control-name"><b>'+esc(a.user_name||"System")+'</b><span>'+esc(a.email||"")+'</span></td><td><b>'+esc(a.action)+'</b></td><td>'+esc(a.entity_type)+'</td><td>'+esc(a.entity_id??"—")+'</td><td>'+esc(JSON.stringify(a.details||{}).slice(0,90))+"</td></tr>").join(""):'<tr><td colspan="6" class="empty-state">No audit activity available.</td></tr>';
}
function renderUsers(){
  $("#usersBody").innerHTML=state.users.length?state.users.map(u=>'<tr><td class="control-name"><b>'+esc(u.name)+'</b></td><td>'+esc(u.email)+'</td><td>'+tag(humanRole(u.role))+'</td><td>'+tag(u.status)+'</td><td>'+fmtDate(u.created_at)+"</td></tr>").join(""):'<tr><td colspan="5" class="empty-state">No users available.</td></tr>';
}
function populateFilters(){
  const cats=[...new Set(state.controls.map(c=>c.category))].sort(); if($("#categoryFilter")){$("#categoryFilter").innerHTML='<option value="">All categories</option>'+cats.map(c=>'<option>'+esc(c)+'</option>').join("")}
}
async function refresh(parts){
  const map={dashboard:["dashboard","/api/dashboard"],controls:["controls","/api/controls"],assessments:["assessments","/api/assessments"],evidence:["evidence","/api/evidence"],findings:["findings","/api/findings"],integrations:["integrations","/api/integrations"],automation:["automation","/api/automation"],report:["report","/api/reports/control-health"],audit:["audit","/api/audit"],users:["users","/api/users"]};
  for(const p of parts){if(map[p])state[map[p][0]]=await api(map[p][1])}renderAll();
}
function modal(html){$("#modalBody").innerHTML=html;$("#modal").classList.remove("hidden")}
function closeModal(){$("#modal").classList.add("hidden");$("#modalBody").innerHTML=""}
function controlOptions(){return state.controls.map(c=>'<option value="'+c.id+'">'+esc(c.control_code+" · "+c.title)+'</option>').join("")}
function integrationOptions(){return state.integrations.map(i=>'<option value="'+i.id+'">'+esc(i.name+" · "+i.category)+'</option>').join("")}
function openForm(type){
  const forms={
    control:`<span class="eyebrow">CONTROL LIBRARY</span><h2>Create a new control</h2><p>Add a control with clear ownership, frequency, risk and evidence expectations.</p><form class="form" id="entityForm" data-kind="control"><div class="form-grid"><label>Control code<input name="control_code" required placeholder="ITGC-013"></label><label>Risk level<select name="risk_level"><option>High</option><option selected>Medium</option><option>Low</option></select></label></div><label>Control title<input name="title" required></label><label>Description<textarea name="description"></textarea></label><div class="form-grid"><label>Category<input name="category" required placeholder="Access Management"></label><label>Framework reference<input name="framework_ref" placeholder="ISO 27001 / COBIT"></label><label>Control owner<input name="owner"></label><label>Frequency<select name="frequency"><option>Continuous</option><option>Daily</option><option>Monthly</option><option selected>Quarterly</option><option>Semi-Annual</option><option>Annual</option></select></label></div><label>Required evidence<textarea name="evidence_required"></textarea></label><div class="form-actions"><button type="button" class="btn secondary" data-close-modal>Cancel</button><button class="btn primary">Create control</button></div></form>`,
    assessment:`<span class="eyebrow">CONTROL TESTING</span><h2>Record an assessment</h2><p>Document the latest operating-effectiveness test for a control.</p><form class="form" id="entityForm" data-kind="assessment"><label>Control<select name="control_id" required><option value="">Select control</option>${controlOptions()}</select></label><div class="form-grid"><label>Assessment period<input name="period" required placeholder="Q3 2026"></label><label>Result<select name="result"><option>Effective</option><option>Partially Effective</option><option>Ineffective</option><option>Not Tested</option></select></label></div><label>Score (0-100)<input type="number" name="score" min="0" max="100"></label><label>Test notes<textarea name="notes"></textarea></label><div class="form-actions"><button type="button" class="btn secondary" data-close-modal>Cancel</button><button class="btn primary">Save assessment</button></div></form>`,
    evidence:`<span class="eyebrow">EVIDENCE REGISTER</span><h2>Add control evidence</h2><p>Register evidence with a source and period so it stays traceable.</p><form class="form" id="entityForm" data-kind="evidence"><label>Control<select name="control_id" required><option value="">Select control</option>${controlOptions()}</select></label><label>Evidence title<input name="title" required placeholder="Q3 privileged users export"></label><div class="form-grid"><label>Evidence type<select name="evidence_type"><option>Document</option><option>System Report</option><option>Screenshot</option><option>Approval</option><option>Log Extract</option></select></label><label>Source<select name="source"><option>Manual Upload</option><option>Microsoft 365</option><option>Entra ID</option><option>SIEM</option><option>Database</option><option>ServiceNow / Jira</option></select></label><label>Period<input name="period" placeholder="Q3 2026"></label><label>Status<select name="status"><option>Current</option><option>Expired</option><option>Superseded</option></select></label></div><label>Evidence URL / repository link<input name="url" placeholder="https://..."></label><div class="form-actions"><button type="button" class="btn secondary" data-close-modal>Cancel</button><button class="btn primary">Add evidence</button></div></form>`,
    finding:`<span class="eyebrow">ISSUES & REMEDIATION</span><h2>Create a finding</h2><p>Capture a control gap and assign clear remediation responsibility.</p><form class="form" id="entityForm" data-kind="finding"><label>Linked control<select name="control_id"><option value="">No linked control</option>${controlOptions()}</select></label><label>Finding title<input name="title" required></label><label>Description<textarea name="description"></textarea></label><div class="form-grid"><label>Severity<select name="severity"><option>High</option><option selected>Medium</option><option>Low</option></select></label><label>Owner<input name="owner"></label><label>Due date<input type="date" name="due_date"></label><label>Status<select name="status"><option>Open</option><option>In Progress</option></select></label></div><div class="form-actions"><button type="button" class="btn secondary" data-close-modal>Cancel</button><button class="btn primary">Create finding</button></div></form>`,
    automation:`<span class="eyebrow">CONTINUOUS ASSURANCE</span><h2>Create an evidence automation rule</h2><p>Map a control to a source system. Live collection remains disabled until the source is genuinely connected and validated.</p><form class="form" id="entityForm" data-kind="automation"><label>Control<select name="control_id" required><option value="">Select control</option>${controlOptions()}</select></label><label>Source integration<select name="integration_id" required><option value="">Select integration</option>${integrationOptions()}</select></label><label>Rule name<input name="name" required placeholder="Collect privileged role assignments"></label><div class="form-grid"><label>Schedule<select name="schedule"><option>Daily</option><option>Weekly</option><option>Monthly</option><option>Quarterly</option></select></label><label>Evidence type<select name="evidence_type"><option>System Report</option><option>Log Extract</option><option>Configuration Snapshot</option><option>Access Listing</option></select></label></div><div class="form-actions"><button type="button" class="btn secondary" data-close-modal>Cancel</button><button class="btn primary">Create rule</button></div></form>`,
    user:`<span class="eyebrow">ACCESS MANAGEMENT</span><h2>Add a platform user</h2><p>Create an account using a defined least-privilege role.</p><form class="form" id="entityForm" data-kind="user"><label>Full name<input name="name" required></label><label>Email<input type="email" name="email" required></label><label>Temporary password<input type="password" name="password" minlength="8" required></label><label>Role<select name="role"><option value="control_manager">Control Manager</option><option value="auditor">Auditor</option><option value="reviewer">Reviewer</option><option value="viewer">Viewer</option><option value="admin">Admin</option></select></label><div class="form-actions"><button type="button" class="btn secondary" data-close-modal>Cancel</button><button class="btn primary">Create user</button></div></form>`
  };
  modal(forms[type]);$("#entityForm").onsubmit=submitForm;$$("[data-close-modal]").forEach(b=>b.onclick=closeModal);
}
async function submitForm(e){
  e.preventDefault();const form=e.target,kind=form.dataset.kind,data=Object.fromEntries(new FormData(form).entries());
  if(["assessment","evidence","finding","automation"].includes(kind)&&data.control_id)data.control_id=Number(data.control_id);
  if(kind==="automation"&&data.integration_id)data.integration_id=Number(data.integration_id);
  if(kind==="assessment"&&data.score!=="")data.score=Number(data.score); if(kind==="assessment"&&data.score==="")delete data.score;
  if(kind==="finding"&&!data.control_id)data.control_id=null;if(kind==="finding"&&!data.due_date)data.due_date=null;
  const endpoints={control:["/api/controls",["controls","report","dashboard","audit"]],assessment:["/api/assessments",["assessments","controls","report","dashboard","audit"]],evidence:["/api/evidence",["evidence","controls","report","dashboard","audit"]],finding:["/api/findings",["findings","controls","report","dashboard","audit"]],automation:["/api/automation",["automation","integrations","audit"]],user:["/api/users",["users","audit"]]};
  try{await api(endpoints[kind][0],{method:"POST",body:JSON.stringify(data)});closeModal();toast(kind.charAt(0).toUpperCase()+kind.slice(1)+" saved");await refresh(endpoints[kind][1])}catch(err){toast(err.message)}
}
$("#loginForm").addEventListener("submit",login);$("#logoutBtn").onclick=logout;$("#refreshBtn").onclick=loadAll;$("#menuBtn").onclick=()=>$(".sidebar").classList.toggle("open");
$$("[data-page]").forEach(b=>b.onclick=()=>go(b.dataset.page));$$("[data-page-link]").forEach(b=>b.onclick=()=>go(b.dataset.pageLink));
$$("[data-open-form]").forEach(b=>b.onclick=()=>openForm(b.dataset.openForm));$$("[data-close-modal]").forEach(b=>b.onclick=closeModal);
$("#modal").addEventListener("click",e=>{if(e.target.matches("[data-close-modal]"))closeModal()});
["controlSearch","categoryFilter","riskFilter"].forEach(id=>$("#"+id)?.addEventListener(id==="controlSearch"?"input":"change",renderControls));
["integrationSearch","integrationCategory","integrationStatus"].forEach(id=>$("#"+id)?.addEventListener(id==="integrationSearch"?"input":"change",renderIntegrations));
restore();
