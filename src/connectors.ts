type Dict=Record<string,any>;
export type CollectedEvidence={controlCode:string;title:string;payload:Dict;finding?:{title:string;description:string;severity:"Low"|"Medium"|"High";owner:string}};
export const liveConnectorKeys=["revolt-os","microsoft-entra","microsoft-365","jira","servicenow","splunk","tenable","crowdstrike"] as const;

function requireString(obj:Dict,key:string){
  const v=String(obj?.[key]||"").trim();if(!v)throw new Error(key.replace(/_/g," ")+" is required");return v;
}
function safePublicHttps(raw:string){
  const u=new URL(raw);if(u.protocol!=="https:")throw new Error("Connector URL must use HTTPS");
  const h=u.hostname.toLowerCase();
  if(["localhost","127.0.0.1","::1"].includes(h)||h.endsWith(".local")||h.endsWith(".internal")||
    /^10\./.test(h)||/^192\.168\./.test(h)||/^172\.(1[6-9]|2\d|3[01])\./.test(h)||/^169\.254\./.test(h)) throw new Error("Private network systems require the Revolt-X connector agent; direct cloud connectors cannot target private addresses");
  return u.origin;
}
async function jsonRequest(url:string,init:RequestInit={}){
  const r=await fetch(url,init);const text=await r.text();let body:any;try{body=text?JSON.parse(text):null}catch{body=text}
  if(!r.ok){const msg=body?.error?.message||body?.message||body?.error_description||("Request failed with status "+r.status);const e:any=new Error(msg);e.status=r.status;e.body=body;throw e}
  return {body,headers:r.headers};
}
async function graphToken(credentials:Dict){
  const tenant=requireString(credentials,"tenant_id"),client=requireString(credentials,"client_id"),secret=requireString(credentials,"client_secret");
  const body=new URLSearchParams({client_id:client,client_secret:secret,scope:"https://graph.microsoft.com/.default",grant_type:"client_credentials"});
  const r=await jsonRequest("https://login.microsoftonline.com/"+encodeURIComponent(tenant)+"/oauth2/v2.0/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body});
  return {token:r.body.access_token,tenant};
}
async function graphGet(path:string,token:string){
  return (await jsonRequest("https://graph.microsoft.com"+path,{headers:{Authorization:"Bearer "+token,Accept:"application/json"}})).body;
}
async function graphTry(path:string,token:string){try{return await graphGet(path,token)}catch(e:any){return {unavailable:true,error:e.message,status:e.status||null}}}


async function revoltOsLogin(credentials:Dict,config:Dict){
  const base=safePublicHttps(requireString(config,"base_url"));
  const body:any={email:requireString(credentials,"email"),password:requireString(credentials,"password")};
  if(credentials.organisation_id)body.organisationId=String(credentials.organisation_id);
  const login=await jsonRequest(base+"/v1/auth/login",{method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json"},body:JSON.stringify(body)});
  return {base,accessToken:login.body.accessToken,organisationId:login.body.organisationId};
}
async function validateRevoltOS(credentials:Dict,config:Dict){
  const {base,accessToken,organisationId}=await revoltOsLogin(credentials,config);
  const context=(await jsonRequest(base+"/v1/auth/context",{headers:{Authorization:"Bearer "+accessToken,Accept:"application/json"}})).body;
  return {identity:context.organisation_name||"Revolt-X OS",metadata:{baseUrl:base,organisationId:organisationId||context.organisation_id,user:context.email,permissions:context.permissions||[]}};
}
async function collectRevoltOS(credentials:Dict,config:Dict):Promise<CollectedEvidence[]>{
  const {base,accessToken}=await revoltOsLogin(credentials,config);
  const headers={Authorization:"Bearer "+accessToken,Accept:"application/json"};
  const get=(path:string)=>jsonRequest(base+path,{headers}).then(r=>r.body).catch((e:any)=>({unavailable:true,error:e.message,status:e.status||null}));
  const [organisation,users,roles,branches,departments,teams,auditLogs]=await Promise.all([
    get("/v1/organisation"),get("/v1/users"),get("/v1/roles"),get("/v1/branches"),get("/v1/departments"),get("/v1/teams"),get("/v1/audit-logs?limit=100")
  ]);
  const userList=Array.isArray(users)?users:[];
  const inactive=userList.filter((u:any)=>u.membership_status!=="active"||u.status!=="active");
  const evidence:CollectedEvidence[]=[
    {controlCode:"GOV-004",title:"Revolt-X OS organisation and responsibility structure",payload:{collectedAt:new Date().toISOString(),organisation,roles,branches,departments,teams}},
    {controlCode:"IAM-001",title:"Revolt-X OS user and membership inventory",payload:{collectedAt:new Date().toISOString(),users}},
    {controlCode:"IAM-004",title:"Revolt-X OS role and access structure",payload:{collectedAt:new Date().toISOString(),roles,users}},
    {controlCode:"LOG-001",title:"Revolt-X OS audit-log snapshot",payload:{collectedAt:new Date().toISOString(),auditLogs}}
  ];
  if(inactive.length)evidence[1].finding={title:inactive.length+" Revolt-X OS user membership(s) need lifecycle review",description:"The Core OS user inventory contains inactive, suspended or invited membership records. Review whether access should remain provisioned.",severity:"Medium",owner:"IAM Manager"};
  return evidence;
}

async function validateMicrosoft(credentials:Dict){
  const {token,tenant}=await graphToken(credentials);
  const org=await graphGet("/v1.0/organization?$select=id,displayName,verifiedDomains",token);
  const first=org.value?.[0]||{};return {identity:first.displayName||tenant,metadata:{tenantId:first.id||tenant,verifiedDomains:first.verifiedDomains||[]}};
}
async function collectEntra(credentials:Dict):Promise<CollectedEvidence[]>{
  const {token}=await graphToken(credentials);
  const [roles,users,groups,ca,registration]=await Promise.all([
    graphTry("/v1.0/directoryRoles?$expand=members($select=id,displayName,userPrincipalName)",token),
    graphTry("/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,userType&$top=999",token),
    graphTry("/v1.0/groups?$select=id,displayName,securityEnabled&$top=999",token),
    graphTry("/v1.0/identity/conditionalAccess/policies",token),
    graphTry("/beta/reports/authenticationMethods/userRegistrationDetails?$top=999",token)
  ]);
  const roleList=Array.isArray(roles.value)?roles.value:[];
  const privilegedMembers=roleList.flatMap((r:any)=>(r.members||[]).map((m:any)=>({role:r.displayName,id:m.id,displayName:m.displayName,userPrincipalName:m.userPrincipalName})));
  const userList=Array.isArray(users.value)?users.value:[];
  const disabled=userList.filter((u:any)=>u.accountEnabled===false);
  const registrationList=Array.isArray(registration.value)?registration.value:[];
  const noMfa=registrationList.filter((u:any)=>u.isMfaRegistered===false);
  const evidence:CollectedEvidence[]=[
    {controlCode:"IAM-003",title:"Microsoft Entra privileged role assignments",payload:{collectedAt:new Date().toISOString(),roles:roleList.map((r:any)=>({id:r.id,displayName:r.displayName,memberCount:(r.members||[]).length})),privilegedMembers}},
    {controlCode:"IAM-002",title:"Microsoft Entra account lifecycle snapshot",payload:{collectedAt:new Date().toISOString(),totalUsers:userList.length,disabledAccounts:disabled}},
    {controlCode:"IAM-005",title:"Microsoft Entra MFA registration coverage",payload:{collectedAt:new Date().toISOString(),registrationReport:registration,total:registrationList.length,notMfaRegistered:noMfa.length}},
    {controlCode:"IAM-004",title:"Microsoft Entra groups and access structure",payload:{collectedAt:new Date().toISOString(),groups}},
    {controlCode:"IAM-006",title:"Microsoft Entra Conditional Access policies",payload:{collectedAt:new Date().toISOString(),conditionalAccess:ca}}
  ];
  if(noMfa.length>0) evidence[2].finding={title:noMfa.length+" Entra user(s) are not registered for MFA",description:"Automated Microsoft Graph evidence found users without MFA registration. Review scope, exclusions and remediation.",severity:"High",owner:"IAM Manager"};
  return evidence;
}
async function collectM365(credentials:Dict):Promise<CollectedEvidence[]>{
  const {token}=await graphToken(credentials);
  const [org,domains,secureScores,alerts,servicePrincipals]=await Promise.all([
    graphTry("/v1.0/organization?$select=id,displayName,verifiedDomains",token),
    graphTry("/v1.0/domains",token),
    graphTry("/v1.0/security/secureScores?$top=5",token),
    graphTry("/v1.0/security/alerts_v2?$top=100",token),
    graphTry("/v1.0/servicePrincipals?$select=id,displayName,accountEnabled,servicePrincipalType&$top=999",token)
  ]);
  return [
    {controlCode:"EMAIL-001",title:"Microsoft 365 security posture snapshot",payload:{collectedAt:new Date().toISOString(),organization:org,secureScores,securityAlerts:alerts}},
    {controlCode:"EMAIL-002",title:"Microsoft 365 tenant domain inventory",payload:{collectedAt:new Date().toISOString(),domains}},
    {controlCode:"IAM-007",title:"Microsoft 365 service principal inventory",payload:{collectedAt:new Date().toISOString(),servicePrincipals}}
  ];
}

function basic(email:string,token:string){return "Basic "+Buffer.from(email+":"+token).toString("base64")}
async function validateJira(credentials:Dict,config:Dict){
  const base=safePublicHttps(requireString(config,"base_url")),email=requireString(credentials,"email"),token=requireString(credentials,"api_token");
  const me=await jsonRequest(base+"/rest/api/3/myself",{headers:{Authorization:basic(email,token),Accept:"application/json"}});
  return {identity:me.body.displayName||me.body.emailAddress||base,metadata:{accountId:me.body.accountId,baseUrl:base}};
}
async function collectJira(credentials:Dict,config:Dict):Promise<CollectedEvidence[]>{
  const base=safePublicHttps(requireString(config,"base_url")),auth=basic(requireString(credentials,"email"),requireString(credentials,"api_token"));
  const headers={Authorization:auth,Accept:"application/json"};
  const [projects,issues]=await Promise.all([
    jsonRequest(base+"/rest/api/3/project/search?maxResults=100",{headers}).then(r=>r.body).catch((e:any)=>({error:e.message})),
    jsonRequest(base+"/rest/api/3/search/jql?jql="+encodeURIComponent("updated >= -30d ORDER BY updated DESC")+"&maxResults=100&fields=summary,status,issuetype,priority,created,updated,resolution,assignee",{headers}).then(r=>r.body).catch((e:any)=>({error:e.message}))
  ]);
  return [
    {controlCode:"CHG-001",title:"Jira recent change and work-item evidence",payload:{collectedAt:new Date().toISOString(),projects,recentIssues:issues}},
    {controlCode:"OPS-003",title:"Jira production problem and remediation tracker",payload:{collectedAt:new Date().toISOString(),recentIssues:issues}}
  ];
}

async function validateServiceNow(credentials:Dict,config:Dict){
  const base=safePublicHttps(requireString(config,"base_url")),user=requireString(credentials,"username"),pass=requireString(credentials,"password");
  const r=await jsonRequest(base+"/api/now/table/sys_user?sysparm_limit=1&sysparm_fields=sys_id,user_name,name",{headers:{Authorization:basic(user,pass),Accept:"application/json"}});
  return {identity:base,metadata:{validated:true,sampleUsers:Array.isArray(r.body.result)?r.body.result.length:0}};
}
async function collectServiceNow(credentials:Dict,config:Dict):Promise<CollectedEvidence[]>{
  const base=safePublicHttps(requireString(config,"base_url")),headers={Authorization:basic(requireString(credentials,"username"),requireString(credentials,"password")),Accept:"application/json"};
  const get=(table:string,fields:string)=>jsonRequest(base+"/api/now/table/"+table+"?sysparm_limit=200&sysparm_fields="+encodeURIComponent(fields),{headers}).then(r=>r.body).catch((e:any)=>({error:e.message}));
  const [changes,incidents,cmdb]=await Promise.all([
    get("change_request","number,state,risk,approval,type,opened_at,closed_at,sys_updated_on,assigned_to"),
    get("incident","number,state,priority,opened_at,resolved_at,close_code,assigned_to"),
    get("cmdb_ci","sys_id,name,sys_class_name,install_status,operational_status,owned_by")
  ]);
  return [
    {controlCode:"CHG-001",title:"ServiceNow change-management evidence",payload:{collectedAt:new Date().toISOString(),changes}},
    {controlCode:"IR-001",title:"ServiceNow incident-response evidence",payload:{collectedAt:new Date().toISOString(),incidents}},
    {controlCode:"AST-001",title:"ServiceNow CMDB asset evidence",payload:{collectedAt:new Date().toISOString(),configurationItems:cmdb}}
  ];
}

async function validateSplunk(credentials:Dict,config:Dict){
  const base=safePublicHttps(requireString(config,"base_url")),token=requireString(credentials,"token");
  const r=await jsonRequest(base+"/services/server/info?output_mode=json",{headers:{Authorization:"Bearer "+token,Accept:"application/json"}});
  return {identity:r.body.entry?.[0]?.content?.serverName||base,metadata:{version:r.body.entry?.[0]?.content?.version||null}};
}
async function collectSplunk(credentials:Dict,config:Dict):Promise<CollectedEvidence[]>{
  const base=safePublicHttps(requireString(config,"base_url")),headers={Authorization:"Bearer "+requireString(credentials,"token"),Accept:"application/json"};
  const [indexes,searches]=await Promise.all([
    jsonRequest(base+"/services/data/indexes?output_mode=json&count=0",{headers}).then(r=>r.body).catch((e:any)=>({error:e.message})),
    jsonRequest(base+"/services/saved/searches?output_mode=json&count=0",{headers}).then(r=>r.body).catch((e:any)=>({error:e.message}))
  ]);
  return [
    {controlCode:"LOG-001",title:"Splunk index and log-source configuration",payload:{collectedAt:new Date().toISOString(),indexes}},
    {controlCode:"LOG-002",title:"Splunk saved security monitoring searches",payload:{collectedAt:new Date().toISOString(),savedSearches:searches}}
  ];
}

function tenableHeaders(credentials:Dict){return {"X-ApiKeys":"accessKey="+requireString(credentials,"access_key")+"; secretKey="+requireString(credentials,"secret_key"),Accept:"application/json"}}
async function validateTenable(credentials:Dict){
  const r=await jsonRequest("https://cloud.tenable.com/users/me",{headers:tenableHeaders(credentials)});
  return {identity:r.body.name||r.body.username||"Tenable.io",metadata:{uuid:r.body.uuid||null}};
}
async function collectTenable(credentials:Dict):Promise<CollectedEvidence[]>{
  const headers=tenableHeaders(credentials);
  const [assets,scans,vulns]=await Promise.all([
    jsonRequest("https://cloud.tenable.com/assets?limit=200",{headers}).then(r=>r.body).catch((e:any)=>({error:e.message})),
    jsonRequest("https://cloud.tenable.com/scans?limit=200",{headers}).then(r=>r.body).catch((e:any)=>({error:e.message})),
    jsonRequest("https://cloud.tenable.com/workbenches/vulnerabilities",{headers}).then(r=>r.body).catch((e:any)=>({error:e.message}))
  ]);
  const vulnList=Array.isArray(vulns.vulnerabilities)?vulns.vulnerabilities:[];
  const critical=vulnList.filter((v:any)=>Number(v.severity)===4);
  const ev:CollectedEvidence={controlCode:"VUL-002",title:"Tenable critical vulnerability snapshot",payload:{collectedAt:new Date().toISOString(),vulnerabilities:vulns,criticalCount:critical.length}};
  if(critical.length)ev.finding={title:critical.length+" critical Tenable vulnerability item(s) require review",description:"Automated Tenable evidence contains critical vulnerability items. Validate affected assets and remediation SLA.",severity:"High",owner:"Vulnerability Manager"};
  return [
    {controlCode:"VUL-001",title:"Tenable scan and asset coverage",payload:{collectedAt:new Date().toISOString(),assets,scans}},
    ev
  ];
}

async function crowdstrikeToken(credentials:Dict,config:Dict){
  const base=config?.base_url?safePublicHttps(String(config.base_url)):"https://api.crowdstrike.com";
  const body=new URLSearchParams({client_id:requireString(credentials,"client_id"),client_secret:requireString(credentials,"client_secret")});
  const r=await jsonRequest(base+"/oauth2/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body});
  return {base,token:r.body.access_token};
}
async function validateCrowdStrike(credentials:Dict,config:Dict){
  const {base,token}=await crowdstrikeToken(credentials,config);
  const r=await jsonRequest(base+"/devices/queries/devices-scroll/v1?limit=1",{headers:{Authorization:"Bearer "+token,Accept:"application/json"}});
  return {identity:"CrowdStrike Falcon",metadata:{baseUrl:base,validated:!!r.body}};
}
async function collectCrowdStrike(credentials:Dict,config:Dict):Promise<CollectedEvidence[]>{
  const {base,token}=await crowdstrikeToken(credentials,config),headers={Authorization:"Bearer "+token,Accept:"application/json"};
  const [devices,detections]=await Promise.all([
    jsonRequest(base+"/devices/queries/devices-scroll/v1?limit=500",{headers}).then(r=>r.body).catch((e:any)=>({error:e.message})),
    jsonRequest(base+"/detects/queries/detects/v1?limit=500",{headers}).then(r=>r.body).catch((e:any)=>({error:e.message}))
  ]);
  return [
    {controlCode:"END-001",title:"CrowdStrike endpoint sensor inventory",payload:{collectedAt:new Date().toISOString(),deviceQuery:devices}},
    {controlCode:"LOG-002",title:"CrowdStrike detection queue snapshot",payload:{collectedAt:new Date().toISOString(),detections}}
  ];
}

export function connectorFields(provider:string){
  const fields:Record<string,any>={
    "revolt-os":{credentials:[["email","OS service account email","email"],["password","OS service account password","password"],["organisation_id","Organisation ID (optional)","text"]],config:[["base_url","Revolt-X OS URL","url","https://revolt-x-os.onrender.com"]]},
    "microsoft-entra":{credentials:[["tenant_id","Tenant ID","text"],["client_id","Client ID","text"],["client_secret","Client secret","password"]],config:[]},
    "microsoft-365":{credentials:[["tenant_id","Tenant ID","text"],["client_id","Client ID","text"],["client_secret","Client secret","password"]],config:[]},
    jira:{credentials:[["email","Atlassian email","email"],["api_token","API token","password"]],config:[["base_url","Jira site URL","url","https://company.atlassian.net"]]},
    servicenow:{credentials:[["username","Integration username","text"],["password","Password","password"]],config:[["base_url","ServiceNow instance URL","url","https://company.service-now.com"]]},
    splunk:{credentials:[["token","Splunk bearer token","password"]],config:[["base_url","Splunk Cloud URL","url","https://company.splunkcloud.com:8089"]]},
    tenable:{credentials:[["access_key","Access key","password"],["secret_key","Secret key","password"]],config:[]},
    crowdstrike:{credentials:[["client_id","API client ID","text"],["client_secret","API client secret","password"]],config:[["base_url","Falcon API URL (optional)","url","https://api.crowdstrike.com"]]}
  };
  return fields[provider]||null;
}

export async function validateConnector(provider:string,credentials:Dict,config:Dict){
  switch(provider){
    case "revolt-os":return validateRevoltOS(credentials,config);
    case "microsoft-entra":case "microsoft-365":return validateMicrosoft(credentials);
    case "jira":return validateJira(credentials,config);
    case "servicenow":return validateServiceNow(credentials,config);
    case "splunk":return validateSplunk(credentials,config);
    case "tenable":return validateTenable(credentials);
    case "crowdstrike":return validateCrowdStrike(credentials,config);
    default:throw new Error("This provider does not have a live direct connector yet");
  }
}
export async function collectConnector(provider:string,credentials:Dict,config:Dict):Promise<CollectedEvidence[]>{
  switch(provider){
    case "revolt-os":return collectRevoltOS(credentials,config);
    case "microsoft-entra":return collectEntra(credentials);
    case "microsoft-365":return collectM365(credentials);
    case "jira":return collectJira(credentials,config);
    case "servicenow":return collectServiceNow(credentials,config);
    case "splunk":return collectSplunk(credentials,config);
    case "tenable":return collectTenable(credentials);
    case "crowdstrike":return collectCrowdStrike(credentials,config);
    default:throw new Error("This provider does not have a live direct connector yet");
  }
}
