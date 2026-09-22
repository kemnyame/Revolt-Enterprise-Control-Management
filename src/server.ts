import "dotenv/config";
import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Pool } from "pg";
import { z } from "zod";
import path from "path";
import multer from "multer";
import crypto from "crypto";
import { controlCatalog, integrationCatalog } from "./seed";

type TokenPayload = { id:number; orgId:number; role:string; email:string; name:string };
type AuthedRequest = Request & { user?: TokenPayload };

const app = express();
const port = Number(process.env.PORT || 10000);
const jwtSecret = process.env.JWT_SECRET || (process.env.NODE_ENV === "production" ? "" : "dev-only-change-me");
if (!jwtSecret) throw new Error("JWT_SECRET is required in production");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized:false } : undefined
});

app.use(helmet({ contentSecurityPolicy:false }));
app.use(cors());
app.use(express.json({ limit:"3mb" }));
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:8*1024*1024}});
const integrationKey=crypto.createHash("sha256").update(process.env.INTEGRATION_ENCRYPTION_KEY || (process.env.NODE_ENV==="production" ? "" : "dev-integration-key")).digest();
if(process.env.NODE_ENV==="production" && !process.env.INTEGRATION_ENCRYPTION_KEY) throw new Error("INTEGRATION_ENCRYPTION_KEY is required in production");

function encryptSecret(value:any){
  const iv=crypto.randomBytes(12);
  const cipher=crypto.createCipheriv("aes-256-gcm",integrationKey,iv);
  const encrypted=Buffer.concat([cipher.update(JSON.stringify(value),"utf8"),cipher.final()]);
  return {ciphertext:encrypted.toString("base64"),iv:iv.toString("base64"),tag:cipher.getAuthTag().toString("base64")};
}
function decryptSecret(row:any){
  const decipher=crypto.createDecipheriv("aes-256-gcm",integrationKey,Buffer.from(row.secret_iv,"base64"));
  decipher.setAuthTag(Buffer.from(row.secret_tag,"base64"));
  const plain=Buffer.concat([decipher.update(Buffer.from(row.secret_ciphertext,"base64")),decipher.final()]).toString("utf8");
  return JSON.parse(plain);
}
async function githubApi(pathname:string,token:string){
  const r=await fetch("https://api.github.com"+pathname,{headers:{
    "Accept":"application/vnd.github+json","Authorization":"Bearer "+token,"X-GitHub-Api-Version":"2022-11-28","User-Agent":"Revolt-X-Control"
  }});
  const text=await r.text(); let body:any=null; try{body=text?JSON.parse(text):null}catch{body=text}
  if(!r.ok){const err:any=new Error(body?.message||("GitHub request failed: "+r.status));err.status=r.status;err.body=body;throw err}
  return {body,headers:r.headers};
}

const permissions: Record<string,string[]> = {
  admin:["dashboard.read","controls.read","controls.write","assessments.read","assessments.write","assessments.review","evidence.read","evidence.write","findings.read","findings.write","audit.read","users.read","users.write","settings.read","settings.write","integrations.read","integrations.write","automation.read","automation.write","reports.read"],
  control_manager:["dashboard.read","controls.read","controls.write","assessments.read","assessments.write","assessments.review","evidence.read","evidence.write","findings.read","findings.write","audit.read","integrations.read","automation.read","automation.write","reports.read"],
  auditor:["dashboard.read","controls.read","assessments.read","assessments.write","assessments.review","evidence.read","evidence.write","findings.read","findings.write","audit.read","integrations.read","automation.read","reports.read"],
  reviewer:["dashboard.read","controls.read","assessments.read","assessments.review","evidence.read","evidence.write","findings.read","findings.write","audit.read","integrations.read","automation.read","reports.read"],
  viewer:["dashboard.read","controls.read","assessments.read","evidence.read","findings.read","integrations.read","automation.read","reports.read"]
};

function auth(req:AuthedRequest,res:Response,next:NextFunction){
  const header=req.headers.authorization;
  if(!header?.startsWith("Bearer ")) return res.status(401).json({error:"Authentication required"});
  try{
    req.user=jwt.verify(header.slice(7),jwtSecret) as TokenPayload;
    next();
  }catch{
    res.status(401).json({error:"Session expired or invalid"});
  }
}

function permit(permission:string){
  return (req:AuthedRequest,res:Response,next:NextFunction)=>{
    if(!req.user || !(permissions[req.user.role]||[]).includes(permission)) return res.status(403).json({error:"You do not have permission for this action"});
    next();
  };
}

async function audit(user:TokenPayload, action:string, entityType:string, entityId:number|null, details:any={}){
  await pool.query(
    "INSERT INTO audit_logs (organization_id,user_id,action,entity_type,entity_id,details) VALUES ($1,$2,$3,$4,$5,$6)",
    [user.orgId,user.id,action,entityType,entityId,JSON.stringify(details)]
  );
}

async function initDb(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS organizations(
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'viewer',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS controls(
      id SERIAL PRIMARY KEY,
      organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      control_code TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      category TEXT NOT NULL DEFAULT 'IT General Controls',
      framework_ref TEXT NOT NULL DEFAULT '',
      owner TEXT NOT NULL DEFAULT '',
      frequency TEXT NOT NULL DEFAULT 'Quarterly',
      status TEXT NOT NULL DEFAULT 'Active',
      risk_level TEXT NOT NULL DEFAULT 'Medium',
      evidence_required TEXT NOT NULL DEFAULT '',
      last_tested DATE,
      next_due DATE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(organization_id, control_code)
    );
    CREATE TABLE IF NOT EXISTS assessments(
      id SERIAL PRIMARY KEY,
      organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      control_id INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
      tester_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      period TEXT NOT NULL,
      result TEXT NOT NULL,
      score INTEGER CHECK(score BETWEEN 0 AND 100),
      notes TEXT NOT NULL DEFAULT '',
      review_status TEXT NOT NULL DEFAULT 'Pending Review',
      tested_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS integrations(
      id SERIAL PRIMARY KEY,
      organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      provider_key TEXT NOT NULL,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      auth_type TEXT NOT NULL,
      capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
      status TEXT NOT NULL DEFAULT 'Available',
      base_url TEXT NOT NULL DEFAULT '',
      tenant_ref TEXT NOT NULL DEFAULT '',
      last_sync_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(organization_id,provider_key)
    );
    CREATE TABLE IF NOT EXISTS evidence(
      id SERIAL PRIMARY KEY,
      organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      control_id INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
      assessment_id INTEGER REFERENCES assessments(id) ON DELETE SET NULL,
      integration_id INTEGER REFERENCES integrations(id) ON DELETE SET NULL,
      title TEXT NOT NULL,
      evidence_type TEXT NOT NULL DEFAULT 'Document',
      source TEXT NOT NULL DEFAULT 'Manual Upload',
      url TEXT NOT NULL DEFAULT '',
      period TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'Current',
      automated BOOLEAN NOT NULL DEFAULT false,
      collected_at TIMESTAMPTZ,
      expires_at TIMESTAMPTZ,
      uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS findings(
      id SERIAL PRIMARY KEY,
      organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      control_id INTEGER REFERENCES controls(id) ON DELETE SET NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      severity TEXT NOT NULL DEFAULT 'Medium',
      status TEXT NOT NULL DEFAULT 'Open',
      owner TEXT NOT NULL DEFAULT '',
      due_date DATE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      resolved_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS automation_rules(
      id SERIAL PRIMARY KEY,
      organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      control_id INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
      integration_id INTEGER NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      schedule TEXT NOT NULL DEFAULT 'Daily',
      evidence_type TEXT NOT NULL DEFAULT 'System Report',
      status TEXT NOT NULL DEFAULT 'Ready',
      last_run_at TIMESTAMPTZ,
      last_result TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS evidence_files(
      id BIGSERIAL PRIMARY KEY,
      organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      original_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      sha256 TEXT NOT NULL,
      content BYTEA NOT NULL,
      uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS integration_connections(
      id BIGSERIAL PRIMARY KEY,
      organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      integration_id INTEGER NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
      provider_key TEXT NOT NULL,
      secret_ciphertext TEXT NOT NULL,
      secret_iv TEXT NOT NULL,
      secret_tag TEXT NOT NULL,
      config JSONB NOT NULL DEFAULT '{}'::jsonb,
      connected_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      connected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_validated_at TIMESTAMPTZ,
      last_error TEXT,
      UNIQUE(organization_id,provider_key)
    );
    CREATE TABLE IF NOT EXISTS audit_logs(
      id BIGSERIAL PRIMARY KEY,
      organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id INTEGER,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE assessments ADD COLUMN IF NOT EXISTS test_objective TEXT NOT NULL DEFAULT '';
    ALTER TABLE assessments ADD COLUMN IF NOT EXISTS test_procedure TEXT NOT NULL DEFAULT '';
    ALTER TABLE assessments ADD COLUMN IF NOT EXISTS sample_size INTEGER;
    ALTER TABLE assessments ADD COLUMN IF NOT EXISTS exception_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE assessments ADD COLUMN IF NOT EXISTS evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE assessments ADD COLUMN IF NOT EXISTS design_effective BOOLEAN;
    ALTER TABLE assessments ADD COLUMN IF NOT EXISTS operating_effective BOOLEAN;
    ALTER TABLE assessments ADD COLUMN IF NOT EXISTS retest_of INTEGER;
    ALTER TABLE assessments ADD COLUMN IF NOT EXISTS reviewed_by INTEGER;
    ALTER TABLE assessments ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
    ALTER TABLE assessments ADD COLUMN IF NOT EXISTS review_notes TEXT NOT NULL DEFAULT '';
    ALTER TABLE evidence ADD COLUMN IF NOT EXISTS file_id BIGINT REFERENCES evidence_files(id) ON DELETE SET NULL;
    ALTER TABLE evidence ADD COLUMN IF NOT EXISTS sha256 TEXT NOT NULL DEFAULT '';
    ALTER TABLE evidence ADD COLUMN IF NOT EXISTS review_status TEXT NOT NULL DEFAULT 'Pending Review';
    ALTER TABLE evidence ADD COLUMN IF NOT EXISTS reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL;
    ALTER TABLE evidence ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
    ALTER TABLE evidence ADD COLUMN IF NOT EXISTS review_notes TEXT NOT NULL DEFAULT '';
    ALTER TABLE evidence ADD COLUMN IF NOT EXISTS evidence_payload JSONB NOT NULL DEFAULT '{}'::jsonb;
    ALTER TABLE findings ADD COLUMN IF NOT EXISTS source_assessment_id INTEGER REFERENCES assessments(id) ON DELETE SET NULL;
    ALTER TABLE organizations ADD COLUMN IF NOT EXISTS industry TEXT NOT NULL DEFAULT '';
    ALTER TABLE organizations ADD COLUMN IF NOT EXISTS country TEXT NOT NULL DEFAULT '';
    ALTER TABLE organizations ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT 'UTC';
    ALTER TABLE organizations ADD COLUMN IF NOT EXISTS contact_email TEXT NOT NULL DEFAULT '';
    CREATE INDEX IF NOT EXISTS idx_controls_org ON controls(organization_id);
    CREATE INDEX IF NOT EXISTS idx_assessments_org ON assessments(organization_id);
    CREATE INDEX IF NOT EXISTS idx_evidence_org ON evidence(organization_id);
    CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(organization_id);
    CREATE INDEX IF NOT EXISTS idx_integrations_org ON integrations(organization_id);
    CREATE INDEX IF NOT EXISTS idx_automation_org ON automation_rules(organization_id);
    CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(organization_id);
  `);

  const adminEmail = process.env.ADMIN_EMAIL || (process.env.NODE_ENV !== "production" ? "admin@revoltx.local" : "");
  const adminPassword = process.env.ADMIN_PASSWORD || (process.env.NODE_ENV !== "production" ? "ChangeMe!234" : "");
  if(!adminEmail || !adminPassword) throw new Error("ADMIN_EMAIL and ADMIN_PASSWORD are required");

  let org = await pool.query("SELECT id FROM organizations WHERE slug='revolt-demo'");
  let orgId:number;
  if(!org.rowCount){
    const created=await pool.query("INSERT INTO organizations(name,slug) VALUES($1,$2) RETURNING id",["Revolt-X Enterprise Control Management","revolt-demo"]);
    orgId=created.rows[0].id;
  } else orgId=org.rows[0].id;

  const hash=await bcrypt.hash(adminPassword,12);
  await pool.query("UPDATE organizations SET name='Revolt-X Enterprise Control Management' WHERE id=$1 AND name ILIKE '%demo%'",[orgId]);

  const existing=await pool.query("SELECT id FROM users WHERE lower(email)=lower($1)",[adminEmail]);
  if(!existing.rowCount){
    await pool.query("INSERT INTO users(organization_id,name,email,password_hash,role,status) VALUES($1,$2,$3,$4,'admin','active')",[
      orgId, process.env.ADMIN_NAME || "Platform Administrator", adminEmail, hash
    ]);
  } else {
    await pool.query("UPDATE users SET organization_id=$1,name=$2,password_hash=$3,role='admin',status='active' WHERE lower(email)=lower($4)",[
      orgId, process.env.ADMIN_NAME || "Platform Administrator", hash, adminEmail
    ]);
  }
  const adminCheck=await pool.query("SELECT password_hash FROM users WHERE lower(email)=lower($1)",[adminEmail]);
  if(!adminCheck.rowCount || !(await bcrypt.compare(adminPassword,adminCheck.rows[0].password_hash))) {
    throw new Error("Admin credential self-check failed");
  }
  console.log("Admin credential self-check passed");

  for(const item of controlCatalog){
    await pool.query(`INSERT INTO controls(organization_id,control_code,title,description,category,framework_ref,owner,frequency,risk_level,evidence_required,next_due)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,current_date + interval '30 days')
      ON CONFLICT(organization_id,control_code) DO UPDATE SET title=excluded.title,description=excluded.description,category=excluded.category,
      framework_ref=excluded.framework_ref,owner=excluded.owner,frequency=excluded.frequency,risk_level=excluded.risk_level,evidence_required=excluded.evidence_required,updated_at=now()`,
      [orgId,item.code,item.title,item.description,item.category,item.framework,item.owner,item.frequency,item.risk,item.evidence]);
  }

  for(const item of integrationCatalog){
    await pool.query(`INSERT INTO integrations(organization_id,provider_key,name,category,auth_type,capabilities)
      VALUES($1,$2,$3,$4,$5,$6::jsonb)
      ON CONFLICT(organization_id,provider_key) DO UPDATE SET name=excluded.name,category=excluded.category,auth_type=excluded.auth_type,capabilities=excluded.capabilities`,
      [orgId,item.key,item.name,item.category,item.authType,JSON.stringify(item.capabilities)]);
  }

  const demoCount=await pool.query("SELECT count(*)::int AS count FROM assessments WHERE organization_id=$1",[orgId]);
  if(Number(demoCount.rows[0].count)===0){
    const controlRows=await pool.query("SELECT id,control_code FROM controls WHERE organization_id=$1",[orgId]);
    const byCode=Object.fromEntries(controlRows.rows.map((r:any)=>[r.control_code,r.id]));
    const samples:any[]=[
      ["IAM-003","Q3 2026","Effective",94,"Privileged recertification completed; dormant elevated accounts removed."],
      ["CHG-001","Q3 2026","Effective",91,"Sampled production changes had approval, testing and implementation evidence."],
      ["BCK-001","September 2026","Partially Effective",78,"Two failed jobs exceeded escalation SLA before successful recovery."],
      ["VUL-002","September 2026","Ineffective",57,"Critical vulnerability remediation exceeded policy SLA for internet-facing assets."],
      ["NET-001","Q3 2026","Partially Effective",74,"Legacy firewall rules require renewed business-owner justification."],
      ["LOG-001","Q3 2026","Effective",89,"Critical log sources are centrally ingested with required retention."],
      ["END-001","September 2026","Effective",96,"EDR coverage is above target with small number of stale devices."],
      ["PAT-001","September 2026","Partially Effective",81,"Server patching meets target; endpoint backlog requires follow-up."],
      ["DB-001","Q3 2026","Effective",92,"Database privileged roles were reviewed and unnecessary grants revoked."],
      ["CLD-002","September 2026","Partially Effective",79,"Cloud role review identified excessive permissions awaiting remediation."],
      ["TPR-002","Q3 2026","Effective",87,"Critical vendor assurance artefacts reviewed and current."],
      ["BCP-003","2026 Annual","Partially Effective",76,"Recovery exercise completed but one dependency exceeded RTO."]
    ];
    for(const [code,period,result,score,notes] of samples){
      if(byCode[code]) await pool.query("INSERT INTO assessments(organization_id,control_id,period,result,score,notes,review_status,tested_at) VALUES($1,$2,$3,$4,$5,$6,'Reviewed',now()-interval '5 days')",[orgId,byCode[code],period,result,score,notes]);
    }

    const evidenceSamples:any[]=[
      ["IAM-003","Q3 privileged access recertification","System Report","Microsoft Entra ID","Q3 2026","Current",true],
      ["CHG-001","Production change approval sample","Approval","ServiceNow","Q3 2026","Current",true],
      ["BCK-001","Daily backup success dashboard","System Report","Veeam","September 2026","Current",true],
      ["VUL-002","Critical vulnerability ageing report","System Report","Tenable / Nessus","September 2026","Current",true],
      ["NET-001","Firewall rule-review workbook","Document","Palo Alto Networks","Q3 2026","Current",false],
      ["LOG-001","Log source coverage report","System Report","Microsoft Sentinel","Q3 2026","Current",true],
      ["END-001","EDR sensor health report","System Report","CrowdStrike Falcon","September 2026","Current",true],
      ["PAT-001","Monthly patch compliance report","System Report","Microsoft Intune","September 2026","Current",true],
      ["DB-001","Database privileged role export","System Report","PostgreSQL","Q3 2026","Current",true],
      ["CLD-002","AWS privileged IAM role review","System Report","Amazon Web Services","September 2026","Current",true],
      ["TPR-002","Critical vendor assurance tracker","Document","Manual Upload","Q3 2026","Current",false],
      ["BCP-003","DR exercise result and timing log","Document","Manual Upload","2026 Annual","Current",false],
      ["SDLC-003","Protected branch and PR approval sample","System Report","GitHub","Q3 2026","Current",true],
      ["EMAIL-002","DMARC aggregate compliance summary","System Report","Microsoft 365","September 2026","Current",true],
      ["CFG-001","Server baseline compliance report","System Report","Microsoft Defender for Endpoint","September 2026","Current",true]
    ];
    for(const [code,title,evidenceType,source,period,status,automated] of evidenceSamples){
      if(byCode[code]) await pool.query("INSERT INTO evidence(organization_id,control_id,title,evidence_type,source,period,status,automated,collected_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()-interval '2 days',now()+interval '28 days')",[orgId,byCode[code],title,evidenceType,source,period,status,automated]);
    }

    const findingsSamples:any[]=[
      ["VUL-002","Critical vulnerability remediation outside SLA","Four critical vulnerabilities exceeded approved remediation timelines.","High","Open","Vulnerability Manager",14],
      ["BCK-001","Backup failure escalation evidence incomplete","Two failed jobs were recovered but escalation evidence was incomplete.","Medium","In Progress","Infrastructure Manager",21],
      ["NET-001","Legacy firewall rules require business revalidation","A subset of legacy rules lacks recent owner justification.","Medium","Open","Network Manager",30],
      ["CLD-002","Excessive cloud permissions identified","Two administrative cloud roles exceed current job responsibilities.","High","In Progress","Cloud Security Lead",10],
      ["PAT-001","Endpoint patch backlog above target","A set of remote endpoints is outside the approved patch threshold.","Medium","Open","Endpoint Manager",20],
      ["BCP-003","Recovery dependency exceeded RTO","One supporting service caused the exercise to exceed the target RTO.","High","Open","BCM Manager",45],
      ["TPR-002","Vendor assurance report nearing expiry","A critical SaaS vendor assurance report needs renewal.","Low","Open","Vendor Risk Manager",60],
      ["SDLC-004","Legacy repository secret requires rotation","A historical credential was detected in repository history and needs rotation.","High","In Progress","DevOps Lead",7]
    ];
    for(const [code,title,description,severity,status,owner,days] of findingsSamples){
      if(byCode[code]) await pool.query("INSERT INTO findings(organization_id,control_id,title,description,severity,status,owner,due_date) VALUES($1,$2,$3,$4,$5,$6,$7,current_date + ($8 || ' days')::interval)",[orgId,byCode[code],title,description,severity,status,owner,days]);
    }

    const integrationRows=await pool.query("SELECT id,provider_key FROM integrations WHERE organization_id=$1",[orgId]);
    const byIntegration=Object.fromEntries(integrationRows.rows.map((r:any)=>[r.provider_key,r.id]));
    const rules:any[]=[
      ["IAM-003","microsoft-entra","Collect privileged role assignments","Weekly"],
      ["IAM-005","microsoft-entra","Collect MFA coverage","Daily"],
      ["SDLC-003","github","Collect protected branch and PR approval evidence","Daily"],
      ["CHG-001","servicenow","Collect approved production changes","Daily"],
      ["VUL-002","tenable","Collect critical vulnerability ageing","Daily"],
      ["END-001","crowdstrike","Collect endpoint sensor health","Daily"],
      ["LOG-001","microsoft-sentinel","Collect log-source coverage","Daily"],
      ["BCK-001","veeam","Collect backup job success/failure","Daily"],
      ["CLD-002","aws","Collect privileged IAM role inventory","Daily"],
      ["PAT-001","intune","Collect patch compliance","Weekly"],
      ["DB-001","postgresql","Collect privileged database roles","Weekly"],
      ["EMAIL-002","microsoft-365","Collect email-authentication posture","Weekly"]
    ];
    for(const [code,key,name,schedule] of rules){
      if(byCode[code]&&byIntegration[key]) await pool.query("INSERT INTO automation_rules(organization_id,control_id,integration_id,name,schedule,status) VALUES($1,$2,$3,$4,$5,'Ready')",[orgId,byCode[code],byIntegration[key],name,schedule]);
    }
  }
}
app.get("/api/health",async(_req,res)=>{
  try{ await pool.query("SELECT 1"); res.json({status:"ok",database:"ready",service:"Revolt-X Enterprise Control Management"}); }
  catch(e){ res.status(503).json({status:"error",database:"unavailable"}); }
});

app.post("/api/auth/login",async(req,res)=>{
  const schema=z.object({email:z.string().email(),password:z.string().min(6)});
  const parsed=schema.safeParse(req.body);
  if(!parsed.success) return res.status(400).json({error:"Enter a valid email and password"});
  const found=await pool.query("SELECT * FROM users WHERE lower(email)=lower($1) AND status='active'",[parsed.data.email]);
  if(!found.rowCount || !(await bcrypt.compare(parsed.data.password,found.rows[0].password_hash))) return res.status(401).json({error:"Invalid email or password"});
  const u=found.rows[0];
  const payload:TokenPayload={id:u.id,orgId:u.organization_id,role:u.role,email:u.email,name:u.name};
  const token=jwt.sign(payload,jwtSecret,{expiresIn:"8h"});
  await audit(payload,"LOGIN","session",null,{});
  res.json({token,user:payload,permissions:permissions[u.role]||[]});
});

app.get("/api/auth/me",auth,(req:AuthedRequest,res)=>res.json({user:req.user,permissions:permissions[req.user!.role]||[]}));

app.get("/api/dashboard",auth,permit("dashboard.read"),async(req:AuthedRequest,res)=>{
  const o=req.user!.orgId;
  const [controls,tests,evidence,findings,byCategory,recent]=await Promise.all([
    pool.query("SELECT count(*)::int total, count(*) FILTER (WHERE risk_level='High')::int high_risk FROM controls WHERE organization_id=$1",[o]),
    pool.query("SELECT count(*)::int total, count(*) FILTER (WHERE result='Effective')::int effective, count(*) FILTER (WHERE result='Ineffective')::int ineffective FROM assessments WHERE organization_id=$1",[o]),
    pool.query("SELECT count(*)::int total FROM evidence WHERE organization_id=$1",[o]),
    pool.query("SELECT count(*)::int total, count(*) FILTER (WHERE status NOT IN ('Closed','Resolved'))::int open, count(*) FILTER (WHERE severity='High' AND status NOT IN ('Closed','Resolved'))::int high_open FROM findings WHERE organization_id=$1",[o]),
    pool.query("SELECT category,count(*)::int total FROM controls WHERE organization_id=$1 GROUP BY category ORDER BY total DESC",[o]),
    pool.query(`SELECT a.id,a.action,a.entity_type,a.created_at,u.name FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id
      WHERE a.organization_id=$1 ORDER BY a.created_at DESC LIMIT 8`,[o])
  ]);
  const t=tests.rows[0]; const tested=Number(t.total); const effective=Number(t.effective);
  res.json({
    controls:controls.rows[0], assessments:t, evidence:evidence.rows[0], findings:findings.rows[0],
    effectiveness: tested ? Math.round(effective/tested*100) : 0,
    categories:byCategory.rows, recentActivity:recent.rows
  });
});

app.get("/api/control-library",auth,permit("controls.read"),async(req:AuthedRequest,res)=>{
  const active=await pool.query("SELECT control_code FROM controls WHERE organization_id=$1",[req.user!.orgId]);
  const activeSet=new Set(active.rows.map((r:any)=>r.control_code));
  res.json(controlCatalog.map(item=>({...item,active:activeSet.has(item.code)})));
});

app.post("/api/control-library/:code/add",auth,permit("controls.write"),async(req:AuthedRequest,res)=>{
  const item=controlCatalog.find(x=>x.code===req.params.code);
  if(!item) return res.status(404).json({error:"Control template not found"});
  try{
    const q=await pool.query(`INSERT INTO controls(organization_id,control_code,title,description,category,framework_ref,owner,frequency,risk_level,evidence_required,next_due)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,current_date+interval '30 days') RETURNING *`,
      [req.user!.orgId,item.code,item.title,item.description,item.category,item.framework,item.owner,item.frequency,item.risk,item.evidence]);
    await audit(req.user!,"ADD_FROM_LIBRARY","control",q.rows[0].id,{code:item.code});res.status(201).json(q.rows[0]);
  }catch(e:any){res.status(409).json({error:e.code==="23505"?"This control is already in the register":"Unable to add control"});}
});

app.get("/api/controls",auth,permit("controls.read"),async(req:AuthedRequest,res)=>{
  const {search="",category="",risk=""}=req.query as Record<string,string>;
  const out=await pool.query(`SELECT c.*,
    (SELECT result FROM assessments a WHERE a.control_id=c.id ORDER BY tested_at DESC LIMIT 1) latest_result,
    (SELECT count(*)::int FROM evidence e WHERE e.control_id=c.id) evidence_count,
    (SELECT count(*)::int FROM findings f WHERE f.control_id=c.id AND f.status NOT IN ('Closed','Resolved')) open_findings
    FROM controls c WHERE c.organization_id=$1
    AND ($2='' OR c.title ILIKE '%'||$2||'%' OR c.control_code ILIKE '%'||$2||'%')
    AND ($3='' OR c.category=$3) AND ($4='' OR c.risk_level=$4)
    ORDER BY c.control_code`,[req.user!.orgId,search,category,risk]);
  res.json(out.rows);
});

app.get("/api/controls/:id",auth,permit("controls.read"),async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const control=await pool.query("SELECT * FROM controls WHERE id=$1 AND organization_id=$2",[id,req.user!.orgId]);
  if(!control.rowCount) return res.status(404).json({error:"Control not found"});
  const [evidence,tests,findings]=await Promise.all([
    pool.query(`SELECT e.*,u.name uploaded_by_name,rv.name reviewed_by_name FROM evidence e
      LEFT JOIN users u ON u.id=e.uploaded_by LEFT JOIN users rv ON rv.id=e.reviewed_by
      WHERE e.organization_id=$1 AND e.control_id=$2 ORDER BY e.created_at DESC`,[req.user!.orgId,id]),
    pool.query(`SELECT a.*,u.name tester_name,rv.name reviewed_by_name FROM assessments a
      LEFT JOIN users u ON u.id=a.tester_id LEFT JOIN users rv ON rv.id=a.reviewed_by
      WHERE a.organization_id=$1 AND a.control_id=$2 ORDER BY a.tested_at DESC`,[req.user!.orgId,id]),
    pool.query("SELECT * FROM findings WHERE organization_id=$1 AND control_id=$2 ORDER BY created_at DESC",[req.user!.orgId,id])
  ]);
  res.json({control:control.rows[0],evidence:evidence.rows,tests:tests.rows,findings:findings.rows});
});

app.post("/api/controls/:id/test",auth,permit("assessments.write"),async(req:AuthedRequest,res)=>{
  const controlId=Number(req.params.id);
  const schema=z.object({
    period:z.string().min(2),
    test_objective:z.string().min(5),
    test_procedure:z.string().min(5),
    result:z.enum(["Effective","Partially Effective","Ineffective"]),
    score:z.number().int().min(0).max(100),
    sample_size:z.number().int().min(0).nullable().optional(),
    exception_count:z.number().int().min(0).default(0),
    evidence_ids:z.array(z.number().int()).default([]),
    design_effective:z.boolean().nullable().optional(),
    operating_effective:z.boolean().nullable().optional(),
    notes:z.string().default(""),
    raise_finding:z.boolean().default(false),
    finding_title:z.string().optional(),
    finding_severity:z.enum(["Low","Medium","High"]).optional(),
    retest_of:z.number().int().nullable().optional()
  });
  const p=schema.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Complete the required testing fields",details:p.error.flatten()});
  const ctrl=await pool.query("SELECT * FROM controls WHERE id=$1 AND organization_id=$2",[controlId,req.user!.orgId]);
  if(!ctrl.rowCount) return res.status(404).json({error:"Control not found"});
  if(p.data.evidence_ids.length){
    const ev=await pool.query("SELECT id FROM evidence WHERE organization_id=$1 AND control_id=$2 AND id=ANY($3::int[])",[req.user!.orgId,controlId,p.data.evidence_ids]);
    if(ev.rowCount!==p.data.evidence_ids.length) return res.status(400).json({error:"One or more selected evidence items do not belong to this control"});
  }
  const d=p.data;
  const q=await pool.query(`INSERT INTO assessments(organization_id,control_id,tester_id,period,result,score,notes,test_objective,test_procedure,sample_size,exception_count,evidence_ids,design_effective,operating_effective,retest_of)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15) RETURNING *`,[
      req.user!.orgId,controlId,req.user!.id,d.period,d.result,d.score,d.notes,d.test_objective,d.test_procedure,d.sample_size??null,d.exception_count,JSON.stringify(d.evidence_ids),d.design_effective??null,d.operating_effective??null,d.retest_of??null
  ]);
  await pool.query("UPDATE controls SET last_tested=current_date,next_due=CASE frequency WHEN 'Monthly' THEN current_date+interval '1 month' WHEN 'Quarterly' THEN current_date+interval '3 months' WHEN 'Semi-Annual' THEN current_date+interval '6 months' WHEN 'Annual' THEN current_date+interval '1 year' ELSE current_date+interval '3 months' END,updated_at=now() WHERE id=$1",[controlId]);
  let finding=null;
  if(d.raise_finding && d.result!=="Effective"){
    const fq=await pool.query(`INSERT INTO findings(organization_id,control_id,title,description,severity,status,owner,due_date,source_assessment_id)
      VALUES($1,$2,$3,$4,$5,'Open',$6,current_date+interval '30 days',$7) RETURNING *`,[
        req.user!.orgId,controlId,d.finding_title||("Control test exception - "+ctrl.rows[0].control_code),d.notes,d.finding_severity||"Medium",ctrl.rows[0].owner||"",q.rows[0].id
    ]);
    finding=fq.rows[0];
  }
  await audit(req.user!,"TEST_CONTROL","control",controlId,{assessmentId:q.rows[0].id,result:d.result,evidenceIds:d.evidence_ids,findingId:finding?.id||null});
  res.status(201).json({assessment:q.rows[0],finding});
});

app.post("/api/controls",auth,permit("controls.write"),async(req:AuthedRequest,res)=>{
  const schema=z.object({control_code:z.string().min(3),title:z.string().min(3),description:z.string().default(""),category:z.string().min(2),framework_ref:z.string().default(""),owner:z.string().default(""),frequency:z.string().default("Quarterly"),risk_level:z.enum(["Low","Medium","High"]),evidence_required:z.string().default("")});
  const p=schema.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Please complete the required control fields",details:p.error.flatten()});
  try{
    const d=p.data; const q=await pool.query(`INSERT INTO controls(organization_id,control_code,title,description,category,framework_ref,owner,frequency,risk_level,evidence_required,next_due)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,current_date + interval '30 days') RETURNING *`,
      [req.user!.orgId,d.control_code,d.title,d.description,d.category,d.framework_ref,d.owner,d.frequency,d.risk_level,d.evidence_required]);
    await audit(req.user!,"CREATE","control",q.rows[0].id,{code:d.control_code}); res.status(201).json(q.rows[0]);
  }catch(e:any){res.status(409).json({error:e.code==="23505"?"Control code already exists":"Unable to create control"});}
});

app.put("/api/controls/:id",auth,permit("controls.write"),async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id); const allowed=["title","description","category","framework_ref","owner","frequency","status","risk_level","evidence_required","next_due"];
  const fields=allowed.filter(k=>req.body[k]!==undefined); if(!fields.length) return res.status(400).json({error:"No supported fields supplied"});
  const vals=fields.map(k=>req.body[k]); const set=fields.map((k,i)=>`${k}=$${i+3}`).join(",");
  const q=await pool.query(`UPDATE controls SET ${set},updated_at=now() WHERE id=$1 AND organization_id=$2 RETURNING *`,[id,req.user!.orgId,...vals]);
  if(!q.rowCount) return res.status(404).json({error:"Control not found"}); await audit(req.user!,"UPDATE","control",id,{fields}); res.json(q.rows[0]);
});

app.get("/api/assessments",auth,permit("assessments.read"),async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT a.*,c.control_code,c.title control_title,u.name tester_name FROM assessments a
    JOIN controls c ON c.id=a.control_id LEFT JOIN users u ON u.id=a.tester_id WHERE a.organization_id=$1 ORDER BY a.tested_at DESC`,[req.user!.orgId]);
  res.json(q.rows);
});

app.post("/api/assessments",auth,permit("assessments.write"),async(req:AuthedRequest,res)=>{
  const s=z.object({control_id:z.number().int(),period:z.string().min(2),result:z.enum(["Effective","Partially Effective","Ineffective","Not Tested"]),score:z.number().int().min(0).max(100).optional(),notes:z.string().default("")});
  const p=s.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Invalid assessment data",details:p.error.flatten()});
  const c=await pool.query("SELECT id FROM controls WHERE id=$1 AND organization_id=$2",[p.data.control_id,req.user!.orgId]); if(!c.rowCount) return res.status(404).json({error:"Control not found"});
  const q=await pool.query(`INSERT INTO assessments(organization_id,control_id,tester_id,period,result,score,notes) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [req.user!.orgId,p.data.control_id,req.user!.id,p.data.period,p.data.result,p.data.score??null,p.data.notes]);
  await pool.query("UPDATE controls SET last_tested=current_date,next_due=current_date + interval '90 days',updated_at=now() WHERE id=$1",[p.data.control_id]);
  await audit(req.user!,"TEST","control",p.data.control_id,{assessmentId:q.rows[0].id,result:p.data.result}); res.status(201).json(q.rows[0]);
});

app.post("/api/evidence/upload",auth,permit("evidence.write"),upload.single("file"),async(req:AuthedRequest,res)=>{
  if(!req.file) return res.status(400).json({error:"Choose a file to upload"});
  const controlId=Number(req.body.control_id);
  if(!Number.isInteger(controlId)) return res.status(400).json({error:"Select a control"});
  const ctrl=await pool.query("SELECT id FROM controls WHERE id=$1 AND organization_id=$2",[controlId,req.user!.orgId]);
  if(!ctrl.rowCount) return res.status(404).json({error:"Control not found"});
  const sha=crypto.createHash("sha256").update(req.file.buffer).digest("hex");
  const f=await pool.query(`INSERT INTO evidence_files(organization_id,original_name,mime_type,size_bytes,sha256,content,uploaded_by)
    VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,original_name,mime_type,size_bytes,sha256,created_at`,[
      req.user!.orgId,req.file.originalname,req.file.mimetype||"application/octet-stream",req.file.size,sha,req.file.buffer,req.user!.id
  ]);
  const ev=await pool.query(`INSERT INTO evidence(organization_id,control_id,title,evidence_type,source,period,status,uploaded_by,file_id,sha256,review_status)
    VALUES($1,$2,$3,$4,'Manual Upload',$5,'Current',$6,$7,$8,'Pending Review') RETURNING *`,[
      req.user!.orgId,controlId,req.body.title||req.file.originalname,req.body.evidence_type||"Document",req.body.period||"",req.user!.id,f.rows[0].id,sha
  ]);
  await audit(req.user!,"UPLOAD_EVIDENCE","control",controlId,{evidenceId:ev.rows[0].id,fileId:f.rows[0].id,sha256:sha});
  res.status(201).json({...ev.rows[0],file:f.rows[0]});
});

app.get("/api/evidence/files/:id",auth,permit("evidence.read"),async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const q=await pool.query("SELECT * FROM evidence_files WHERE id=$1 AND organization_id=$2",[id,req.user!.orgId]);
  if(!q.rowCount) return res.status(404).json({error:"Evidence file not found"});
  const f=q.rows[0];res.setHeader("Content-Type",f.mime_type);res.setHeader("Content-Length",String(f.size_bytes));
  res.setHeader("Content-Disposition",'attachment; filename="'+String(f.original_name).replace(/"/g,"")+'"');res.setHeader("X-Evidence-SHA256",f.sha256);await audit(req.user!,"DOWNLOAD_EVIDENCE","evidence_file",id,{sha256:f.sha256});res.send(f.content);
});

app.post("/api/evidence/:id/verify",auth,permit("evidence.read"),async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const q=await pool.query(`SELECT e.id,e.sha256,e.file_id,f.content,f.sha256 stored_file_sha FROM evidence e
    LEFT JOIN evidence_files f ON f.id=e.file_id
    WHERE e.id=$1 AND e.organization_id=$2`,[id,req.user!.orgId]);
  if(!q.rowCount)return res.status(404).json({error:"Evidence not found"});
  if(!q.rows[0].file_id)return res.status(400).json({error:"Integrity verification is available for uploaded source files"});
  const calculated=crypto.createHash("sha256").update(q.rows[0].content).digest("hex");
  const valid=calculated===q.rows[0].sha256 && calculated===q.rows[0].stored_file_sha;
  await audit(req.user!,"VERIFY_EVIDENCE","evidence",id,{valid,sha256:calculated});
  res.json({valid,sha256:calculated});
});

app.post("/api/evidence/:id/review",auth,permit("evidence.write"),async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const s=z.object({review_status:z.enum(["Approved","Rejected","Needs Update"]),review_notes:z.string().default("")});
  const p=s.safeParse(req.body);if(!p.success) return res.status(400).json({error:"Invalid review"});
  const q=await pool.query(`UPDATE evidence SET review_status=$3,review_notes=$4,reviewed_by=$5,reviewed_at=now()
    WHERE id=$1 AND organization_id=$2 RETURNING *`,[id,req.user!.orgId,p.data.review_status,p.data.review_notes,req.user!.id]);
  if(!q.rowCount) return res.status(404).json({error:"Evidence not found"});
  await audit(req.user!,"REVIEW_EVIDENCE","evidence",id,{status:p.data.review_status});res.json(q.rows[0]);
});

app.post("/api/assessments/:id/review",auth,permit("assessments.review"),async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const s=z.object({review_status:z.enum(["Reviewed","Needs Rework","Rejected"]),review_notes:z.string().default("")});
  const p=s.safeParse(req.body);if(!p.success)return res.status(400).json({error:"Invalid assessment review"});
  const q=await pool.query(`UPDATE assessments SET review_status=$3,review_notes=$4,reviewed_by=$5,reviewed_at=now()
    WHERE id=$1 AND organization_id=$2 RETURNING *`,[id,req.user!.orgId,p.data.review_status,p.data.review_notes,req.user!.id]);
  if(!q.rowCount)return res.status(404).json({error:"Assessment not found"});
  await audit(req.user!,"REVIEW_TEST","assessment",id,{status:p.data.review_status});res.json(q.rows[0]);
});

app.get("/api/evidence",auth,permit("evidence.read"),async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT e.*,c.control_code,c.title control_title,u.name uploaded_by_name FROM evidence e
    JOIN controls c ON c.id=e.control_id LEFT JOIN users u ON u.id=e.uploaded_by WHERE e.organization_id=$1 ORDER BY e.created_at DESC`,[req.user!.orgId]); res.json(q.rows);
});

app.post("/api/evidence",auth,permit("evidence.write"),async(req:AuthedRequest,res)=>{
  const s=z.object({control_id:z.number().int(),assessment_id:z.number().int().nullable().optional(),title:z.string().min(2),evidence_type:z.string().default("Document"),source:z.string().default("Manual Upload"),url:z.string().default(""),period:z.string().default(""),status:z.string().default("Current")});
  const p=s.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Invalid evidence data",details:p.error.flatten()});
  const c=await pool.query("SELECT id FROM controls WHERE id=$1 AND organization_id=$2",[p.data.control_id,req.user!.orgId]); if(!c.rowCount) return res.status(404).json({error:"Control not found"});
  const d=p.data; const q=await pool.query(`INSERT INTO evidence(organization_id,control_id,assessment_id,title,evidence_type,source,url,period,status,uploaded_by)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,[req.user!.orgId,d.control_id,d.assessment_id??null,d.title,d.evidence_type,d.source,d.url,d.period,d.status,req.user!.id]);
  await audit(req.user!,"ADD_EVIDENCE","control",d.control_id,{evidenceId:q.rows[0].id,title:d.title}); res.status(201).json(q.rows[0]);
});

app.get("/api/findings",auth,permit("findings.read"),async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT f.*,c.control_code,c.title control_title FROM findings f LEFT JOIN controls c ON c.id=f.control_id
    WHERE f.organization_id=$1 ORDER BY CASE f.severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,f.created_at DESC`,[req.user!.orgId]); res.json(q.rows);
});

app.post("/api/findings",auth,permit("findings.write"),async(req:AuthedRequest,res)=>{
  const s=z.object({control_id:z.number().int().nullable().optional(),title:z.string().min(3),description:z.string().default(""),severity:z.enum(["Low","Medium","High"]),status:z.string().default("Open"),owner:z.string().default(""),due_date:z.string().nullable().optional()});
  const p=s.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Invalid finding data",details:p.error.flatten()});
  const d=p.data; const q=await pool.query(`INSERT INTO findings(organization_id,control_id,title,description,severity,status,owner,due_date)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[req.user!.orgId,d.control_id??null,d.title,d.description,d.severity,d.status,d.owner,d.due_date??null]);
  await audit(req.user!,"CREATE","finding",q.rows[0].id,{severity:d.severity}); res.status(201).json(q.rows[0]);
});

app.put("/api/findings/:id",auth,permit("findings.write"),async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id); const s=z.object({status:z.string(),owner:z.string().optional(),due_date:z.string().nullable().optional(),description:z.string().optional()}); const p=s.safeParse(req.body);
  if(!p.success) return res.status(400).json({error:"Invalid update"});
  const existing=await pool.query("SELECT * FROM findings WHERE id=$1 AND organization_id=$2",[id,req.user!.orgId]);
  if(!existing.rowCount) return res.status(404).json({error:"Finding not found"});
  const d=p.data;
  if(["Closed","Resolved"].includes(d.status)){
    const pass=await pool.query(`SELECT id FROM assessments WHERE organization_id=$1 AND control_id=$2 AND result='Effective'
      AND tested_at >= $3 ORDER BY tested_at DESC LIMIT 1`,[req.user!.orgId,existing.rows[0].control_id,existing.rows[0].created_at]);
    if(!pass.rowCount) return res.status(409).json({error:"A passing retest is required before this finding can be closed"});
  }
  const q=await pool.query(`UPDATE findings SET status=$3,owner=COALESCE($4,owner),due_date=COALESCE($5::date,due_date),description=COALESCE($6,description),
    resolved_at=CASE WHEN $3 IN ('Closed','Resolved') THEN now() ELSE NULL END WHERE id=$1 AND organization_id=$2 RETURNING *`,
    [id,req.user!.orgId,d.status,d.owner??null,d.due_date??null,d.description??null]);
  await audit(req.user!,"UPDATE","finding",id,{status:d.status}); res.json(q.rows[0]);
});

app.post("/api/integrations/github/connect",auth,permit("integrations.write"),async(req:AuthedRequest,res)=>{
  const s=z.object({token:z.string().min(20),repositories:z.array(z.string()).default([])});
  const p=s.safeParse(req.body);if(!p.success) return res.status(400).json({error:"A valid GitHub token is required"});
  try{
    const me=await githubApi("/user",p.data.token);
    const integration=await pool.query("SELECT id FROM integrations WHERE organization_id=$1 AND provider_key='github'",[req.user!.orgId]);
    if(!integration.rowCount) return res.status(404).json({error:"GitHub integration definition not found"});
    const secret=encryptSecret({token:p.data.token});
    await pool.query(`INSERT INTO integration_connections(organization_id,integration_id,provider_key,secret_ciphertext,secret_iv,secret_tag,config,connected_by,last_validated_at,last_error)
      VALUES($1,$2,'github',$3,$4,$5,$6::jsonb,$7,now(),NULL)
      ON CONFLICT(organization_id,provider_key) DO UPDATE SET integration_id=excluded.integration_id,secret_ciphertext=excluded.secret_ciphertext,secret_iv=excluded.secret_iv,secret_tag=excluded.secret_tag,config=excluded.config,connected_by=excluded.connected_by,connected_at=now(),last_validated_at=now(),last_error=NULL`,[
        req.user!.orgId,integration.rows[0].id,secret.ciphertext,secret.iv,secret.tag,JSON.stringify({repositories:p.data.repositories,login:me.body.login}),req.user!.id
    ]);
    await pool.query("UPDATE integrations SET status='Connected',tenant_ref=$3,last_sync_at=NULL WHERE id=$1 AND organization_id=$2",[integration.rows[0].id,req.user!.orgId,me.body.login]);
    await audit(req.user!,"CONNECT","integration",integration.rows[0].id,{provider:"github",login:me.body.login});
    res.json({status:"Connected",account:{login:me.body.login,name:me.body.name,avatar_url:me.body.avatar_url},scopes:me.headers.get("x-oauth-scopes")||""});
  }catch(err:any){res.status(err.status===401?401:400).json({error:err.message||"Unable to validate GitHub connection"});}
});

app.get("/api/integrations/github/repositories",auth,permit("integrations.read"),async(req:AuthedRequest,res)=>{
  const q=await pool.query("SELECT * FROM integration_connections WHERE organization_id=$1 AND provider_key='github'",[req.user!.orgId]);
  if(!q.rowCount) return res.status(409).json({error:"GitHub is not connected"});
  try{
    const {token}=decryptSecret(q.rows[0]); const data=await githubApi("/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member",token);
    const repos=(data.body||[]).map((r:any)=>({full_name:r.full_name,name:r.name,owner:r.owner?.login,private:r.private,default_branch:r.default_branch,archived:r.archived,updated_at:r.updated_at,permissions:r.permissions}));
    res.json({repositories:repos,selected:q.rows[0].config?.repositories||[]});
  }catch(err:any){await pool.query("UPDATE integration_connections SET last_error=$2 WHERE organization_id=$1 AND provider_key='github'",[req.user!.orgId,err.message]);res.status(400).json({error:err.message});}
});

app.put("/api/integrations/github/config",auth,permit("integrations.write"),async(req:AuthedRequest,res)=>{
  const s=z.object({repositories:z.array(z.string()).max(100)});const p=s.safeParse(req.body);if(!p.success)return res.status(400).json({error:"Invalid repository selection"});
  const q=await pool.query("UPDATE integration_connections SET config=jsonb_set(COALESCE(config,'{}'::jsonb),'{repositories}',$2::jsonb,true) WHERE organization_id=$1 AND provider_key='github' RETURNING id",[req.user!.orgId,JSON.stringify(p.data.repositories)]);
  if(!q.rowCount)return res.status(409).json({error:"GitHub is not connected"});await audit(req.user!,"CONFIGURE","integration",null,{provider:"github",repositories:p.data.repositories});res.json({repositories:p.data.repositories});
});

app.post("/api/integrations/github/sync",auth,permit("integrations.write"),async(req:AuthedRequest,res)=>{
  const conn=await pool.query("SELECT c.*,i.id integration_id FROM integration_connections c JOIN integrations i ON i.id=c.integration_id WHERE c.organization_id=$1 AND c.provider_key='github'",[req.user!.orgId]);
  if(!conn.rowCount) return res.status(409).json({error:"GitHub is not connected"});
  const {token}=decryptSecret(conn.rows[0]);let repos:string[]=conn.rows[0].config?.repositories||[];
  try{
    if(!repos.length){
      const rr=await githubApi("/user/repos?per_page=30&sort=updated&affiliation=owner,collaborator,organization_member",token);
      repos=(rr.body||[]).filter((r:any)=>!r.archived).slice(0,20).map((r:any)=>r.full_name);
    }
    const ctrlRows=await pool.query("SELECT id,control_code FROM controls WHERE organization_id=$1 AND control_code=ANY($2::text[])",[req.user!.orgId,["SDLC-002","SDLC-003","SDLC-004","SDLC-005"]]);
    const byCode=Object.fromEntries(ctrlRows.rows.map((r:any)=>[r.control_code,r.id]));let created=0,findings=0,errors:any[]=[];
    for(const full of repos.slice(0,40)){
      const [owner,repo]=full.split("/"); if(!owner||!repo) continue;
      try{
        const repoResp=await githubApi("/repos/"+encodeURIComponent(owner)+"/"+encodeURIComponent(repo),token); const meta=repoResp.body;
        let protection:any=null,protectionError:string|null=null,workflows:any=null,secrets:any=null,codeAlerts:any=null,dependabot:any=null,pulls:any=null,collaborators:any=null,actionsPermissions:any=null;
        try{protection=(await githubApi("/repos/"+owner+"/"+repo+"/branches/"+encodeURIComponent(meta.default_branch)+"/protection",token)).body}catch(e:any){protectionError=e.status===404?"Not enabled":e.message}
        try{workflows=(await githubApi("/repos/"+owner+"/"+repo+"/actions/workflows?per_page=100",token)).body}catch(e:any){workflows={error:e.message}}
        try{actionsPermissions=(await githubApi("/repos/"+owner+"/"+repo+"/actions/permissions",token)).body}catch(e:any){actionsPermissions={error:e.message}}
        try{collaborators=(await githubApi("/repos/"+owner+"/"+repo+"/collaborators?affiliation=direct&per_page=100",token)).body}catch(e:any){collaborators={error:e.message}}
        try{secrets=(await githubApi("/repos/"+owner+"/"+repo+"/secret-scanning/alerts?state=open&per_page=100",token)).body}catch(e:any){secrets={error:e.message}}
        try{codeAlerts=(await githubApi("/repos/"+owner+"/"+repo+"/code-scanning/alerts?state=open&per_page=100",token)).body}catch(e:any){codeAlerts={error:e.message}}
        try{dependabot=(await githubApi("/repos/"+owner+"/"+repo+"/dependabot/alerts?state=open&per_page=100",token)).body}catch(e:any){dependabot={error:e.message}}
        try{pulls=(await githubApi("/repos/"+owner+"/"+repo+"/pulls?state=closed&per_page=30&sort=updated&direction=desc",token)).body}catch(e:any){pulls={error:e.message}}
        const snapshots:any[]=[
          ["SDLC-002","Source repository access & configuration",{repository:full,visibility:meta.visibility,private:meta.private,default_branch:meta.default_branch,permissions:meta.permissions,archived:meta.archived,direct_collaborators:Array.isArray(collaborators)?collaborators.map((u:any)=>({login:u.login,role_name:u.role_name,permissions:u.permissions})):collaborators}],
          ["SDLC-003","Branch protection & pull-request review",{repository:full,default_branch:meta.default_branch,branch_protection:protection,branch_protection_status:protectionError,recent_closed_pulls:Array.isArray(pulls)?pulls.slice(0,15).map((p:any)=>({number:p.number,merged_at:p.merged_at,user:p.user?.login,title:p.title})):pulls}],
          ["SDLC-004","Secret and code security alerts",{repository:full,secret_scanning_alerts:secrets,code_scanning_alerts:codeAlerts,dependabot_alerts:dependabot}],
          ["SDLC-005","CI/CD workflow inventory",{repository:full,workflows:workflows?.workflows||workflows,actions_permissions:actionsPermissions}]
        ];
        for(const [code,label,payload] of snapshots){
          if(!byCode[code]) continue; const json=JSON.stringify(payload);const sha=crypto.createHash("sha256").update(json).digest("hex");
          await pool.query(`INSERT INTO evidence(organization_id,control_id,integration_id,title,evidence_type,source,period,status,automated,collected_at,expires_at,uploaded_by,sha256,review_status,evidence_payload)
            VALUES($1,$2,$3,$4,'System Snapshot','GitHub',to_char(current_date,'YYYY-MM'),'Current',true,now(),now()+interval '30 days',$5,$6,'Pending Review',$7::jsonb)`,[
              req.user!.orgId,byCode[code],conn.rows[0].integration_id,full+" - "+label,req.user!.id,sha,json
          ]);created++;
        }
        if(byCode["SDLC-003"] && protectionError==="Not enabled"){
          const dup=await pool.query("SELECT id FROM findings WHERE organization_id=$1 AND control_id=$2 AND title=$3 AND status NOT IN ('Closed','Resolved')",[req.user!.orgId,byCode["SDLC-003"],full+" default branch is not protected"]);
          if(!dup.rowCount){await pool.query(`INSERT INTO findings(organization_id,control_id,title,description,severity,status,owner,due_date)
            VALUES($1,$2,$3,$4,'High','Open','Engineering Lead',current_date+interval '14 days')`,[req.user!.orgId,byCode["SDLC-003"],full+" default branch is not protected","GitHub sync found no branch protection on "+meta.default_branch+"."]);findings++;}
        }
        const secretCount=Array.isArray(secrets)?secrets.length:0;
        const codeHigh=Array.isArray(codeAlerts)?codeAlerts.filter((a:any)=>["critical","high"].includes(String(a.rule?.security_severity_level||"").toLowerCase())).length:0;
        const depHigh=Array.isArray(dependabot)?dependabot.filter((a:any)=>["critical","high"].includes(String(a.security_advisory?.severity||"").toLowerCase())).length:0;
        if(byCode["SDLC-004"] && (secretCount>0 || codeHigh>0 || depHigh>0)){
          const title=full+" has open high-risk repository security alerts";
          const dup=await pool.query("SELECT id FROM findings WHERE organization_id=$1 AND control_id=$2 AND title=$3 AND status NOT IN ('Closed','Resolved')",[req.user!.orgId,byCode["SDLC-004"],title]);
          if(!dup.rowCount){await pool.query(`INSERT INTO findings(organization_id,control_id,title,description,severity,status,owner,due_date)
            VALUES($1,$2,$3,$4,'High','Open','DevOps Lead',current_date+interval '7 days')`,[
              req.user!.orgId,byCode["SDLC-004"],title,"GitHub sync found "+secretCount+" open secret-scanning alert(s), "+codeHigh+" high/critical code-scanning alert(s), and "+depHigh+" high/critical Dependabot alert(s)."
            ]);findings++;}
        }
      }catch(e:any){errors.push({repository:full,error:e.message});}
    }
    await pool.query("UPDATE integrations SET status='Connected',last_sync_at=now() WHERE id=$1",[conn.rows[0].integration_id]);
    await pool.query("UPDATE integration_connections SET last_validated_at=now(),last_error=$2 WHERE organization_id=$1 AND provider_key='github'",[req.user!.orgId,errors.length?JSON.stringify(errors.slice(0,5)):null]);
    await audit(req.user!,"SYNC","integration",conn.rows[0].integration_id,{provider:"github",repositories:repos.length,evidenceCreated:created,findingsCreated:findings,errors});
    res.json({repositoriesScanned:repos.length,evidenceCreated:created,findingsCreated:findings,errors});
  }catch(err:any){res.status(400).json({error:err.message||"GitHub sync failed"});}
});

app.delete("/api/integrations/github/connection",auth,permit("integrations.write"),async(req:AuthedRequest,res)=>{
  const integration=await pool.query("SELECT id FROM integrations WHERE organization_id=$1 AND provider_key='github'",[req.user!.orgId]);
  await pool.query("DELETE FROM integration_connections WHERE organization_id=$1 AND provider_key='github'",[req.user!.orgId]);
  if(integration.rowCount) await pool.query("UPDATE integrations SET status='Available',tenant_ref='',last_sync_at=NULL WHERE id=$1",[integration.rows[0].id]);
  await audit(req.user!,"DISCONNECT","integration",integration.rows[0]?.id||null,{provider:"github"});res.json({status:"Available"});
});

app.get("/api/integrations",auth,permit("integrations.read"),async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT i.*,
    (SELECT count(*)::int FROM automation_rules a WHERE a.integration_id=i.id) automation_count
    FROM integrations i WHERE i.organization_id=$1 ORDER BY category,name`,[req.user!.orgId]);
  res.json(q.rows);
});

app.put("/api/integrations/:id",auth,permit("integrations.write"),async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const s=z.object({status:z.enum(["Available","Configured","Paused"]),base_url:z.string().optional(),tenant_ref:z.string().optional()});
  const p=s.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Invalid integration settings"});
  const q=await pool.query(`UPDATE integrations SET status=$3,base_url=COALESCE($4,base_url),tenant_ref=COALESCE($5,tenant_ref),
    last_sync_at=CASE WHEN $3='Connected' THEN now() ELSE last_sync_at END WHERE id=$1 AND organization_id=$2 RETURNING *`,
    [id,req.user!.orgId,p.data.status,p.data.base_url??null,p.data.tenant_ref??null]);
  if(!q.rowCount) return res.status(404).json({error:"Integration not found"});
  await audit(req.user!,"UPDATE","integration",id,{status:p.data.status});res.json(q.rows[0]);
});

app.get("/api/automation",auth,permit("automation.read"),async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT a.*,c.control_code,c.title control_title,i.name integration_name,i.status integration_status
    FROM automation_rules a JOIN controls c ON c.id=a.control_id JOIN integrations i ON i.id=a.integration_id
    WHERE a.organization_id=$1 ORDER BY a.status,a.name`,[req.user!.orgId]);
  res.json(q.rows);
});

app.post("/api/automation",auth,permit("automation.write"),async(req:AuthedRequest,res)=>{
  const s=z.object({control_id:z.number().int(),integration_id:z.number().int(),name:z.string().min(3),schedule:z.string().min(2),evidence_type:z.string().default("System Report")});
  const p=s.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Invalid automation rule",details:p.error.flatten()});
  const d=p.data;
  const valid=await pool.query(`SELECT 1 FROM controls c JOIN integrations i ON i.organization_id=c.organization_id
    WHERE c.id=$1 AND i.id=$2 AND c.organization_id=$3`,[d.control_id,d.integration_id,req.user!.orgId]);
  if(!valid.rowCount) return res.status(400).json({error:"Control or integration is not available to this organisation"});
  const q=await pool.query("INSERT INTO automation_rules(organization_id,control_id,integration_id,name,schedule,evidence_type,status) VALUES($1,$2,$3,$4,$5,$6,'Ready') RETURNING *",
    [req.user!.orgId,d.control_id,d.integration_id,d.name,d.schedule,d.evidence_type]);
  await audit(req.user!,"CREATE","automation_rule",q.rows[0].id,{controlId:d.control_id,integrationId:d.integration_id});res.status(201).json(q.rows[0]);
});

app.post("/api/automation/:id/run",auth,permit("automation.write"),async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const q=await pool.query(`SELECT a.*,i.status integration_status FROM automation_rules a JOIN integrations i ON i.id=a.integration_id
    WHERE a.id=$1 AND a.organization_id=$2`,[id,req.user!.orgId]);
  if(!q.rowCount) return res.status(404).json({error:"Automation rule not found"});
  if(q.rows[0].integration_status!=="Connected") return res.status(409).json({error:"Connect and validate the source integration before running automated evidence collection"});
  const provider=await pool.query("SELECT provider_key FROM integrations WHERE id=$1",[q.rows[0].integration_id]);
  if(provider.rows[0]?.provider_key==="github"){
    return res.status(202).json({message:"GitHub automation is available through the GitHub Sync action, which collects all mapped GitHub control evidence in one validated run."});
  }
  res.status(501).json({error:"This connector is not live yet. Configure the provider credential and connector worker before automated collection can run."});
});

app.get("/api/reports/control-health",auth,permit("reports.read"),async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT c.control_code,c.title,c.category,c.risk_level,c.owner,c.next_due,
    COALESCE((SELECT a.score FROM assessments a WHERE a.control_id=c.id ORDER BY tested_at DESC LIMIT 1),0) score,
    COALESCE((SELECT a.result FROM assessments a WHERE a.control_id=c.id ORDER BY tested_at DESC LIMIT 1),'Not Tested') latest_result,
    (SELECT count(*)::int FROM evidence e WHERE e.control_id=c.id AND e.status='Current') current_evidence,
    (SELECT count(*)::int FROM findings f WHERE f.control_id=c.id AND f.status NOT IN ('Closed','Resolved')) open_findings
    FROM controls c WHERE c.organization_id=$1 ORDER BY c.category,c.control_code`,[req.user!.orgId]);
  res.json(q.rows);
});


app.get("/api/reports/framework-coverage",auth,permit("reports.read"),async(req:AuthedRequest,res)=>{
  const o=req.user!.orgId;
  const frameworks=[
    ["ISO 27001","ISO 27001"],["NIST","NIST"],["CIS","CIS"],["COBIT","COBIT"],
    ["SOC 2","SOC 2"],["PCI DSS","PCI DSS"],["OWASP","OWASP"],["ISO 22301","ISO 22301"],
    ["NIST AI RMF","NIST AI RMF"],["ISO 42001","ISO 42001"]
  ];
  const rows=[];
  for(const [name,needle] of frameworks){
    const q=await pool.query("SELECT count(*)::int total FROM controls WHERE organization_id=$1 AND framework_ref ILIKE '%'||$2||'%'",[o,needle]);
    rows.push({framework:name,controls:Number(q.rows[0].total)});
  }
  res.json(rows.filter(x=>x.controls>0));
});

app.get("/api/reports/evidence-freshness",auth,permit("reports.read"),async(req:AuthedRequest,res)=>{
  const o=req.user!.orgId;
  const q=await pool.query(`SELECT
    count(*)::int total,
    count(*) FILTER (WHERE status='Current' AND (expires_at IS NULL OR expires_at > now()+interval '7 days'))::int fresh,
    count(*) FILTER (WHERE status='Current' AND expires_at IS NOT NULL AND expires_at <= now()+interval '7 days' AND expires_at > now())::int expiring_soon,
    count(*) FILTER (WHERE status='Expired' OR (expires_at IS NOT NULL AND expires_at <= now()))::int expired,
    count(*) FILTER (WHERE automated=true)::int automated
    FROM evidence WHERE organization_id=$1`,[o]);
  const due=await pool.query(`SELECT e.id,e.title,e.source,e.expires_at,c.control_code,c.title control_title
    FROM evidence e JOIN controls c ON c.id=e.control_id
    WHERE e.organization_id=$1 AND e.expires_at IS NOT NULL AND e.expires_at <= now()+interval '14 days'
    ORDER BY e.expires_at ASC LIMIT 25`,[o]);
  res.json({...q.rows[0],items:due.rows});
});

app.get("/api/reports/assurance-summary",auth,permit("reports.read"),async(req:AuthedRequest,res)=>{
  const o=req.user!.orgId;
  const q=await pool.query(`SELECT
    (SELECT count(*)::int FROM controls WHERE organization_id=$1) controls,
    (SELECT count(DISTINCT control_id)::int FROM assessments WHERE organization_id=$1) tested_controls,
    (SELECT count(DISTINCT control_id)::int FROM automation_rules WHERE organization_id=$1) automated_controls,
    (SELECT count(*)::int FROM findings WHERE organization_id=$1 AND severity='High' AND status NOT IN ('Closed','Resolved')) high_findings,
    (SELECT count(*)::int FROM evidence WHERE organization_id=$1 AND (status='Expired' OR (expires_at IS NOT NULL AND expires_at<=now()))) stale_evidence,
    (SELECT count(*)::int FROM controls WHERE organization_id=$1 AND next_due IS NOT NULL AND next_due<=current_date+30) due_30_days`,[o]);
  const r=q.rows[0], total=Math.max(1,Number(r.controls));
  res.json({...r,
    testing_coverage:Math.round(Number(r.tested_controls)/total*100),
    automation_coverage:Math.round(Number(r.automated_controls)/total*100)
  });
});

app.get("/api/reports/audit-pack.csv",auth,permit("reports.read"),async(req:AuthedRequest,res)=>{
  const o=req.user!.orgId;
  const q=await pool.query(`SELECT c.control_code,c.title,c.category,c.framework_ref,c.owner,c.frequency,c.risk_level,c.status,c.last_tested,c.next_due,
    COALESCE((SELECT a.result FROM assessments a WHERE a.control_id=c.id ORDER BY tested_at DESC LIMIT 1),'Not Tested') latest_result,
    COALESCE((SELECT a.score FROM assessments a WHERE a.control_id=c.id ORDER BY tested_at DESC LIMIT 1),0) latest_score,
    (SELECT count(*)::int FROM evidence e WHERE e.control_id=c.id) evidence_items,
    (SELECT count(*)::int FROM evidence e WHERE e.control_id=c.id AND e.automated=true) automated_evidence,
    (SELECT count(*)::int FROM findings f WHERE f.control_id=c.id AND f.status NOT IN ('Closed','Resolved')) open_findings
    FROM controls c WHERE c.organization_id=$1 ORDER BY c.category,c.control_code`,[o]);
  const cols=["Control Code","Control Title","Category","Framework Mapping","Owner","Frequency","Risk","Status","Last Tested","Next Due","Latest Result","Latest Score","Evidence Items","Automated Evidence","Open Findings"];
  const escCsv=(v:any)=>'"'+String(v??"").replace(/"/g,'""')+'"';
  const csv=[cols.join(","),...q.rows.map(r=>[
    r.control_code,r.title,r.category,r.framework_ref,r.owner,r.frequency,r.risk_level,r.status,
    r.last_tested,r.next_due,r.latest_result,r.latest_score,r.evidence_items,r.automated_evidence,r.open_findings
  ].map(escCsv).join(","))].join("\n");
  await audit(req.user!,"EXPORT","audit_pack",null,{format:"csv",controls:q.rowCount});
  res.setHeader("Content-Type","text/csv; charset=utf-8");
  res.setHeader("Content-Disposition",'attachment; filename="revolt-x-it-controls-audit-pack.csv"');
  res.send(csv);
});

app.get("/api/settings/organization",auth,permit("settings.read"),async(req:AuthedRequest,res)=>{
  const q=await pool.query("SELECT id,name,slug,industry,country,timezone,contact_email,created_at FROM organizations WHERE id=$1",[req.user!.orgId]);
  res.json(q.rows[0]);
});
app.put("/api/settings/organization",auth,permit("settings.write"),async(req:AuthedRequest,res)=>{
  const s=z.object({name:z.string().min(2),industry:z.string().default(""),country:z.string().default(""),timezone:z.string().default("UTC"),contact_email:z.union([z.string().email(),z.literal("")]).default("")});
  const p=s.safeParse(req.body);if(!p.success)return res.status(400).json({error:"Invalid organisation settings",details:p.error.flatten()});
  const d=p.data,q=await pool.query("UPDATE organizations SET name=$2,industry=$3,country=$4,timezone=$5,contact_email=$6 WHERE id=$1 RETURNING id,name,slug,industry,country,timezone,contact_email",[req.user!.orgId,d.name,d.industry,d.country,d.timezone,d.contact_email]);
  await audit(req.user!,"UPDATE","organization",req.user!.orgId,{fields:["name","industry","country","timezone","contact_email"]});res.json(q.rows[0]);
});
app.post("/api/auth/change-password",auth,async(req:AuthedRequest,res)=>{
  const s=z.object({current_password:z.string().min(6),new_password:z.string().min(10)});
  const p=s.safeParse(req.body);if(!p.success)return res.status(400).json({error:"Use a new password of at least 10 characters"});
  const q=await pool.query("SELECT password_hash FROM users WHERE id=$1 AND organization_id=$2",[req.user!.id,req.user!.orgId]);
  if(!q.rowCount||!(await bcrypt.compare(p.data.current_password,q.rows[0].password_hash)))return res.status(400).json({error:"Current password is incorrect"});
  const hash=await bcrypt.hash(p.data.new_password,12);await pool.query("UPDATE users SET password_hash=$2 WHERE id=$1",[req.user!.id,hash]);
  await audit(req.user!,"CHANGE_PASSWORD","user",req.user!.id,{});res.json({success:true});
});
app.put("/api/users/:id/status",auth,permit("users.write"),async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);const s=z.object({status:z.enum(["active","disabled"])});const p=s.safeParse(req.body);
  if(!p.success)return res.status(400).json({error:"Invalid user status"});
  if(id===req.user!.id&&p.data.status==="disabled")return res.status(400).json({error:"You cannot disable your own account"});
  const q=await pool.query("UPDATE users SET status=$3 WHERE id=$1 AND organization_id=$2 RETURNING id,name,email,role,status,created_at",[id,req.user!.orgId,p.data.status]);
  if(!q.rowCount)return res.status(404).json({error:"User not found"});await audit(req.user!,"UPDATE_STATUS","user",id,{status:p.data.status});res.json(q.rows[0]);
});

app.get("/api/audit",auth,permit("audit.read"),async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT a.*,u.name user_name,u.email FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id
    WHERE a.organization_id=$1 ORDER BY a.created_at DESC LIMIT 250`,[req.user!.orgId]); res.json(q.rows);
});

app.get("/api/users",auth,permit("users.read"),async(req:AuthedRequest,res)=>{
  const q=await pool.query("SELECT id,name,email,role,status,created_at FROM users WHERE organization_id=$1 ORDER BY name",[req.user!.orgId]); res.json(q.rows);
});

app.post("/api/users",auth,permit("users.write"),async(req:AuthedRequest,res)=>{
  const s=z.object({name:z.string().min(2),email:z.string().email(),password:z.string().min(8),role:z.enum(["admin","control_manager","auditor","reviewer","viewer"])});
  const p=s.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Invalid user data",details:p.error.flatten()});
  try{ const hash=await bcrypt.hash(p.data.password,12); const q=await pool.query("INSERT INTO users(organization_id,name,email,password_hash,role) VALUES($1,$2,$3,$4,$5) RETURNING id,name,email,role,status,created_at",[req.user!.orgId,p.data.name,p.data.email,hash,p.data.role]); await audit(req.user!,"CREATE","user",q.rows[0].id,{role:p.data.role}); res.status(201).json(q.rows[0]); }
  catch(e:any){res.status(409).json({error:e.code==="23505"?"Email already exists":"Unable to create user"});}
});

const publicDir=path.join(process.cwd(),"public");
app.use(express.static(publicDir));
app.get("*",(_req,res)=>res.sendFile(path.join(publicDir,"index.html")));

async function runStartupSmokeTest(){
  const base=`http://127.0.0.1:${port}`;
  const adminEmail=process.env.ADMIN_EMAIL || "";
  const adminPassword=process.env.ADMIN_PASSWORD || "";
  const login=await fetch(base+"/api/auth/login",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({email:adminEmail,password:adminPassword})
  });
  if(!login.ok) throw new Error(`Smoke test login failed: ${login.status}`);
  const loginData:any=await login.json();
  if(!loginData.token) throw new Error("Smoke test login returned no token");
  const headers={Authorization:`Bearer ${loginData.token}`};
  const endpoints=[
    ["/api/dashboard","dashboard"],
    ["/api/controls","controls"],
    ["/api/assessments","assessments"],
    ["/api/evidence","evidence"],
    ["/api/findings","findings"],
    ["/api/integrations","integrations"],
    ["/api/automation","automation"],
    ["/api/reports/control-health","controlHealth"],
    ["/api/reports/framework-coverage","frameworkCoverage"],
    ["/api/reports/evidence-freshness","evidenceFreshness"],
    ["/api/reports/assurance-summary","assuranceSummary"],
    ["/api/audit","audit"],
    ["/api/users","users"]
  ] as const;
  const results:any={};
  for(const [url,key] of endpoints){
    const r=await fetch(base+url,{headers});
    if(!r.ok) throw new Error(`Smoke test ${key} failed: ${r.status}`);
    const data:any=await r.json();
    results[key]=Array.isArray(data)?data.length:(data?.controls?.total ?? data?.total ?? "ok");
  }
  if(Number(results.controls)<70) throw new Error(`Smoke test control count too low: ${results.controls}`);
  if(Number(results.integrations)<30) throw new Error(`Smoke test integration count too low: ${results.integrations}`);

  const settings=await fetch(base+"/api/settings/organization",{headers});
  if(!settings.ok) throw new Error(`Smoke test organization settings failed: ${settings.status}`);
  results.organizationSettings="ok";

  const controlRow=await pool.query("SELECT id,last_tested,next_due FROM controls WHERE control_code='SDLC-002' ORDER BY id LIMIT 1");
  if(!controlRow.rowCount) throw new Error("Smoke test control SDLC-002 missing");
  const controlId=Number(controlRow.rows[0].id);
  const detail=await fetch(base+"/api/controls/"+controlId,{headers});
  if(!detail.ok) throw new Error(`Smoke test control detail failed: ${detail.status}`);
  results.controlDetail="ok";

  let smokeEvidenceId:number|null=null,smokeFileId:number|null=null,smokeAssessmentId:number|null=null;
  try{
    const fd=new FormData();
    fd.set("control_id",String(controlId));
    fd.set("title","__startup_smoke_evidence__");
    fd.set("period","startup-smoke");
    fd.set("evidence_type","Document");
    fd.set("file",new Blob(["Revolt-X evidence integrity smoke test"],{type:"text/plain"}),"startup-smoke.txt");
    const up=await fetch(base+"/api/evidence/upload",{method:"POST",headers:{Authorization:headers.Authorization},body:fd});
    if(!up.ok) throw new Error(`Smoke test evidence upload failed: ${up.status} ${await up.text()}`);
    const upData:any=await up.json();smokeEvidenceId=Number(upData.id);smokeFileId=Number(upData.file?.id);
    const verify=await fetch(base+"/api/evidence/"+smokeEvidenceId+"/verify",{method:"POST",headers:{...headers,"Content-Type":"application/json"},body:"{}"});
    if(!verify.ok) throw new Error(`Smoke test evidence verify failed: ${verify.status}`);
    const verifyData:any=await verify.json();if(!verifyData.valid) throw new Error("Smoke test evidence hash verification failed");
    results.evidenceIntegrity="ok";

    const test=await fetch(base+"/api/controls/"+controlId+"/test",{method:"POST",headers:{...headers,"Content-Type":"application/json"},body:JSON.stringify({
      period:"startup-smoke",test_objective:"Validate the production Test Control workflow.",
      test_procedure:"Create a temporary operating-effectiveness test through the production API and remove it after validation.",
      result:"Effective",score:100,sample_size:1,exception_count:0,evidence_ids:[smokeEvidenceId],
      design_effective:true,operating_effective:true,notes:"Temporary startup smoke test.",raise_finding:false
    })});
    if(!test.ok) throw new Error(`Smoke test Test Control failed: ${test.status} ${await test.text()}`);
    const testData:any=await test.json();smokeAssessmentId=Number(testData.assessment?.id);
    const review=await fetch(base+"/api/assessments/"+smokeAssessmentId+"/review",{method:"POST",headers:{...headers,"Content-Type":"application/json"},body:JSON.stringify({review_status:"Reviewed",review_notes:"Automated startup validation."})});
    if(!review.ok) throw new Error(`Smoke test test-review failed: ${review.status}`);
    results.testControl="ok";
    results.testReview="ok";

    try{
      const gh=await fetch("https://api.github.com/repos/kemnyame/Revolt-Enterprise-Control-Management",{headers:{"Accept":"application/vnd.github+json","User-Agent":"Revolt-X-Control-Smoke-Test"}});
      results.githubConnectivity=gh.ok?"ok":"unavailable:"+gh.status;
      if(!gh.ok) console.warn("GitHub connectivity smoke check unavailable",gh.status);
    }catch(err:any){
      results.githubConnectivity="unavailable";
      console.warn("GitHub connectivity smoke check failed",err?.message||err);
    }
  } finally {
    if(smokeAssessmentId){
      await pool.query("DELETE FROM audit_logs WHERE entity_type='assessment' AND entity_id=$1",[smokeAssessmentId]).catch(()=>{});
      await pool.query("DELETE FROM audit_logs WHERE action='TEST_CONTROL' AND entity_type='control' AND entity_id=$1 AND details->>'assessmentId'=$2",[controlId,String(smokeAssessmentId)]).catch(()=>{});
      await pool.query("DELETE FROM assessments WHERE id=$1",[smokeAssessmentId]);
    }
    if(smokeEvidenceId){
      await pool.query("DELETE FROM audit_logs WHERE entity_type='evidence' AND entity_id=$1",[smokeEvidenceId]).catch(()=>{});
      await pool.query("DELETE FROM audit_logs WHERE action='UPLOAD_EVIDENCE' AND entity_type='control' AND entity_id=$1 AND details->>'evidenceId'=$2",[controlId,String(smokeEvidenceId)]).catch(()=>{});
      await pool.query("DELETE FROM evidence WHERE id=$1",[smokeEvidenceId]);
    }
    if(smokeFileId){
      await pool.query("DELETE FROM audit_logs WHERE entity_type='evidence_file' AND entity_id=$1",[smokeFileId]).catch(()=>{});
      await pool.query("DELETE FROM evidence_files WHERE id=$1",[smokeFileId]);
    }
    await pool.query("UPDATE controls SET last_tested=$2,next_due=$3 WHERE id=$1",[controlId,controlRow.rows[0].last_tested,controlRow.rows[0].next_due]);
  }
  console.log("Authenticated startup smoke test passed",JSON.stringify(results));
}

initDb().then(()=>{
  const server=app.listen(port,async()=>{
    console.log(`Revolt-X Enterprise Control Management running on port ${port}`);
    try{
      await runStartupSmokeTest();
    }catch(err){
      console.error("Authenticated startup smoke test failed",err);
      server.close(()=>process.exit(1));
    }
  });
}).catch(err=>{console.error("Startup failed",err);process.exit(1);});
