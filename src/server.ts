import "dotenv/config";
import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Pool } from "pg";
import { z } from "zod";
import path from "path";
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
app.use(express.json({ limit:"2mb" }));

const permissions: Record<string,string[]> = {
  admin:["dashboard.read","controls.read","controls.write","assessments.read","assessments.write","evidence.read","evidence.write","findings.read","findings.write","audit.read","users.read","users.write","integrations.read","integrations.write","automation.read","automation.write","reports.read"],
  control_manager:["dashboard.read","controls.read","controls.write","assessments.read","assessments.write","evidence.read","evidence.write","findings.read","findings.write","audit.read","integrations.read","automation.read","automation.write","reports.read"],
  auditor:["dashboard.read","controls.read","assessments.read","assessments.write","evidence.read","evidence.write","findings.read","findings.write","audit.read","integrations.read","automation.read","reports.read"],
  reviewer:["dashboard.read","controls.read","assessments.read","evidence.read","findings.read","findings.write","audit.read","integrations.read","automation.read","reports.read"],
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
    const created=await pool.query("INSERT INTO organizations(name,slug) VALUES($1,$2) RETURNING id",["Revolt-X Enterprise Demo","revolt-demo"]);
    orgId=created.rows[0].id;
  } else orgId=org.rows[0].id;

  const existing=await pool.query("SELECT id FROM users WHERE lower(email)=lower($1)",[adminEmail]);
  if(!existing.rowCount){
    const hash=await bcrypt.hash(adminPassword,12);
    await pool.query("INSERT INTO users(organization_id,name,email,password_hash,role) VALUES($1,$2,$3,$4,'admin')",[
      orgId, process.env.ADMIN_NAME || "Platform Administrator", adminEmail, hash
    ]);
  }

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
  const d=p.data; const q=await pool.query(`UPDATE findings SET status=$3,owner=COALESCE($4,owner),due_date=COALESCE($5::date,due_date),description=COALESCE($6,description),
    resolved_at=CASE WHEN $3 IN ('Closed','Resolved') THEN now() ELSE NULL END WHERE id=$1 AND organization_id=$2 RETURNING *`,
    [id,req.user!.orgId,d.status,d.owner??null,d.due_date??null,d.description??null]);
  if(!q.rowCount) return res.status(404).json({error:"Finding not found"}); await audit(req.user!,"UPDATE","finding",id,{status:d.status}); res.json(q.rows[0]);
});

app.get("/api/integrations",auth,permit("integrations.read"),async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT i.*,
    (SELECT count(*)::int FROM automation_rules a WHERE a.integration_id=i.id) automation_count
    FROM integrations i WHERE i.organization_id=$1 ORDER BY category,name`,[req.user!.orgId]);
  res.json(q.rows);
});

app.put("/api/integrations/:id",auth,permit("integrations.write"),async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const s=z.object({status:z.enum(["Available","Configured","Connected","Paused"]),base_url:z.string().optional(),tenant_ref:z.string().optional()});
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
  res.status(501).json({error:"Live connector execution requires provider credentials and the provider-specific connector worker. The rule is ready but no credentials are configured."});
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

initDb().then(()=>app.listen(port,()=>console.log(`Revolt-X Enterprise Control Management running on port ${port}`))).catch(err=>{console.error("Startup failed",err);process.exit(1);});
