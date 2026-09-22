import "dotenv/config";
import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Pool } from "pg";
import { z } from "zod";
import path from "path";

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
  admin:["dashboard.read","controls.read","controls.write","assessments.read","assessments.write","evidence.read","evidence.write","findings.read","findings.write","audit.read","users.read","users.write"],
  control_manager:["dashboard.read","controls.read","controls.write","assessments.read","assessments.write","evidence.read","evidence.write","findings.read","findings.write","audit.read"],
  auditor:["dashboard.read","controls.read","assessments.read","assessments.write","evidence.read","evidence.write","findings.read","findings.write","audit.read"],
  reviewer:["dashboard.read","controls.read","assessments.read","evidence.read","findings.read","findings.write","audit.read"],
  viewer:["dashboard.read","controls.read","assessments.read","evidence.read","findings.read"]
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
    CREATE TABLE IF NOT EXISTS evidence(
      id SERIAL PRIMARY KEY,
      organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      control_id INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
      assessment_id INTEGER REFERENCES assessments(id) ON DELETE SET NULL,
      title TEXT NOT NULL,
      evidence_type TEXT NOT NULL DEFAULT 'Document',
      source TEXT NOT NULL DEFAULT 'Manual Upload',
      url TEXT NOT NULL DEFAULT '',
      period TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'Current',
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
    CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(organization_id);
  `);

  const adminEmail = process.env.ADMIN_EMAIL || (process.env.NODE_ENV !== "production" ? "admin@revoltx.local" : "");
  const adminPassword = process.env.ADMIN_PASSWORD || (process.env.NODE_ENV !== "production" ? "ChangeMe!234" : "");
  if(!adminEmail || !adminPassword) return;

  let org = await pool.query("SELECT id FROM organizations WHERE slug='revolt-demo'");
  let orgId:number;
  if(!org.rowCount){
    const created=await pool.query("INSERT INTO organizations(name,slug) VALUES($1,$2) RETURNING id",["Revolt-X Demo Organisation","revolt-demo"]);
    orgId=created.rows[0].id;
  } else orgId=org.rows[0].id;

  const existing=await pool.query("SELECT id FROM users WHERE lower(email)=lower($1)",[adminEmail]);
  if(!existing.rowCount){
    const hash=await bcrypt.hash(adminPassword,12);
    await pool.query("INSERT INTO users(organization_id,name,email,password_hash,role) VALUES($1,$2,$3,$4,'admin')",[
      orgId, process.env.ADMIN_NAME || "Platform Administrator", adminEmail, hash
    ]);
  }

  const count=await pool.query("SELECT count(*)::int AS count FROM controls WHERE organization_id=$1",[orgId]);
  if(Number(count.rows[0].count)===0){
    const seed=[
      ["ITGC-001","Privileged Access Review","Privileged access is reviewed and approved periodically.","Access Management","ISO 27001 A.5.18 / COBIT DSS05","Head of IT","Quarterly","High","User listing, reviewer sign-off and removal evidence"],
      ["ITGC-002","User Access Provisioning","New system access requires documented approval before provisioning.","Access Management","ISO 27001 A.5.15","IT Security","Continuous","High","Approved request and provisioning record"],
      ["ITGC-003","Terminated User Deprovisioning","Access for terminated personnel is removed within the defined SLA.","Access Management","ISO 27001 A.5.18","IT Security","Monthly","High","HR leaver list and disabled-account evidence"],
      ["ITGC-004","Change Management Approval","Production changes are tested, approved and traceable before release.","Change Management","COBIT BAI06","Applications Manager","Continuous","High","Change ticket, test results and approval"],
      ["ITGC-005","Emergency Change Review","Emergency changes receive retrospective approval and review.","Change Management","COBIT BAI06","Applications Manager","Monthly","Medium","Emergency change ticket and retrospective approval"],
      ["ITGC-006","Backup Completion Monitoring","Scheduled backups are monitored and failures are resolved.","IT Operations","ISO 27001 A.8.13","Infrastructure Manager","Daily","High","Backup job logs and exception resolution"],
      ["ITGC-007","Restore Testing","Critical system backups are periodically restored to verify recoverability.","Business Continuity","ISO 27001 A.8.13","Infrastructure Manager","Quarterly","High","Restore test report and screenshots"],
      ["ITGC-008","Vulnerability Remediation","Critical vulnerabilities are remediated within approved timelines.","Cybersecurity","ISO 27001 A.8.8","Security Manager","Monthly","High","Scanner report and remediation evidence"],
      ["ITGC-009","Security Log Monitoring","Security-relevant logs are centrally collected and reviewed.","Monitoring","ISO 27001 A.8.15","SOC Lead","Daily","High","SIEM alerts, review logs and incident references"],
      ["ITGC-010","Firewall Rule Review","Firewall rules are periodically reviewed for business need and least privilege.","Network Security","ISO 27001 A.8.20","Network Manager","Quarterly","Medium","Rule export and signed review"],
      ["ITGC-011","Patch Compliance Monitoring","Servers and endpoints are assessed against approved patching thresholds.","IT Operations","ISO 27001 A.8.8","Infrastructure Manager","Monthly","Medium","Patch compliance report"],
      ["ITGC-012","Database Privileged Activity Review","Privileged database activity is monitored for inappropriate actions.","Database Security","COBIT DSS05","Database Administrator","Monthly","High","DB audit extract and reviewer sign-off"]
    ];
    for(const row of seed){
      await pool.query(`INSERT INTO controls(organization_id,control_code,title,description,category,framework_ref,owner,frequency,risk_level,evidence_required,next_due)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,current_date + interval '30 days')`,[orgId,...row]);
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
