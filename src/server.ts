import "dotenv/config";
import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Pool } from "pg";
import { z } from "zod";
import path from "path";
import multer from "multer";
import crypto from "crypto";
import archiver from "archiver";
import { controlCatalog, integrationCatalog } from "./seed";
import {registerCommercial,SessionUser,queueNotice} from "./commercial-api";
import {migrateCommercial} from "./commercial-schema";
import {dispatchSmtp} from "./commercial-notifications";
import { liveConnectorKeys, connectorFields, validateConnector, collectConnector } from "./connectors";

type TokenPayload = SessionUser;
type AuthedRequest = Request & { user?: TokenPayload };

const app = express();
const asyncRoute=(fn:(req:AuthedRequest,res:Response,next:NextFunction)=>any)=>(req:Request,res:Response,next:NextFunction)=>{Promise.resolve(fn(req,res,next)).catch(next)};
const port = Number(process.env.PORT || 10000);
const jwtSecret = process.env.JWT_SECRET || (process.env.NODE_ENV === "production" ? "" : "dev-only-change-me");
if (!jwtSecret) throw new Error("JWT_SECRET is required in production");

const databaseUrl=process.env.DATABASE_URL || "";
if(!databaseUrl) throw new Error("DATABASE_URL is required");
const effectiveDatabaseUrl=process.env.NODE_ENV==="production" ? (()=>{const u=new URL(databaseUrl);u.searchParams.set("sslmode","verify-full");return u.toString()})() : databaseUrl;
const pool = new Pool({ connectionString: effectiveDatabaseUrl });

const allowedOrigins=(process.env.ALLOWED_ORIGINS || "").split(",").map(x=>x.trim()).filter(Boolean);
if(process.env.NODE_ENV==="production" && !allowedOrigins.length) throw new Error("ALLOWED_ORIGINS is required in production");
app.set("trust proxy",1);
app.use(helmet({
  contentSecurityPolicy:{
    directives:{
      defaultSrc:["'self'"],
      scriptSrc:["'self'"],
      styleSrc:["'self'","https://fonts.googleapis.com"],
      fontSrc:["'self'","https://fonts.gstatic.com","data:"],
      imgSrc:["'self'","data:"],
      connectSrc:["'self'"],
      objectSrc:["'none'"],
      frameAncestors:["'none'"],
      baseUri:["'self'"],
      formAction:["'self'"]
    }
  },
  referrerPolicy:{policy:"strict-origin-when-cross-origin"}
}));
app.use(cors({
  origin:(origin,callback)=>{
    if(!origin || process.env.NODE_ENV!=="production" || allowedOrigins.includes(origin)) return callback(null,true);
    callback(new Error("Origin not allowed"));
  },
  methods:["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders:["Content-Type","Authorization"]
}));
const apiLimiter=rateLimit({windowMs:15*60*1000,limit:600,standardHeaders:"draft-8",legacyHeaders:false});
const loginLimiter=rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:"draft-8",legacyHeaders:false,skipSuccessfulRequests:true});
app.use("/api",apiLimiter);
app.use("/api/auth/login",loginLimiter);
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
  admin:["dashboard.read","controls.read","controls.write","assessments.read","assessments.write","assessments.review","evidence.read","evidence.write","evidence.review","findings.read","findings.write","audit.read","users.read","users.write","settings.read","settings.write","integrations.read","integrations.write","automation.read","automation.write","reports.read"],
  control_manager:["dashboard.read","controls.read","controls.write","assessments.read","assessments.write","assessments.review","evidence.read","evidence.write","evidence.review","findings.read","findings.write","audit.read","users.read","integrations.read","automation.read","automation.write","reports.read"],
  control_officer:["dashboard.read","controls.read","assessments.read","assessments.write","evidence.read","evidence.write","findings.read","findings.write","integrations.read","automation.read"],
  auditor:["dashboard.read","controls.read","assessments.read","assessments.write","assessments.review","evidence.read","evidence.write","evidence.review","findings.read","findings.write","audit.read","integrations.read","automation.read","reports.read"],
  reviewer:["dashboard.read","controls.read","assessments.read","assessments.review","evidence.read","evidence.write","evidence.review","findings.read","findings.write","audit.read","integrations.read","automation.read","reports.read"],
  viewer:["dashboard.read","controls.read","assessments.read","evidence.read","findings.read","integrations.read","automation.read","reports.read"]
};

function sessionCookie(req:Request){const cookie=String(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('ecm_session='));return cookie?decodeURIComponent(cookie.slice(12)):''}
function setSessionCookie(res:Response,token:string){res.cookie('ecm_session',token,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'strict',path:'/',maxAge:8*60*60*1000})}
async function auth(req:AuthedRequest,res:Response,next:NextFunction){
 try{
  const bearer=req.headers.authorization?.startsWith('Bearer ')?req.headers.authorization.slice(7):'',token=bearer||sessionCookie(req);
  if(!token)return res.status(401).json({error:'Authentication required'});
  const signed=jwt.verify(token,jwtSecret) as TokenPayload;
  const q=await pool.query('SELECT u.*,o.status AS org_status,o.subscription_expires FROM users u JOIN organizations o ON o.id=u.organization_id WHERE u.id=$1 AND u.email=$2',[signed.id,signed.email]);
  const u=q.rows[0];if(!u||u.status!=='active'||Number(signed.sessionVersion||1)!==u.session_version)return res.status(401).json({error:'Session expired or access was removed'});
  if(signed.orgId!==u.organization_id&&!u.platform_admin)return res.status(403).json({error:'Organisation access denied'});
  if(u.org_status!=='active'&&!u.platform_admin)return res.status(403).json({error:'This organisation is suspended. Contact the platform administrator.'});
  const authPath=req.path.startsWith('/api/auth/');
  req.user={id:u.id,orgId:signed.orgId,role:u.role,email:u.email,name:u.name,mustChange:u.must_change_password,platformAdmin:u.platform_admin,sessionVersion:u.session_version,subscriptionExpired:!!u.subscription_expires&&new Date(u.subscription_expires).toISOString().slice(0,10)<new Date().toISOString().slice(0,10)};
  if(u.must_change_password&&u.temporary_password_expires&&new Date(u.temporary_password_expires)<new Date())return res.status(401).json({error:'The temporary password expired. Ask an admin to issue a new one.'});
  if(u.must_change_password&&!['/api/auth/me','/api/auth/change-password','/api/auth/logout'].includes(req.path))return res.status(403).json({error:'Set your personal password before opening the workspace.',code:'PASSWORD_CHANGE_REQUIRED'});
  if(req.user.subscriptionExpired&&!u.platform_admin&&!authPath&&!['GET','HEAD'].includes(req.method))return res.status(403).json({error:'The workspace subscription expired. It is read-only until renewed.'});
  if(!bearer&&!['GET','HEAD','OPTIONS'].includes(req.method)){
   const origin=req.headers.origin;if(!origin||!(allowedOrigins.includes(origin)||process.env.NODE_ENV!=='production'&&origin===`http://localhost:${port}`))return res.status(403).json({error:'Request origin could not be verified.'});
  }
  next();
 }catch(err){if(err instanceof jwt.JsonWebTokenError||err instanceof jwt.TokenExpiredError)return res.status(401).json({error:'Session expired or invalid'});next(err)}
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

async function hasControlAccess(user:TokenPayload,controlId:number){
  const officer=user.role==="control_officer";
  const q=await pool.query("SELECT 1 FROM controls WHERE id=$1 AND organization_id=$2 AND ($3::boolean=false OR assigned_user_id=$4)",[controlId,user.orgId,officer,user.id]);
  return Boolean(q.rowCount);
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
    ALTER TABLE controls ADD COLUMN IF NOT EXISTS assigned_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
    ALTER TABLE findings ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
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

  await migrateCommercial(pool);
  const adminEmail = process.env.ADMIN_EMAIL || (process.env.NODE_ENV !== "production" ? "admin@revoltx.local" : "");
  const adminPassword = process.env.ADMIN_PASSWORD || (process.env.NODE_ENV !== "production" ? "ChangeMe!234" : "");
  if(!adminEmail || !adminPassword) throw new Error("ADMIN_EMAIL and ADMIN_PASSWORD are required");

  let org = await pool.query("SELECT id FROM organizations WHERE slug='revolt-demo'");
  let orgId:number;
  if(!org.rowCount){
    const created=await pool.query("INSERT INTO organizations(name,slug) VALUES($1,$2) RETURNING id",["Revolt-X Enterprise Control Management","revolt-demo"]);
    orgId=created.rows[0].id;
  } else orgId=org.rows[0].id;

  const existing=await pool.query('SELECT id FROM users WHERE lower(email)=lower($1)',[adminEmail]);
  if(!existing.rowCount){const hash=await bcrypt.hash(adminPassword,12);await pool.query("INSERT INTO users(organization_id,name,email,password_hash,role,status,must_change_password,temporary_password_expires,platform_admin) VALUES($1,$2,$3,$4,'admin','active',true,now()+interval '24 hours',true)",[orgId,process.env.ADMIN_NAME||'Platform Administrator',adminEmail,hash])}
  // Existing personal passwords and customer settings must survive restarts.

  for(const item of controlCatalog){
    await pool.query(`INSERT INTO controls(organization_id,control_code,title,description,category,framework_ref,owner,frequency,risk_level,evidence_required,next_due)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,current_date + interval '30 days')
      ON CONFLICT(organization_id,control_code) DO NOTHING`,
      [orgId,item.code,item.title,item.description,item.category,item.framework,item.owner,item.frequency,item.risk,item.evidence]);
  }

  for(const item of integrationCatalog){
    await pool.query(`INSERT INTO integrations(organization_id,provider_key,name,category,auth_type,capabilities)
      VALUES($1,$2,$3,$4,$5,$6::jsonb)
      ON CONFLICT(organization_id,provider_key) DO NOTHING`,
      [orgId,item.key,item.name,item.category,item.authType,JSON.stringify(item.capabilities)]);
  }

}

app.get("/api/health",asyncRoute(async(_req,res)=>{
  try{ await pool.query("SELECT 1"); res.json({status:"ok",database:"ready",service:"Revolt-X IT Control Management",version:"2.0.0",modules:12}); }
  catch(e){ res.status(503).json({status:"error",database:"unavailable"}); }
}));

app.post("/api/auth/login",asyncRoute(async(req,res)=>{
  const schema=z.object({email:z.string().email(),password:z.string().min(6)});
  const parsed=schema.safeParse(req.body);
  if(!parsed.success) return res.status(400).json({error:"Enter a valid email and password"});
  const found=await pool.query("SELECT * FROM users WHERE lower(email)=lower($1) AND status='active'",[parsed.data.email]);
  if(!found.rowCount || !(await bcrypt.compare(parsed.data.password,found.rows[0].password_hash))) return res.status(401).json({error:"Invalid email or password"});
  const u=found.rows[0];
  if(u.must_change_password&&u.temporary_password_expires&&new Date(u.temporary_password_expires)<new Date())return res.status(401).json({error:'Temporary password expired. Ask an admin to issue another.'});
  const payload:TokenPayload={id:u.id,orgId:u.organization_id,role:u.role,email:u.email,name:u.name,mustChange:u.must_change_password,platformAdmin:u.platform_admin,sessionVersion:u.session_version};
  const token=jwt.sign(payload,jwtSecret,{expiresIn:"8h"});
  const remote=req.socket.remoteAddress||"";
  const internalSmoke=req.headers["x-revolt-smoke-test"]==="1" && ["127.0.0.1","::1","::ffff:127.0.0.1"].includes(remote);
  if(!internalSmoke) await audit(payload,"LOGIN","session",null,{});
  setSessionCookie(res,token);res.json({token,user:payload,permissions:permissions[u.role]||[]});
}));

app.get("/api/auth/me",auth,(req:AuthedRequest,res)=>res.json({user:req.user,permissions:permissions[req.user!.role]||[]}));

app.get("/api/dashboard",auth,permit("dashboard.read"),asyncRoute(async(req:AuthedRequest,res)=>{
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
}));

app.get("/api/dashboard/progress",auth,permit("dashboard.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const period=String(req.query.period||"quarter");
  const frequency=String(req.query.frequency||"");
  if(!["month","quarter","year"].includes(period)) return res.status(400).json({error:"Period must be month, quarter or year"});
  const anchorRaw=String(req.query.anchor||new Date().toISOString().slice(0,10));
  const anchor=new Date(anchorRaw+"T00:00:00Z");if(Number.isNaN(anchor.getTime()))return res.status(400).json({error:"Invalid anchor date"});
  let start:Date,end:Date,label:string;
  if(period==="month"){start=new Date(Date.UTC(anchor.getUTCFullYear(),anchor.getUTCMonth(),1));end=new Date(Date.UTC(anchor.getUTCFullYear(),anchor.getUTCMonth()+1,1));label=start.toLocaleString("en-GB",{month:"long",year:"numeric",timeZone:"UTC"});}
  else if(period==="quarter"){const q=Math.floor(anchor.getUTCMonth()/3);start=new Date(Date.UTC(anchor.getUTCFullYear(),q*3,1));end=new Date(Date.UTC(anchor.getUTCFullYear(),q*3+3,1));label="Q"+(q+1)+" "+anchor.getUTCFullYear();}
  else{start=new Date(Date.UTC(anchor.getUTCFullYear(),0,1));end=new Date(Date.UTC(anchor.getUTCFullYear()+1,0,1));label=String(anchor.getUTCFullYear());}
  const requestedAssignee=Number(req.query.assignee_id||0)||null;
  const assigneeId=req.user!.role==="control_officer"?req.user!.id:requestedAssignee;
  const params:any[]=[req.user!.orgId,start.toISOString(),end.toISOString(),frequency,assigneeId];
  const rows=await pool.query(`SELECT c.id,c.control_code,c.title,c.category,c.owner,c.frequency,c.risk_level,c.next_due,c.last_tested,c.assigned_user_id,u.name assigned_user_name,u.email assigned_user_email,
    (SELECT a.id FROM assessments a WHERE a.control_id=c.id AND a.tested_at >= $2::timestamptz AND a.tested_at < $3::timestamptz ORDER BY a.tested_at DESC LIMIT 1) period_assessment_id,
    (SELECT a.result FROM assessments a WHERE a.control_id=c.id AND a.tested_at >= $2::timestamptz AND a.tested_at < $3::timestamptz ORDER BY a.tested_at DESC LIMIT 1) period_result,
    (SELECT a.score FROM assessments a WHERE a.control_id=c.id AND a.tested_at >= $2::timestamptz AND a.tested_at < $3::timestamptz ORDER BY a.tested_at DESC LIMIT 1) period_score,
    (SELECT count(*)::int FROM evidence e WHERE e.control_id=c.id AND COALESCE(e.collected_at,e.created_at) >= $2::timestamptz AND COALESCE(e.collected_at,e.created_at) < $3::timestamptz) period_evidence,
    (SELECT count(*)::int FROM findings f WHERE f.control_id=c.id AND f.status NOT IN ('Closed','Resolved')) open_findings
    FROM controls c LEFT JOIN users u ON u.id=c.assigned_user_id
    WHERE c.organization_id=$1 AND c.status='Active'
      AND ($4='' OR c.frequency=$4)
      AND ($5::int IS NULL OR c.assigned_user_id=$5)
    ORDER BY c.risk_level='High' DESC,c.control_code`,params);
  const now=new Date();
  const items=rows.rows.map((r:any)=>{
    const completed=Boolean(r.period_assessment_id);
    const inProgress=!completed && Number(r.period_evidence)>0;
    const overdue=!completed && !inProgress && r.next_due && new Date(r.next_due)<now;
    const status=completed?"Completed":inProgress?"In Progress":overdue?"Overdue":"Not Started";
    const progress=completed?100:inProgress?50:overdue?10:0;
    return {...r,work_status:status,progress};
  });
  const count=(s:string)=>items.filter((x:any)=>x.work_status===s).length,total=items.length;
  const byFrequency=Object.values(items.reduce((acc:any,x:any)=>{const k=x.frequency||"Other";acc[k]??={frequency:k,total:0,completed:0,in_progress:0,overdue:0,not_started:0};acc[k].total++;if(x.work_status==="Completed")acc[k].completed++;else if(x.work_status==="In Progress")acc[k].in_progress++;else if(x.work_status==="Overdue")acc[k].overdue++;else acc[k].not_started++;return acc;},{}));
  const byOfficer=Object.values(items.reduce((acc:any,x:any)=>{const k=String(x.assigned_user_id||0);acc[k]??={user_id:x.assigned_user_id,name:x.assigned_user_name||"Unassigned",total:0,completed:0,in_progress:0,overdue:0};acc[k].total++;if(x.work_status==="Completed")acc[k].completed++;if(x.work_status==="In Progress")acc[k].in_progress++;if(x.work_status==="Overdue")acc[k].overdue++;return acc;},{}));
  res.json({
    period,label,start:start.toISOString(),end:end.toISOString(),frequency:frequency||"All",assignee_id:assigneeId,
    summary:{total,completed:count("Completed"),in_progress:count("In Progress"),overdue:count("Overdue"),not_started:count("Not Started"),completion_percent:total?Math.round(count("Completed")/total*100):0,activity_percent:total?Math.round(items.reduce((s:number,x:any)=>s+x.progress,0)/total):0},
    by_frequency:byFrequency,by_officer:byOfficer,items
  });
}));

app.get("/api/control-library",auth,permit("controls.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const active=await pool.query("SELECT control_code FROM controls WHERE organization_id=$1",[req.user!.orgId]);
  const activeSet=new Set(active.rows.map((r:any)=>r.control_code));
  res.json(controlCatalog.map(item=>({...item,active:activeSet.has(item.code)})));
}));

app.post("/api/control-library/:code/add",auth,permit("controls.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const item=controlCatalog.find(x=>x.code===req.params.code);
  if(!item) return res.status(404).json({error:"Control template not found"});
  try{
    const q=await pool.query(`INSERT INTO controls(organization_id,control_code,title,description,category,framework_ref,owner,frequency,risk_level,evidence_required,next_due)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,current_date+interval '30 days') RETURNING *`,
      [req.user!.orgId,item.code,item.title,item.description,item.category,item.framework,item.owner,item.frequency,item.risk,item.evidence]);
    await audit(req.user!,"ADD_FROM_LIBRARY","control",q.rows[0].id,{code:item.code});res.status(201).json(q.rows[0]);
  }catch(e:any){res.status(409).json({error:e.code==="23505"?"This control is already in the register":"Unable to add control"});}
}));

app.get("/api/controls",auth,permit("controls.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const {search="",category="",risk=""}=req.query as Record<string,string>;
  const out=await pool.query(`SELECT c.*,au.name assigned_user_name,au.email assigned_user_email,
    (SELECT result FROM assessments a WHERE a.control_id=c.id ORDER BY tested_at DESC LIMIT 1) latest_result,
    (SELECT count(*)::int FROM evidence e WHERE e.control_id=c.id) evidence_count,
    (SELECT count(*)::int FROM findings f WHERE f.control_id=c.id AND f.status NOT IN ('Closed','Resolved')) open_findings
    FROM controls c LEFT JOIN users au ON au.id=c.assigned_user_id WHERE c.organization_id=$1
    AND ($2='' OR c.title ILIKE '%'||$2||'%' OR c.control_code ILIKE '%'||$2||'%')
    AND ($3='' OR c.category=$3) AND ($4='' OR c.risk_level=$4)
    AND ($5::boolean=false OR c.assigned_user_id=$6)
    ORDER BY c.control_code`,[req.user!.orgId,search,category,risk,req.user!.role==="control_officer",req.user!.id]);
  res.json(out.rows);
}));

app.get("/api/controls/:id",auth,permit("controls.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const control=await pool.query("SELECT c.*,u.name assigned_user_name,u.email assigned_user_email FROM controls c LEFT JOIN users u ON u.id=c.assigned_user_id WHERE c.id=$1 AND c.organization_id=$2 AND ($3::boolean=false OR c.assigned_user_id=$4)",[id,req.user!.orgId,req.user!.role==="control_officer",req.user!.id]);
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
}));

app.post("/api/controls/:id/test",auth,permit("assessments.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const controlId=Number(req.params.id);
  const schema=z.object({
    period:z.string().min(2),
    test_objective:z.string().min(5),
    test_procedure:z.string().min(5),
    result:z.enum(["Effective","Partially Effective","Ineffective"]),
    score:z.number().int().min(0).max(100),
    sample_size:z.number().int().min(0).nullable().optional(),
    exception_count:z.number().int().min(0).default(0),
    evidence_ids:z.array(z.number().int()).min(1),
    design_effective:z.boolean().nullable().optional(),
    operating_effective:z.boolean().nullable().optional(),
    notes:z.string().default(""),
    raise_finding:z.boolean().default(false),
    finding_title:z.string().optional(),
    finding_severity:z.enum(["Low","Medium","High"]).optional(),
    retest_of:z.number().int().nullable().optional()
  });
  const p=schema.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Complete the required testing fields",details:p.error.flatten()});
  const ctrl=await pool.query("SELECT * FROM controls WHERE id=$1 AND organization_id=$2 AND ($3::boolean=false OR assigned_user_id=$4)",[controlId,req.user!.orgId,req.user!.role==="control_officer",req.user!.id]);
  if(!ctrl.rowCount) return res.status(404).json({error:"Control not found or not assigned to you"});
  if(p.data.evidence_ids.length){
    const ev=await pool.query("SELECT id FROM evidence WHERE organization_id=$1 AND control_id=$2 AND NOT is_sample AND id=ANY($3::int[])",[req.user!.orgId,controlId,p.data.evidence_ids]);
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
}));

app.post("/api/controls",auth,permit("controls.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const schema=z.object({control_code:z.string().min(3),title:z.string().min(3),description:z.string().default(""),category:z.string().min(2),framework_ref:z.string().default(""),owner:z.string().default(""),assigned_user_id:z.number().int().nullable().optional(),frequency:z.string().default("Quarterly"),risk_level:z.enum(["Low","Medium","High"]),evidence_required:z.string().default(""),testing_criteria:z.string().default("")});
  const p=schema.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Please complete the required control fields",details:p.error.flatten()});
  try{
    const d=p.data;
    if(d.assigned_user_id){
      const assignee=await pool.query("SELECT id FROM users WHERE id=$1 AND organization_id=$2 AND status='active' AND role IN ('control_manager','control_officer')",[d.assigned_user_id,req.user!.orgId]);
      if(!assignee.rowCount)return res.status(400).json({error:"Assigned officer must be an active Control Manager or Control Officer in this workspace"});
    }
    const q=await pool.query(`INSERT INTO controls(organization_id,control_code,title,description,category,framework_ref,owner,assigned_user_id,frequency,risk_level,evidence_required,testing_criteria,next_due)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,current_date + interval '30 days') RETURNING *`,
      [req.user!.orgId,d.control_code,d.title,d.description,d.category,d.framework_ref,d.owner,d.assigned_user_id??null,d.frequency,d.risk_level,d.evidence_required,d.testing_criteria]);
    await audit(req.user!,"CREATE","control",q.rows[0].id,{code:d.control_code}); res.status(201).json(q.rows[0]);
  }catch(e:any){res.status(409).json({error:e.code==="23505"?"Control code already exists":"Unable to create control"});}
}));

app.put("/api/controls/:id",auth,permit("controls.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id); const allowed=["title","description","category","framework_ref","owner","assigned_user_id","frequency","status","risk_level","evidence_required","testing_criteria","next_due"];
  const fields=allowed.filter(k=>req.body[k]!==undefined); if(!fields.length) return res.status(400).json({error:"No supported fields supplied"});
  if(req.body.assigned_user_id){
    const assignee=await pool.query("SELECT id FROM users WHERE id=$1 AND organization_id=$2 AND status='active' AND role IN ('control_manager','control_officer')",[Number(req.body.assigned_user_id),req.user!.orgId]);
    if(!assignee.rowCount)return res.status(400).json({error:"Assigned officer must be an active Control Manager or Control Officer in this workspace"});
  }
  const vals=fields.map(k=>req.body[k]); const set=fields.map((k,i)=>`${k}=$${i+3}`).join(",");
  const q=await pool.query(`UPDATE controls SET ${set},updated_at=now() WHERE id=$1 AND organization_id=$2 RETURNING *`,[id,req.user!.orgId,...vals]);
  if(!q.rowCount) return res.status(404).json({error:"Control not found"}); await audit(req.user!,"UPDATE","control",id,{fields}); res.json(q.rows[0]);
}));

app.get("/api/assessments",auth,permit("assessments.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT a.*,c.control_code,c.title control_title,u.name tester_name FROM assessments a
    JOIN controls c ON c.id=a.control_id LEFT JOIN users u ON u.id=a.tester_id WHERE a.organization_id=$1 AND ($4::text='' OR a.is_sample=($4='sample')) AND ($2::boolean=false OR c.assigned_user_id=$3) ORDER BY a.tested_at DESC`,[req.user!.orgId,req.user!.role==="control_officer",req.user!.id,["actual","sample"].includes(String(req.query.dataset))?String(req.query.dataset):""]);
  res.json(q.rows);
}));

app.post('/api/assessments',auth,(_req,res)=>res.status(410).json({error:'Use the Test Control workflow to document the procedure and evidence.'}));

app.post("/api/evidence/upload",auth,permit("evidence.write"),upload.single("file"),asyncRoute(async(req:AuthedRequest,res)=>{
  if(!req.file) return res.status(400).json({error:"Choose a file to upload"});
  const controlId=Number(req.body.control_id);
  if(!Number.isInteger(controlId)) return res.status(400).json({error:"Select a control"});
  if(!(await hasControlAccess(req.user!,controlId))) return res.status(404).json({error:"Control not found or not assigned to you"});
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
}));

app.get("/api/evidence/files/:id",auth,permit("evidence.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const q=await pool.query(`SELECT f.* FROM evidence_files f JOIN evidence e ON e.file_id=f.id JOIN controls c ON c.id=e.control_id WHERE f.id=$1 AND f.organization_id=$2 AND ($3::boolean=false OR c.assigned_user_id=$4)`,[id,req.user!.orgId,req.user!.role==="control_officer",req.user!.id]);
  if(!q.rowCount) return res.status(404).json({error:"Evidence file not found"});
  const f=q.rows[0];res.setHeader("Content-Type",f.mime_type);res.setHeader("Content-Length",String(f.size_bytes));
  res.setHeader("Content-Disposition",'attachment; filename="'+String(f.original_name).replace(/["\r\n]/g,"")+'"');res.setHeader("X-Evidence-SHA256",f.sha256);await audit(req.user!,"DOWNLOAD_EVIDENCE","evidence_file",id,{sha256:f.sha256});res.send(f.content);
}));

app.post("/api/evidence/:id/verify",auth,permit("evidence.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const q=await pool.query(`SELECT e.id,e.sha256,e.file_id,f.content,f.sha256 stored_file_sha FROM evidence e
    LEFT JOIN evidence_files f ON f.id=e.file_id JOIN controls c ON c.id=e.control_id
    WHERE e.id=$1 AND e.organization_id=$2 AND ($3::boolean=false OR c.assigned_user_id=$4)`,[id,req.user!.orgId,req.user!.role==="control_officer",req.user!.id]);
  if(!q.rowCount)return res.status(404).json({error:"Evidence not found"});
  if(!q.rows[0].file_id)return res.status(400).json({error:"Integrity verification is available for uploaded source files"});
  const calculated=crypto.createHash("sha256").update(q.rows[0].content).digest("hex");
  const valid=calculated===q.rows[0].sha256 && calculated===q.rows[0].stored_file_sha;
  await audit(req.user!,"VERIFY_EVIDENCE","evidence",id,{valid,sha256:calculated});
  res.json({valid,sha256:calculated});
}));

app.post("/api/evidence/:id/review",auth,permit("evidence.review"),asyncRoute(async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const independent=await pool.query('SELECT uploaded_by,is_sample FROM evidence WHERE id=$1 AND organization_id=$2',[id,req.user!.orgId]);if(!independent.rowCount)return res.status(404).json({error:'Record not found'});if(independent.rows[0].is_sample)return res.status(403).json({error:'Sample evidence is read-only'});if(independent.rows[0].uploaded_by===req.user!.id)return res.status(403).json({error:'An independent reviewer must make this decision'});
  const s=z.object({review_status:z.enum(["Approved","Rejected","Needs Update"]),review_notes:z.string().default("")});
  const p=s.safeParse(req.body);if(!p.success) return res.status(400).json({error:"Invalid review"});
  const q=await pool.query(`UPDATE evidence e SET review_status=$3,review_notes=$4,reviewed_by=$5,reviewed_at=now()
    FROM controls c WHERE e.control_id=c.id AND e.id=$1 AND e.organization_id=$2 AND ($6::boolean=false OR c.assigned_user_id=$7) RETURNING e.*`,
    [id,req.user!.orgId,p.data.review_status,p.data.review_notes,req.user!.id,req.user!.role==="control_officer",req.user!.id]);
  if(!q.rowCount) return res.status(404).json({error:"Evidence not found"});
  await audit(req.user!,"REVIEW_EVIDENCE","evidence",id,{status:p.data.review_status});res.json(q.rows[0]);
}));

app.post("/api/assessments/:id/review",auth,permit("assessments.review"),asyncRoute(async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const independent=await pool.query('SELECT tester_id,is_sample FROM assessments WHERE id=$1 AND organization_id=$2',[id,req.user!.orgId]);if(!independent.rowCount)return res.status(404).json({error:'Record not found'});if(independent.rows[0].is_sample)return res.status(403).json({error:'Sample tests are read-only'});if(independent.rows[0].tester_id===req.user!.id)return res.status(403).json({error:'An independent reviewer must make this decision'});
  const s=z.object({review_status:z.enum(["Reviewed","Needs Rework","Rejected"]),review_notes:z.string().default("")});
  const p=s.safeParse(req.body);if(!p.success)return res.status(400).json({error:"Invalid assessment review"});
  const q=await pool.query(`UPDATE assessments SET review_status=$3,review_notes=$4,reviewed_by=$5,reviewed_at=now()
    WHERE id=$1 AND organization_id=$2 RETURNING *`,[id,req.user!.orgId,p.data.review_status,p.data.review_notes,req.user!.id]);
  if(!q.rowCount)return res.status(404).json({error:"Assessment not found"});
  await audit(req.user!,"REVIEW_TEST","assessment",id,{status:p.data.review_status});res.json(q.rows[0]);
}));

app.get("/api/evidence",auth,permit("evidence.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT e.*,c.control_code,c.title control_title,u.name uploaded_by_name FROM evidence e
    JOIN controls c ON c.id=e.control_id LEFT JOIN users u ON u.id=e.uploaded_by WHERE e.organization_id=$1 AND ($4::text='' OR e.is_sample=($4='sample')) AND ($2::boolean=false OR c.assigned_user_id=$3) ORDER BY e.created_at DESC`,[req.user!.orgId,req.user!.role==="control_officer",req.user!.id,["actual","sample"].includes(String(req.query.dataset))?String(req.query.dataset):""]); res.json(q.rows);
}));

app.post("/api/evidence",auth,permit("evidence.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const s=z.object({control_id:z.number().int(),assessment_id:z.number().int().nullable().optional(),title:z.string().min(2),evidence_type:z.string().default("Document"),source:z.string().default("Manual Upload"),url:z.string().default(""),period:z.string().default(""),status:z.string().default("Current")});
  const p=s.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Invalid evidence data",details:p.error.flatten()});
  if(!(await hasControlAccess(req.user!,p.data.control_id))) return res.status(404).json({error:"Control not found or not assigned to you"});
  const d=p.data; const q=await pool.query(`INSERT INTO evidence(organization_id,control_id,assessment_id,title,evidence_type,source,url,period,status,uploaded_by)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,[req.user!.orgId,d.control_id,d.assessment_id??null,d.title,d.evidence_type,d.source,d.url,d.period,d.status,req.user!.id]);
  await audit(req.user!,"ADD_EVIDENCE","control",d.control_id,{evidenceId:q.rows[0].id,title:d.title}); res.status(201).json(q.rows[0]);
}));

app.get("/api/findings",auth,permit("findings.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT f.*,c.control_code,c.title control_title FROM findings f LEFT JOIN controls c ON c.id=f.control_id
    WHERE f.organization_id=$1 AND ($4::text='' OR f.is_sample=($4='sample')) AND ($2::boolean=false OR c.assigned_user_id=$3) ORDER BY CASE f.severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,f.created_at DESC`,[req.user!.orgId,req.user!.role==="control_officer",req.user!.id,["actual","sample"].includes(String(req.query.dataset))?String(req.query.dataset):""]); res.json(q.rows);
}));

app.post("/api/findings",auth,permit("findings.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const s=z.object({control_id:z.number().int().nullable().optional(),title:z.string().trim().min(3),description:z.string().default(""),severity:z.enum(["Low","Medium","High"]),status:z.enum(["Open","In Progress"]).default("Open"),owner:z.string().default(""),owner_user_id:z.number().int().nullable().optional(),root_cause:z.string().max(6000).default(""),recommendation:z.string().max(6000).default(""),completion_notes:z.string().max(6000).default(""),due_date:z.union([z.string().regex(/^\d{4}-\d{2}-\d{2}$/),z.literal(""),z.null()]).optional()});
  const p=s.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Please check the finding fields",details:p.error.flatten()});
  const d=p.data;
  if(req.user!.role==="control_officer"&&!d.control_id)return res.status(400).json({error:"Control Officers must link findings to an assigned control"});
  if(d.control_id){
    if(!(await hasControlAccess(req.user!,d.control_id)))return res.status(400).json({error:"The selected control is unavailable or not assigned to you"});
  }
  let owner=d.owner;if(d.owner_user_id){const u=await pool.query("SELECT name FROM users WHERE id=$1 AND organization_id=$2 AND status='active'",[d.owner_user_id,req.user!.orgId]);if(!u.rowCount)return res.status(400).json({error:"Choose an active owner in this organisation"});owner=u.rows[0].name;}
  try{
    const q=await pool.query(`INSERT INTO findings(organization_id,control_id,title,description,severity,status,owner,due_date,owner_user_id,root_cause,recommendation,completion_notes,updated_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now()) RETURNING *`,[req.user!.orgId,d.control_id??null,d.title,d.description,d.severity,d.status,owner,d.due_date||null,d.owner_user_id||null,d.root_cause,d.recommendation,d.completion_notes]);
    await audit(req.user!,"CREATE","finding",q.rows[0].id,{severity:d.severity,controlId:d.control_id??null,status:d.status});
    res.status(201).json(q.rows[0]);
  }catch(err:any){console.error("Create finding failed",err);res.status(500).json({error:"Unable to save finding"});}
}));

app.put("/api/findings/:id",auth,permit("findings.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);const schema=z.object({title:z.string().trim().min(3).max(240),status:z.enum(["Open","In Progress","Pending Review","Closed","Resolved"]),severity:z.enum(["Low","Medium","High"]),owner_user_id:z.number().int().nullable().optional(),due_date:z.string().regex(/^\d{4}-\d{2}-\d{2}$/).or(z.literal("")).nullable().optional(),description:z.string().max(6000),root_cause:z.string().max(6000).default(""),recommendation:z.string().max(6000).default(""),completion_notes:z.string().max(6000).default("")});const p=schema.safeParse(req.body);if(!p.success)return res.status(400).json({error:"Check the finding fields"});
  const existing=await pool.query(`SELECT f.* FROM findings f LEFT JOIN controls c ON c.id=f.control_id WHERE f.id=$1 AND f.organization_id=$2 AND ($3::boolean=false OR c.assigned_user_id=$4)`,[id,req.user!.orgId,req.user!.role==="control_officer",req.user!.id]);
  if(!existing.rowCount)return res.status(404).json({error:"Finding not found"});if(existing.rows[0].is_sample)return res.status(403).json({error:"Sample findings are read-only"});const d=p.data;let owner=existing.rows[0].owner;
  if(d.owner_user_id){const u=await pool.query("SELECT name FROM users WHERE id=$1 AND organization_id=$2 AND status='active'",[d.owner_user_id,req.user!.orgId]);if(!u.rowCount)return res.status(400).json({error:"Choose an active owner in this organisation"});owner=u.rows[0].name;}
  if(["Closed","Resolved"].includes(d.status)){
    if(!['admin','control_manager','auditor'].includes(req.user!.role)||existing.rows[0].owner_user_id===req.user!.id)return res.status(403).json({error:"An independent manager or auditor must verify closure"});
    if(!d.completion_notes)return res.status(400).json({error:"Record the closure verification"});
    const pass=await pool.query(`SELECT id FROM assessments WHERE organization_id=$1 AND control_id=$2 AND NOT is_sample AND result='Effective' AND tested_at >= $3 AND review_status='Reviewed' AND reviewed_by IS NOT NULL AND reviewed_by<>tester_id AND jsonb_array_length(evidence_ids)>0 ORDER BY tested_at DESC LIMIT 1`,[req.user!.orgId,existing.rows[0].control_id,existing.rows[0].created_at]);
    if(!pass.rowCount)return res.status(409).json({error:"An independently reviewed passing retest is required before closure"});
  }
  const q=await pool.query(`UPDATE findings SET title=$3,status=$4,severity=$5,owner=$6,owner_user_id=$7,due_date=$8,description=$9,root_cause=$10,recommendation=$11,completion_notes=$12,updated_at=now(),resolved_at=CASE WHEN $4 IN ('Closed','Resolved') THEN now() ELSE NULL END WHERE id=$1 AND organization_id=$2 RETURNING *`,[id,req.user!.orgId,d.title,d.status,d.severity,owner,d.owner_user_id||null,d.due_date||null,d.description,d.root_cause,d.recommendation,d.completion_notes]);
  await audit(req.user!,"UPDATE","finding",id,{status:d.status,ownerId:d.owner_user_id});res.json(q.rows[0]);
}));

app.post("/api/integrations/github/connect",auth,permit("integrations.write"),asyncRoute(async(req:AuthedRequest,res)=>{
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
}));

app.get("/api/integrations/github/repositories",auth,permit("integrations.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const q=await pool.query("SELECT * FROM integration_connections WHERE organization_id=$1 AND provider_key='github'",[req.user!.orgId]);
  if(!q.rowCount) return res.status(409).json({error:"GitHub is not connected"});
  try{
    const {token}=decryptSecret(q.rows[0]); const data=await githubApi("/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member",token);
    const repos=(data.body||[]).map((r:any)=>({full_name:r.full_name,name:r.name,owner:r.owner?.login,private:r.private,default_branch:r.default_branch,archived:r.archived,updated_at:r.updated_at,permissions:r.permissions}));
    res.json({repositories:repos,selected:q.rows[0].config?.repositories||[]});
  }catch(err:any){await pool.query("UPDATE integration_connections SET last_error=$2 WHERE organization_id=$1 AND provider_key='github'",[req.user!.orgId,err.message]);res.status(400).json({error:err.message});}
}));

app.put("/api/integrations/github/config",auth,permit("integrations.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const s=z.object({repositories:z.array(z.string()).max(100)});const p=s.safeParse(req.body);if(!p.success)return res.status(400).json({error:"Invalid repository selection"});
  const q=await pool.query("UPDATE integration_connections SET config=jsonb_set(COALESCE(config,'{}'::jsonb),'{repositories}',$2::jsonb,true) WHERE organization_id=$1 AND provider_key='github' RETURNING id",[req.user!.orgId,JSON.stringify(p.data.repositories)]);
  if(!q.rowCount)return res.status(409).json({error:"GitHub is not connected"});await audit(req.user!,"CONFIGURE","integration",null,{provider:"github",repositories:p.data.repositories});res.json({repositories:p.data.repositories});
}));

app.post("/api/integrations/github/sync",auth,permit("integrations.write"),asyncRoute(async(req:AuthedRequest,res)=>{
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
}));

app.delete("/api/integrations/github/connection",auth,permit("integrations.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const integration=await pool.query("SELECT id FROM integrations WHERE organization_id=$1 AND provider_key='github'",[req.user!.orgId]);
  await pool.query("DELETE FROM integration_connections WHERE organization_id=$1 AND provider_key='github'",[req.user!.orgId]);
  if(integration.rowCount) await pool.query("UPDATE integrations SET status='Available',tenant_ref='',last_sync_at=NULL WHERE id=$1",[integration.rows[0].id]);
  await audit(req.user!,"DISCONNECT","integration",integration.rows[0]?.id||null,{provider:"github"});res.json({status:"Available"});
}));

app.post("/api/integrations/:provider/connect",auth,permit("integrations.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const provider=String(req.params.provider||"");
  if(provider==="github") return res.status(400).json({error:"Use the dedicated GitHub connection flow"});
  if(!liveConnectorKeys.includes(provider as any)) return res.status(400).json({error:"This connector is catalogued but its live adapter is not enabled yet"});
  const credentials=req.body?.credentials||{},config=req.body?.config||{};
  try{
    const validation=await validateConnector(provider,credentials,config);
    const integration=await pool.query("SELECT id FROM integrations WHERE organization_id=$1 AND provider_key=$2",[req.user!.orgId,provider]);
    if(!integration.rowCount)return res.status(404).json({error:"Integration definition not found"});
    const secret=encryptSecret(credentials);
    const safeConfig={...config,identity:validation.identity,metadata:validation.metadata};
    await pool.query(`INSERT INTO integration_connections(organization_id,integration_id,provider_key,secret_ciphertext,secret_iv,secret_tag,config,connected_by,last_validated_at,last_error)
      VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,now(),NULL)
      ON CONFLICT(organization_id,provider_key) DO UPDATE SET integration_id=excluded.integration_id,secret_ciphertext=excluded.secret_ciphertext,secret_iv=excluded.secret_iv,secret_tag=excluded.secret_tag,config=excluded.config,connected_by=excluded.connected_by,connected_at=now(),last_validated_at=now(),last_error=NULL`,[
      req.user!.orgId,integration.rows[0].id,provider,secret.ciphertext,secret.iv,secret.tag,JSON.stringify(safeConfig),req.user!.id
    ]);
    await pool.query("UPDATE integrations SET status='Connected',tenant_ref=$3,last_sync_at=NULL WHERE id=$1 AND organization_id=$2",[integration.rows[0].id,req.user!.orgId,validation.identity||provider]);
    await audit(req.user!,"CONNECT","integration",integration.rows[0].id,{provider,identity:validation.identity});
    res.json({status:"Connected",identity:validation.identity,metadata:validation.metadata});
  }catch(err:any){res.status(err?.status===401||err?.status===403?401:400).json({error:err?.message||"Connector validation failed"});}
}));

app.post("/api/integrations/:provider/sync",auth,permit("integrations.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const provider=String(req.params.provider||"");
  if(provider==="github") return res.status(400).json({error:"Use the dedicated GitHub sync flow"});
  if(!liveConnectorKeys.includes(provider as any)) return res.status(400).json({error:"This connector does not have a live adapter yet"});
  const conn=await pool.query(`SELECT c.*,i.id integration_id FROM integration_connections c JOIN integrations i ON i.id=c.integration_id
    WHERE c.organization_id=$1 AND c.provider_key=$2`,[req.user!.orgId,provider]);
  if(!conn.rowCount)return res.status(409).json({error:"Connect and validate this provider before syncing"});
  try{
    const credentials=decryptSecret(conn.rows[0]),config=conn.rows[0].config||{};
    const collected=await collectConnector(provider,credentials,config);
    const codes=[...new Set(collected.map((e:any)=>e.controlCode))];
    const ctrl=await pool.query("SELECT id,control_code,owner FROM controls WHERE organization_id=$1 AND control_code=ANY($2::text[])",[req.user!.orgId,codes]);
    const byCode=Object.fromEntries(ctrl.rows.map((r:any)=>[r.control_code,r]));
    let created=0,findings=0;
    for(const item of collected){
      const control=byCode[item.controlCode];if(!control)continue;
      const json=JSON.stringify(item.payload),sha=crypto.createHash("sha256").update(json).digest("hex");
      await pool.query(`INSERT INTO evidence(organization_id,control_id,integration_id,title,evidence_type,source,period,status,automated,collected_at,expires_at,uploaded_by,sha256,review_status,evidence_payload)
        VALUES($1,$2,$3,$4,'System Snapshot',$5,to_char(current_date,'YYYY-MM'),'Current',true,now(),now()+interval '30 days',$6,$7,'Pending Review',$8::jsonb)`,[
        req.user!.orgId,control.id,conn.rows[0].integration_id,item.title,provider,req.user!.id,sha,json
      ]);created++;
      if(item.finding){
        const dup=await pool.query("SELECT id FROM findings WHERE organization_id=$1 AND control_id=$2 AND title=$3 AND status NOT IN ('Closed','Resolved')",[req.user!.orgId,control.id,item.finding.title]);
        if(!dup.rowCount){
          await pool.query(`INSERT INTO findings(organization_id,control_id,title,description,severity,status,owner,due_date)
            VALUES($1,$2,$3,$4,$5,'Open',$6,current_date+interval '14 days')`,[
            req.user!.orgId,control.id,item.finding.title,item.finding.description,item.finding.severity,item.finding.owner||control.owner||""
          ]);findings++;
        }
      }
    }
    await pool.query("UPDATE integrations SET status='Connected',last_sync_at=now() WHERE id=$1",[conn.rows[0].integration_id]);
    await pool.query("UPDATE integration_connections SET last_validated_at=now(),last_error=NULL WHERE id=$1",[conn.rows[0].id]);
    await audit(req.user!,"SYNC","integration",conn.rows[0].integration_id,{provider,evidenceCreated:created,findingsCreated:findings});
    res.json({provider,evidenceCreated:created,findingsCreated:findings});
  }catch(err:any){
    await pool.query("UPDATE integration_connections SET last_error=$2 WHERE id=$1",[conn.rows[0].id,err?.message||"Sync failed"]).catch(()=>{});
    res.status(400).json({error:err?.message||"Connector sync failed"});
  }
}));

app.delete("/api/integrations/:provider/connection",auth,permit("integrations.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const provider=String(req.params.provider||"");if(provider==="github")return res.status(400).json({error:"Use the dedicated GitHub disconnect flow"});
  const integration=await pool.query("SELECT id FROM integrations WHERE organization_id=$1 AND provider_key=$2",[req.user!.orgId,provider]);
  await pool.query("DELETE FROM integration_connections WHERE organization_id=$1 AND provider_key=$2",[req.user!.orgId,provider]);
  if(integration.rowCount)await pool.query("UPDATE integrations SET status='Available',tenant_ref='',last_sync_at=NULL WHERE id=$1",[integration.rows[0].id]);
  await audit(req.user!,"DISCONNECT","integration",integration.rows[0]?.id||null,{provider});res.json({status:"Available"});
}));

app.get("/api/integrations",auth,permit("integrations.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT i.*,
    (SELECT count(*)::int FROM automation_rules a WHERE a.integration_id=i.id) automation_count,
    EXISTS(SELECT 1 FROM integration_connections c WHERE c.integration_id=i.id AND c.organization_id=i.organization_id) has_connection
    FROM integrations i WHERE i.organization_id=$1 ORDER BY category,name`,[req.user!.orgId]);
  res.json(q.rows.map((r:any)=>({...r,connector_live:r.provider_key==="github"||liveConnectorKeys.includes(r.provider_key as any),connector_fields:r.provider_key==="github"?null:connectorFields(r.provider_key)})));
}));

app.put("/api/integrations/:id",auth,permit("integrations.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const s=z.object({status:z.enum(["Available","Configured","Paused"]),base_url:z.string().optional(),tenant_ref:z.string().optional()});
  const p=s.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Invalid integration settings"});
  const q=await pool.query(`UPDATE integrations SET status=$3,base_url=COALESCE($4,base_url),tenant_ref=COALESCE($5,tenant_ref),
    last_sync_at=CASE WHEN $3='Connected' THEN now() ELSE last_sync_at END WHERE id=$1 AND organization_id=$2 RETURNING *`,
    [id,req.user!.orgId,p.data.status,p.data.base_url??null,p.data.tenant_ref??null]);
  if(!q.rowCount) return res.status(404).json({error:"Integration not found"});
  await audit(req.user!,"UPDATE","integration",id,{status:p.data.status});res.json(q.rows[0]);
}));

app.get("/api/automation",auth,permit("automation.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT a.*,c.control_code,c.title control_title,i.name integration_name,i.status integration_status
    FROM automation_rules a JOIN controls c ON c.id=a.control_id JOIN integrations i ON i.id=a.integration_id
    WHERE a.organization_id=$1 ORDER BY a.status,a.name`,[req.user!.orgId]);
  res.json(q.rows);
}));

app.post("/api/automation",auth,permit("automation.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const s=z.object({control_id:z.number().int(),integration_id:z.number().int(),name:z.string().min(3),schedule:z.string().min(2),evidence_type:z.string().default("System Report")});
  const p=s.safeParse(req.body); if(!p.success) return res.status(400).json({error:"Invalid automation rule",details:p.error.flatten()});
  const d=p.data;
  const valid=await pool.query(`SELECT 1 FROM controls c JOIN integrations i ON i.organization_id=c.organization_id
    WHERE c.id=$1 AND i.id=$2 AND c.organization_id=$3`,[d.control_id,d.integration_id,req.user!.orgId]);
  if(!valid.rowCount) return res.status(400).json({error:"Control or integration is not available to this organisation"});
  const q=await pool.query("INSERT INTO automation_rules(organization_id,control_id,integration_id,name,schedule,evidence_type,status) VALUES($1,$2,$3,$4,$5,$6,'Ready') RETURNING *",
    [req.user!.orgId,d.control_id,d.integration_id,d.name,d.schedule,d.evidence_type]);
  await audit(req.user!,"CREATE","automation_rule",q.rows[0].id,{controlId:d.control_id,integrationId:d.integration_id});res.status(201).json(q.rows[0]);
}));

app.post("/api/automation/:id/run",auth,permit("automation.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);
  const q=await pool.query(`SELECT a.*,i.status integration_status,i.provider_key,c.control_code,c.owner control_owner
    FROM automation_rules a JOIN integrations i ON i.id=a.integration_id JOIN controls c ON c.id=a.control_id
    WHERE a.id=$1 AND a.organization_id=$2`,[id,req.user!.orgId]);
  if(!q.rowCount) return res.status(404).json({error:"Automation rule not found"});
  const rule=q.rows[0];
  if(rule.integration_status!=="Connected") return res.status(409).json({error:"Connect and validate the source integration before running automated evidence collection"});
  if(rule.provider_key==="github"){
    return res.status(202).json({message:"Run GitHub Sync from Integrations. It collects the mapped GitHub controls in one validated repository pass."});
  }
  if(!liveConnectorKeys.includes(rule.provider_key as any)) return res.status(501).json({error:"This provider does not have a live evidence collector yet"});
  const conn=await pool.query("SELECT * FROM integration_connections WHERE organization_id=$1 AND integration_id=$2",[req.user!.orgId,rule.integration_id]);
  if(!conn.rowCount) return res.status(409).json({error:"The integration connection is missing or has been disconnected"});
  try{
    const credentials=decryptSecret(conn.rows[0]),config=conn.rows[0].config||{};
    const collected=(await collectConnector(rule.provider_key,credentials,config)).filter((x:any)=>x.controlCode===rule.control_code);
    if(!collected.length) return res.status(409).json({error:"This automation rule is not mapped to evidence returned by the provider adapter"});
    let created=0,findings=0;
    for(const item of collected){
      const json=JSON.stringify(item.payload),sha=crypto.createHash("sha256").update(json).digest("hex");
      await pool.query(`INSERT INTO evidence(organization_id,control_id,integration_id,title,evidence_type,source,period,status,automated,collected_at,expires_at,uploaded_by,sha256,review_status,evidence_payload)
        VALUES($1,$2,$3,$4,$5,$6,to_char(current_date,'YYYY-MM'),'Current',true,now(),now()+interval '30 days',$7,$8,'Pending Review',$9::jsonb)`,[
        req.user!.orgId,rule.control_id,rule.integration_id,item.title,rule.evidence_type||"System Snapshot",rule.provider_key,req.user!.id,sha,json
      ]);created++;
      if(item.finding){
        const dup=await pool.query("SELECT id FROM findings WHERE organization_id=$1 AND control_id=$2 AND title=$3 AND status NOT IN ('Closed','Resolved')",[req.user!.orgId,rule.control_id,item.finding.title]);
        if(!dup.rowCount){
          await pool.query(`INSERT INTO findings(organization_id,control_id,title,description,severity,status,owner,due_date)
            VALUES($1,$2,$3,$4,$5,'Open',$6,current_date+interval '14 days')`,[
            req.user!.orgId,rule.control_id,item.finding.title,item.finding.description,item.finding.severity,item.finding.owner||rule.control_owner||""
          ]);findings++;
        }
      }
    }
    await pool.query("UPDATE automation_rules SET last_run_at=now(),last_result=$2 WHERE id=$1",[id,`Success: ${created} evidence item(s), ${findings} finding(s)`]);
    await pool.query("UPDATE integrations SET last_sync_at=now() WHERE id=$1",[rule.integration_id]);
    await audit(req.user!,"RUN_AUTOMATION","automation_rule",id,{provider:rule.provider_key,evidenceCreated:created,findingsCreated:findings});
    res.json({message:"Automation completed",evidenceCreated:created,findingsCreated:findings});
  }catch(err:any){
    await pool.query("UPDATE automation_rules SET last_run_at=now(),last_result=$2 WHERE id=$1",[id,"Failed: "+(err?.message||"Unknown error")]).catch(()=>{});
    res.status(400).json({error:err?.message||"Automation run failed"});
  }
}));

app.get("/api/reports/control-health",auth,permit("reports.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const q=await pool.query(`SELECT c.control_code,c.title,c.category,c.risk_level,c.owner,c.next_due,
    COALESCE((SELECT a.score FROM assessments a WHERE a.control_id=c.id ORDER BY tested_at DESC LIMIT 1),0) score,
    COALESCE((SELECT a.result FROM assessments a WHERE a.control_id=c.id ORDER BY tested_at DESC LIMIT 1),'Not Tested') latest_result,
    (SELECT count(*)::int FROM evidence e WHERE e.control_id=c.id AND e.status='Current') current_evidence,
    (SELECT count(*)::int FROM findings f WHERE f.control_id=c.id AND f.status NOT IN ('Closed','Resolved')) open_findings
    FROM controls c WHERE c.organization_id=$1 ORDER BY c.category,c.control_code`,[req.user!.orgId]);
  res.json(q.rows);
}));


app.get("/api/reports/framework-coverage",auth,permit("reports.read"),asyncRoute(async(req:AuthedRequest,res)=>{
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
}));

app.get("/api/reports/evidence-freshness",auth,permit("reports.read"),asyncRoute(async(req:AuthedRequest,res)=>{
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
}));

app.get("/api/reports/assurance-summary",auth,permit("reports.read"),asyncRoute(async(req:AuthedRequest,res)=>{
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
}));

app.get("/api/reports/audit-pack.csv",auth,permit("reports.read"),asyncRoute(async(req:AuthedRequest,res)=>{
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
}));

app.get("/api/reports/audit-pack.zip",auth,permit("reports.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const o=req.user!.orgId;
  const [org,controls,tests,evidence,findings,auditRows,integrations,files]=await Promise.all([
    pool.query("SELECT name,slug,industry,country,timezone,contact_email,created_at FROM organizations WHERE id=$1",[o]),
    pool.query(`SELECT c.*,u.name assigned_user_name,
      COALESCE((SELECT a.result FROM assessments a WHERE a.control_id=c.id ORDER BY tested_at DESC LIMIT 1),'Not Tested') latest_result,
      COALESCE((SELECT a.score FROM assessments a WHERE a.control_id=c.id ORDER BY tested_at DESC LIMIT 1),0) latest_score,
      (SELECT count(*)::int FROM evidence e WHERE e.control_id=c.id) evidence_items,
      (SELECT count(*)::int FROM findings f WHERE f.control_id=c.id AND f.status NOT IN ('Closed','Resolved')) open_findings
      FROM controls c LEFT JOIN users u ON u.id=c.assigned_user_id WHERE c.organization_id=$1 ORDER BY c.category,c.control_code`,[o]),
    pool.query(`SELECT a.id,c.control_code,c.title control_title,a.period,a.result,a.score,a.test_objective,a.test_procedure,a.sample_size,a.exception_count,a.design_effective,a.operating_effective,a.notes,a.review_status,a.review_notes,a.tested_at,u.name tester_name,rv.name reviewer_name
      FROM assessments a JOIN controls c ON c.id=a.control_id LEFT JOIN users u ON u.id=a.tester_id LEFT JOIN users rv ON rv.id=a.reviewed_by
      WHERE a.organization_id=$1 ORDER BY a.tested_at DESC`,[o]),
    pool.query(`SELECT e.id,c.control_code,c.title control_title,e.title,e.evidence_type,e.source,e.period,e.status,e.automated,e.collected_at,e.expires_at,e.sha256,e.review_status,e.review_notes,uf.original_name,uf.mime_type,uf.size_bytes
      FROM evidence e JOIN controls c ON c.id=e.control_id LEFT JOIN evidence_files uf ON uf.id=e.file_id
      WHERE e.organization_id=$1 ORDER BY c.control_code,e.created_at DESC`,[o]),
    pool.query(`SELECT f.id,c.control_code,c.title control_title,f.title,f.description,f.severity,f.status,f.owner,f.due_date,f.created_at,f.updated_at,f.resolved_at
      FROM findings f LEFT JOIN controls c ON c.id=f.control_id WHERE f.organization_id=$1 ORDER BY f.created_at DESC`,[o]),
    pool.query(`SELECT a.id,a.created_at,u.name user_name,u.email,a.action,a.entity_type,a.entity_id,a.details
      FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id WHERE a.organization_id=$1 ORDER BY a.created_at DESC`,[o]),
    pool.query(`SELECT name,category,auth_type,status,tenant_ref,last_sync_at,created_at FROM integrations WHERE organization_id=$1 ORDER BY category,name`,[o]),
    pool.query(`SELECT f.id,f.original_name,f.mime_type,f.size_bytes,f.sha256,f.content,c.control_code,e.title evidence_title
      FROM evidence_files f JOIN evidence e ON e.file_id=f.id JOIN controls c ON c.id=e.control_id
      WHERE f.organization_id=$1 ORDER BY c.control_code,f.id`,[o])
  ]);
  const escCsv=(v:any)=>'"'+String(v??"").replace(/"/g,'""').replace(/\r?\n/g," ")+'"';
  const csv=(rows:any[],cols:[string,string][])=>[cols.map(x=>escCsv(x[0])).join(","),...rows.map(r=>cols.map(x=>escCsv(r[x[1]])).join(","))].join("\n");
  const controlCols:any=[["Control Code","control_code"],["Title","title"],["Category","category"],["Framework","framework_ref"],["Owner","owner"],["Assigned Officer","assigned_user_name"],["Frequency","frequency"],["Risk","risk_level"],["Status","status"],["Last Tested","last_tested"],["Next Due","next_due"],["Latest Result","latest_result"],["Latest Score","latest_score"],["Evidence Items","evidence_items"],["Open Findings","open_findings"]];
  const evidenceCols:any=[["ID","id"],["Control","control_code"],["Control Title","control_title"],["Evidence Title","title"],["Type","evidence_type"],["Source","source"],["Period","period"],["Status","status"],["Automated","automated"],["Collected","collected_at"],["Expires","expires_at"],["SHA-256","sha256"],["Review Status","review_status"],["File Name","original_name"],["MIME Type","mime_type"],["Size Bytes","size_bytes"]];
  const testCols:any=[["ID","id"],["Control","control_code"],["Control Title","control_title"],["Period","period"],["Result","result"],["Score","score"],["Objective","test_objective"],["Procedure","test_procedure"],["Sample Size","sample_size"],["Exceptions","exception_count"],["Design Effective","design_effective"],["Operating Effective","operating_effective"],["Tester","tester_name"],["Review Status","review_status"],["Reviewer","reviewer_name"],["Review Notes","review_notes"],["Tested At","tested_at"]];
  const findingCols:any=[["ID","id"],["Control","control_code"],["Control Title","control_title"],["Finding","title"],["Description","description"],["Severity","severity"],["Status","status"],["Owner","owner"],["Due Date","due_date"],["Created","created_at"],["Updated","updated_at"],["Resolved","resolved_at"]];
  const auditCols:any=[["ID","id"],["Timestamp","created_at"],["User","user_name"],["Email","email"],["Action","action"],["Entity Type","entity_type"],["Entity ID","entity_id"],["Details","details"]];
  const integrationCols:any=[["Name","name"],["Category","category"],["Auth Type","auth_type"],["Status","status"],["Account/Tenant","tenant_ref"],["Last Sync","last_sync_at"],["Created","created_at"]];
  const summary={
    generated_at:new Date().toISOString(),generated_by:req.user!.name,organisation:org.rows[0],
    totals:{controls:controls.rowCount,tests:tests.rowCount,evidence:evidence.rowCount,findings:findings.rowCount,audit_events:auditRows.rowCount,integrations:integrations.rowCount},
    open_findings:findings.rows.filter((x:any)=>!["Closed","Resolved"].includes(x.status)).length,
    high_open_findings:findings.rows.filter((x:any)=>x.severity==="High"&&!["Closed","Resolved"].includes(x.status)).length,
    effective_controls:controls.rows.filter((x:any)=>x.latest_result==="Effective").length
  };
  res.setHeader("Content-Type","application/zip");
  res.setHeader("Content-Disposition",'attachment; filename="revolt-x-it-controls-audit-pack.zip"');
  const archive=archiver("zip",{zlib:{level:9}});archive.on("error",(err:any)=>{console.error("Audit pack archive error",err);if(!res.headersSent)res.status(500).end();else res.end();});archive.pipe(res);
  archive.append(JSON.stringify(summary,null,2),{name:"00-executive-summary.json"});
  archive.append(`<!doctype html><html><head><meta charset="utf-8"><title>Revolt-X IT Controls Audit Pack</title><style>body{font-family:Arial,sans-serif;margin:36px;color:#222}h1{font-size:26px}.kpi{display:inline-block;border:1px solid #ddd;padding:14px;margin:6px;min-width:130px}table{border-collapse:collapse;width:100%;margin-top:20px}th,td{border:1px solid #ddd;padding:7px;font-size:12px;text-align:left}</style></head><body><h1>Revolt-X IT Controls Audit Pack</h1><p><b>Organisation:</b> ${String(org.rows[0]?.name||"")}</p><p><b>Generated:</b> ${new Date().toISOString()}</p><p><b>Generated by:</b> ${String(req.user!.name)}</p><div class="kpi"><b>${controls.rowCount}</b><br>Controls</div><div class="kpi"><b>${tests.rowCount}</b><br>Tests</div><div class="kpi"><b>${evidence.rowCount}</b><br>Evidence</div><div class="kpi"><b>${summary.open_findings}</b><br>Open findings</div><h2>Control summary</h2><table><tr><th>Control</th><th>Title</th><th>Owner</th><th>Frequency</th><th>Risk</th><th>Latest result</th><th>Evidence</th><th>Open findings</th></tr>${controls.rows.map((r:any)=>`<tr><td>${r.control_code}</td><td>${r.title}</td><td>${r.assigned_user_name||r.owner||""}</td><td>${r.frequency}</td><td>${r.risk_level}</td><td>${r.latest_result}</td><td>${r.evidence_items}</td><td>${r.open_findings}</td></tr>`).join("")}</table></body></html>`,{name:"01-executive-summary.html"});
  archive.append(csv(controls.rows,controlCols),{name:"02-controls.csv"});
  archive.append(csv(tests.rows,testCols),{name:"03-control-tests.csv"});
  archive.append(csv(evidence.rows,evidenceCols),{name:"04-evidence-register.csv"});
  archive.append(csv(findings.rows,findingCols),{name:"05-findings-remediation.csv"});
  archive.append(csv(auditRows.rows,auditCols),{name:"06-audit-log.csv"});
  archive.append(csv(integrations.rows,integrationCols),{name:"07-integrations.csv"});
  archive.append(JSON.stringify({generated_at:new Date().toISOString(),files:files.rows.map((x:any)=>({control_code:x.control_code,evidence_title:x.evidence_title,file_name:x.original_name,mime_type:x.mime_type,size_bytes:x.size_bytes,sha256:x.sha256}))},null,2),{name:"08-evidence-file-manifest.json"});
  let includedBytes=0;const cap=100*1024*1024;
  for(const file of files.rows){if(includedBytes+Number(file.size_bytes)>cap)continue;includedBytes+=Number(file.size_bytes);const safe=String(file.original_name).replace(/[^a-zA-Z0-9._-]/g,"_");archive.append(file.content,{name:"evidence-files/"+String(file.control_code).replace(/[^a-zA-Z0-9._-]/g,"_")+"/"+file.id+"-"+safe});}
  archive.append("This pack was generated by Revolt-X Enterprise Control Management. Verify source-file integrity using the SHA-256 values in the evidence register and manifest. Files beyond the 100 MB pack cap remain available in the Evidence Vault.",{name:"README.txt"});
  await audit(req.user!,"EXPORT","audit_pack",null,{format:"zip",controls:controls.rowCount,evidence:evidence.rowCount,filesIncludedBytes:includedBytes});
  await archive.finalize();
}));

app.get("/api/settings/organization",auth,permit("settings.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const q=await pool.query("SELECT id,name,slug,industry,country,timezone,contact_email,created_at FROM organizations WHERE id=$1",[req.user!.orgId]);
  res.json(q.rows[0]);
}));
app.put("/api/settings/organization",auth,permit("settings.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const s=z.object({name:z.string().min(2),industry:z.string().default(""),country:z.string().default(""),timezone:z.string().default("UTC"),contact_email:z.union([z.string().email(),z.literal("")]).default("")});
  const p=s.safeParse(req.body);if(!p.success)return res.status(400).json({error:"Invalid organisation settings",details:p.error.flatten()});
  const d=p.data,q=await pool.query("UPDATE organizations SET name=$2,industry=$3,country=$4,timezone=$5,contact_email=$6 WHERE id=$1 RETURNING id,name,slug,industry,country,timezone,contact_email",[req.user!.orgId,d.name,d.industry,d.country,d.timezone,d.contact_email]);
  await audit(req.user!,"UPDATE","organization",req.user!.orgId,{fields:["name","industry","country","timezone","contact_email"]});res.json(q.rows[0]);
}));
app.post('/api/auth/change-password',auth,asyncRoute(async(req:AuthedRequest,res,next)=>{
 try{const current=String(req.body.current_password||''),password=String(req.body.new_password||'');if(password.length<12||password.length>128)return res.status(400).json({error:'Use a personal password with 12–128 characters.'});
  const q=await pool.query('SELECT password_hash FROM users WHERE id=$1',[req.user!.id]);if(!q.rowCount||!await bcrypt.compare(current,q.rows[0].password_hash))return res.status(400).json({error:'Current password is incorrect'});if(await bcrypt.compare(password,q.rows[0].password_hash))return res.status(400).json({error:'Choose a different personal password.'});
  const hash=await bcrypt.hash(password,12),updated=await pool.query('UPDATE users SET password_hash=$2,must_change_password=false,temporary_password_expires=NULL,session_version=session_version+1 WHERE id=$1 RETURNING session_version',[req.user!.id,hash]);
  const user={...req.user!,mustChange:false,sessionVersion:updated.rows[0].session_version},token=jwt.sign(user,jwtSecret,{expiresIn:'8h'});setSessionCookie(res,token);await audit(user,'CHANGE_PASSWORD','user',user.id,{});res.json({success:true,user,token,permissions:permissions[user.role]||[]});
 }catch(e){next(e)}
}));
app.post('/api/auth/logout',auth,(req:AuthedRequest,res)=>{res.clearCookie('ecm_session',{path:'/'});res.json({ok:true})});
const resetLimiter=rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:'draft-8',legacyHeaders:false});
app.post('/api/auth/forgot-password',resetLimiter,asyncRoute(async(req,res,next)=>{try{const email=String(req.body.email||'').trim().toLowerCase();if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({error:'Enter a valid email address.'});const q=await pool.query("SELECT id,organization_id,name,email FROM users WHERE lower(email)=$1 AND status='active'",[email]);if(q.rowCount){const u=q.rows[0],recent=await pool.query("SELECT 1 FROM ecm_password_resets WHERE user_id=$1 AND created_at>now()-interval '2 minutes'",[u.id]);if(!recent.rowCount){const token=crypto.randomBytes(32).toString('base64url'),hash=crypto.createHash('sha256').update(token).digest('hex'),expires=new Date(Date.now()+2*60*60*1000);await pool.query('INSERT INTO ecm_password_resets(token_hash,user_id,expires_at) VALUES($1,$2,$3)',[hash,u.id,expires]);await queueNotice(pool,u.organization_id,u.email,'Reset your IT Control password','Hello '+u.name+',\n\nUse this single-use link within two hours to choose a new password:\nhttps://revolt-enterprise-control-management.onrender.com/reset-password?token='+token+'\n\nIf you did not request this, ignore this message.','password_reset','reset:'+hash,expires)}}res.json({message:'If the account exists, a password reset message has been queued.'})}catch(e){next(e)}}));
app.post('/api/auth/reset-password',resetLimiter,asyncRoute(async(req,res,next)=>{const db=await pool.connect();try{const token=String(req.body.token||''),password=String(req.body.password||'');if(token.length<32||password.length<12||password.length>128)return res.status(400).json({error:'Enter the reset token and a password of 12–128 characters.'});await db.query('BEGIN');const hash=crypto.createHash('sha256').update(token).digest('hex'),q=await db.query('SELECT * FROM ecm_password_resets WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE',[hash]);if(!q.rowCount){await db.query('ROLLBACK');return res.status(400).json({error:'The reset link expired or was already used.'})}const passwordHash=await bcrypt.hash(password,12);await db.query('UPDATE users SET password_hash=$2,must_change_password=false,temporary_password_expires=NULL,session_version=session_version+1 WHERE id=$1',[q.rows[0].user_id,passwordHash]);await db.query('UPDATE ecm_password_resets SET used_at=now() WHERE token_hash=$1',[hash]);await db.query('COMMIT');res.clearCookie('ecm_session',{path:'/'});res.json({message:'Password updated. Sign in using your new password.'})}catch(e){await db.query('ROLLBACK');next(e)}finally{db.release()}}));

app.put("/api/users/:id/status",auth,permit("users.write"),asyncRoute(async(req:AuthedRequest,res)=>{
  const id=Number(req.params.id);const s=z.object({status:z.enum(["active","disabled"])});const p=s.safeParse(req.body);
  if(!p.success)return res.status(400).json({error:"Invalid user status"});
  if(id===req.user!.id&&p.data.status==="disabled")return res.status(400).json({error:"You cannot disable your own account"});
  const q=await pool.query("UPDATE users SET status=$3 WHERE id=$1 AND organization_id=$2 RETURNING id,name,email,role,status,created_at",[id,req.user!.orgId,p.data.status]);
  if(!q.rowCount)return res.status(404).json({error:"User not found"});await audit(req.user!,"UPDATE_STATUS","user",id,{status:p.data.status});res.json(q.rows[0]);
}));

app.get("/api/audit",auth,permit("audit.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const search=String(req.query.search||""),action=String(req.query.action||""),entity=String(req.query.entity||"");
  const limit=Math.min(1000,Math.max(1,Number(req.query.limit||500)||500));
  const q=await pool.query(`SELECT a.*,u.name user_name,u.email FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id
    WHERE a.organization_id=$1
      AND ($2='' OR a.action=$2)
      AND ($3='' OR a.entity_type=$3)
      AND ($4='' OR COALESCE(u.name,'') ILIKE '%'||$4||'%' OR COALESCE(u.email,'') ILIKE '%'||$4||'%' OR a.action ILIKE '%'||$4||'%' OR a.entity_type ILIKE '%'||$4||'%' OR a.details::text ILIKE '%'||$4||'%')
    ORDER BY a.created_at DESC LIMIT $5`,[req.user!.orgId,action,entity,search,limit]);
  res.json(q.rows);
}));

app.get("/api/users",auth,permit("users.read"),asyncRoute(async(req:AuthedRequest,res)=>{
  const q=await pool.query("SELECT id,name,email,role,status,created_at FROM users WHERE organization_id=$1 ORDER BY name",[req.user!.orgId]); res.json(q.rows);
}));

registerCommercial(app,{pool,auth,permit,audit});

const publicDir=path.join(process.cwd(),"public");
app.use(express.static(publicDir));
app.get('*',(_req,res)=>res.sendFile(path.join(publicDir,'index.html')));
app.use((error:any,_req:Request,res:Response,_next:NextFunction)=>{const status=error.status|| (error.code==='23505'?409:500);res.status(status).json({error:status===500?'The operation could not complete. Please retry.':error.code==='23505'?'A record with these details already exists.':error.message});console.error('Request failure',status,error.code||error.name)});

export {app,pool,initDb};
async function start(){await initDb();const server=app.listen(port,()=>console.log('Revolt-X IT Control Management running on port '+port));
 const cycle=async()=>{try{await pool.query('SELECT ecm_prepare_notifications()');await dispatchSmtp(pool)}catch(e){console.error('Notification check failed',e instanceof Error?e.name:'Error')}};
 const timer=setInterval(cycle,60000);timer.unref();process.on('SIGTERM',()=>{clearInterval(timer);server.close(()=>{pool.end().finally(()=>process.exit(0))})});
}
if(process.env.ECM_TEST_MODE!=='1')start().catch(e=>{console.error('Startup failed',e instanceof Error?e.message:'Error');process.exit(1)});
