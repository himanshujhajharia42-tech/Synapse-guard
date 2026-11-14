const express = require("express");
const helmet = require("helmet");
const crypto = require("crypto");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost") ? { rejectUnauthorized: false } : false });
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(__dirname));

const hashKey = value => crypto.createHash("sha256").update(value).digest("hex");
const newKey = () => "sg_live_" + crypto.randomBytes(32).toString("base64url");
const clean = value => String(value || "").trim();
let schemaReady;
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS projects (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      key_hash TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      access_count BIGINT NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS allowlist (
      id BIGSERIAL PRIMARY KEY, project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      subject TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(project_id, subject)
    );
    CREATE TABLE IF NOT EXISTS license_keys (
      id BIGSERIAL PRIMARY KEY, project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      license_key TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(project_id, license_key)
    );
    CREATE TABLE IF NOT EXISTS blacklist (
      id BIGSERIAL PRIMARY KEY, project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      subject TEXT NOT NULL, reason TEXT DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(project_id, subject)
    );
    CREATE TABLE IF NOT EXISTS events (
      id BIGSERIAL PRIMARY KEY, project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}
function ready(req,res,next) {
  if (!schemaReady) schemaReady = initDb();
  schemaReady.then(()=>next()).catch(err=>{ console.error("DB init:",err.message); res.status(503).json({error:"Database is starting. Try again shortly."}); });
}
const attempts = new Map();
async function authenticate(req,res,next) {
  const raw = clean(req.headers.authorization).replace(/^Bearer\s+/i,"");
  if (!raw || raw.length > 160) return res.status(401).json({error:"Enter a valid project API key."});
  const ip = req.ip || "unknown";
  const now = Date.now();
  const record = attempts.get(ip);
  if (record && record.until > now && record.count >= 30) return res.status(429).json({error:"Too many attempts. Try again later."});
  try {
    const result = await pool.query("SELECT id,name,created_at,access_count FROM projects WHERE key_hash=$1", [hashKey(raw)]);
    if (!result.rowCount) {
      const r = attempts.get(ip) || {count:0,until:now+60000};
      if (r.until < now) { r.count=0; r.until=now+60000; }
      r.count++; attempts.set(ip,r);
      return res.status(401).json({error:"That API key is not valid."});
    }
    attempts.delete(ip);
    req.project = result.rows[0];
    await pool.query("UPDATE projects SET access_count=access_count+1 WHERE id=$1",[req.project.id]);
    await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'dashboard_access')",[req.project.id]);
    next();
  } catch(e) { console.error(e); res.status(500).json({error:"Could not verify project key."}); }
}
app.get("/api/health",async(req,res)=>{try{await pool.query("SELECT 1");res.json({ok:true,database:"connected",service:"Synapse Guard"});}catch(e){console.error("Health check:",e.message);res.status(503).json({ok:false,database:"unavailable",service:"Synapse Guard"});}});
app.post("/api/projects", ready, async (req,res)=>{
  const name = clean(req.body.name);
  if (name.length < 2 || name.length > 60) return res.status(400).json({error:"Project name must be 2–60 characters."});
  const key = newKey();
  try {
    const result = await pool.query("INSERT INTO projects(name,key_hash) VALUES($1,$2) RETURNING id,name,created_at",[name,hashKey(key)]);
    await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'project_created')",[result.rows[0].id]);
    res.status(201).json({project:result.rows[0],apiKey:key,message:"Copy this key now. It will not be shown again."});
  } catch(e) { console.error(e); res.status(500).json({error:"Could not create project."}); }
});
app.post("/api/auth", ready, authenticate, (req,res)=>res.json({project:req.project}));
app.get("/api/dashboard", ready, authenticate, async (req,res)=>{
  try {
    const id=req.project.id;
    const [allow,keys,blocked,events]=await Promise.all([
      pool.query("SELECT id,subject,created_at FROM allowlist WHERE project_id=$1 ORDER BY created_at DESC LIMIT 100",[id]),
      pool.query("SELECT id,license_key,status,created_at FROM license_keys WHERE project_id=$1 ORDER BY created_at DESC LIMIT 100",[id]),
      pool.query("SELECT id,subject,reason,created_at FROM blacklist WHERE project_id=$1 ORDER BY created_at DESC LIMIT 100",[id]),
      pool.query("SELECT event_type,COUNT(*)::int AS total FROM events WHERE project_id=$1 GROUP BY event_type",[id])
    ]);
    const analytics={}; events.rows.forEach(row=>analytics[row.event_type]=row.total);
    res.json({project:req.project,whitelist:allow.rows,keys:keys.rows,blacklist:blocked.rows,analytics});
  } catch(e) { console.error(e); res.status(500).json({error:"Could not load project data."}); }
});
app.post("/api/whitelist", ready, authenticate, async(req,res)=>{
  const subject=clean(req.body.subject); if(!subject || subject.length>160) return res.status(400).json({error:"Enter a valid user identifier."});
  try { const r=await pool.query("INSERT INTO allowlist(project_id,subject) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING *",[req.project.id,subject]); await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'whitelist_added')",[req.project.id]); res.status(201).json({item:r.rows[0]||null}); } catch(e){res.status(500).json({error:"Could not add whitelist entry."});}
});
app.delete("/api/whitelist/:id", ready, authenticate, async(req,res)=>{await pool.query("DELETE FROM allowlist WHERE id=$1 AND project_id=$2",[req.params.id,req.project.id]);res.json({ok:true});});
app.post("/api/keys", ready, authenticate, async(req,res)=>{
  const licenseKey="LIC-"+crypto.randomBytes(12).toString("hex").toUpperCase();
  try {const r=await pool.query("INSERT INTO license_keys(project_id,license_key) VALUES($1,$2) RETURNING *",[req.project.id,licenseKey]);await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'license_created')",[req.project.id]);res.status(201).json({item:r.rows[0]});}catch(e){res.status(500).json({error:"Could not create license key."});}
});
app.patch("/api/keys/:id", ready, authenticate, async(req,res)=>{const status=req.body.status==="revoked"?"revoked":"active";await pool.query("UPDATE license_keys SET status=$1 WHERE id=$2 AND project_id=$3",[status,req.params.id,req.project.id]);res.json({ok:true});});
app.post("/api/blacklist", ready, authenticate, async(req,res)=>{
  const subject=clean(req.body.subject),reason=clean(req.body.reason).slice(0,240);if(!subject||subject.length>160)return res.status(400).json({error:"Enter a valid user identifier."});
  try{const r=await pool.query("INSERT INTO blacklist(project_id,subject,reason) VALUES($1,$2,$3) ON CONFLICT(project_id,subject) DO UPDATE SET reason=EXCLUDED.reason RETURNING *",[req.project.id,subject,reason]);await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'blacklist_added')",[req.project.id]);res.status(201).json({item:r.rows[0]});}catch(e){res.status(500).json({error:"Could not add blacklist entry."});}
});
app.delete("/api/blacklist/:id", ready, authenticate, async(req,res)=>{await pool.query("DELETE FROM blacklist WHERE id=$1 AND project_id=$2",[req.params.id,req.project.id]);res.json({ok:true});});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"index.html")));
app.listen(port,()=>console.log("Synapse Guard listening on",port));
