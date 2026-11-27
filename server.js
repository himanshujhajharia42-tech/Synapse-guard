const express = require("express");
const helmet = require("helmet");
const crypto = require("crypto");
const { Pool } = require("pg");
const path = require("path");
const fs = require("fs/promises");
const os = require("os");
const { spawn } = require("child_process");

const app = express();
const port = process.env.PORT || 3000;
const APP_URL = (process.env.APP_URL || "https://synapse-guard-app.onrender.com").replace(/\/$/, "");
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false } : false
});
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "12mb" }));
// Keep OAuth state and session cookies on one canonical host. Vercel aliases
// are different cookie domains, so normalize requests before any auth route.
app.use((req, res, next) => {
  if (process.env.VERCEL === "1") {
    try {
      const canonical = new URL(APP_URL);
      if (req.headers.host && req.headers.host.toLowerCase() !== canonical.host.toLowerCase()) {
        return res.redirect(308, APP_URL + req.originalUrl);
      }
    } catch (error) {
      console.error("Invalid APP_URL configuration.");
      return res.status(500).send("Application URL is not configured correctly.");
    }
  }
  next();
});

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
      access_count BIGINT NOT NULL DEFAULT 0,
      owner_discord_id TEXT,
      owner_email TEXT,
      access_mode TEXT NOT NULL DEFAULT 'key',
      hwid_lock BOOLEAN NOT NULL DEFAULT TRUE,
      runtime_type TEXT NOT NULL DEFAULT 'standalone_lua' CHECK (runtime_type IN ('roblox_studio','standalone_lua'))
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
    CREATE TABLE IF NOT EXISTS scripts (
      id BIGSERIAL PRIMARY KEY, project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      title TEXT NOT NULL, content TEXT NOT NULL DEFAULT '', version INTEGER NOT NULL DEFAULT 1,
      protection_engine TEXT NOT NULL DEFAULT 'prometheus',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS discord_integrations (
      project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
      owner_user_id TEXT NOT NULL, guild_id TEXT, connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS discord_connect_codes (
      project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
      code_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS script_builds (
      id BIGSERIAL PRIMARY KEY,
      script_id BIGINT NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
      source_version INTEGER NOT NULL,
      preset TEXT NOT NULL DEFAULT 'Medium',
      status TEXT NOT NULL CHECK (status IN ('success','failed')),
      output_content TEXT NOT NULL DEFAULT '',
      error_message TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS owner_discord_id TEXT;
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS owner_email TEXT;
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS access_mode TEXT NOT NULL DEFAULT 'key';
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS hwid_lock BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE projects ADD COLUMN IF NOT EXISTS runtime_type TEXT NOT NULL DEFAULT 'standalone_lua';
    ALTER TABLE scripts ADD COLUMN IF NOT EXISTS protection_engine TEXT NOT NULL DEFAULT 'prometheus';
    UPDATE scripts SET protection_engine='prometheus' WHERE protection_engine <> 'prometheus';
    CREATE TABLE IF NOT EXISTS script_versions (
      id BIGSERIAL PRIMARY KEY,
      script_id BIGINT NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
      version INTEGER NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(script_id, version)
    );
    INSERT INTO script_versions(script_id,version,title,content,created_at)
    SELECT id,version,title,content,updated_at FROM scripts
    ON CONFLICT(script_id,version) DO NOTHING;
    CREATE TABLE IF NOT EXISTS discord_accounts (
      discord_id TEXT PRIMARY KEY, email TEXT NOT NULL, username TEXT NOT NULL,
      global_name TEXT, avatar TEXT, banner TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS duration TEXT NOT NULL DEFAULT 'lifetime';
    ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
    ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS hwid_hash TEXT;
    ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS hwid_reset_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS hwid_reset_limit INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS bound_at TIMESTAMPTZ;
    ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS last_validated_at TIMESTAMPTZ;
  `);
}

function ready(req, res, next) {
  if (!schemaReady) schemaReady = initDb();
  schemaReady.then(() => next()).catch(err => {
    console.error("DB init:", err.message);
    res.status(503).json({ error: "Database is starting. Try again shortly." });
  });
}

const attempts = new Map();
async function authenticate(req, res, next) {
  const raw = clean(req.headers.authorization).replace(/^Bearer\s+/i, "");
  if (!raw) {
    const session=readSession(req);
    if(!session) return res.status(401).json({error:"Sign in with Discord or your project API key."});
    try {
      const owned=await pool.query("SELECT id,name,created_at,access_count,access_mode,hwid_lock,runtime_type FROM projects WHERE id=$1 AND owner_discord_id=$2",[session.projectId,session.discordId]);
      if(!owned.rowCount) return res.status(401).json({error:"This Discord account has no linked workspace. Please sign in again."});
      req.project=owned.rows[0]; return next();
    } catch(e) { console.error(e); return res.status(500).json({error:"Could not verify Discord session."}); }
  }
  if (raw.length > 160) return res.status(401).json({ error: "Enter a valid project API key." });
  const ip = req.ip || "unknown";
  const now = Date.now();
  const record = attempts.get(ip);
  if (record && record.until > now && record.count >= 30) return res.status(429).json({ error: "Too many attempts. Try again later." });
  try {
    const result = await pool.query("SELECT id,name,created_at,access_count,access_mode,hwid_lock,runtime_type FROM projects WHERE key_hash=$1", [hashKey(raw)]);
    if (!result.rowCount) {
      const r = attempts.get(ip) || { count: 0, until: now + 60000 };
      if (r.until < now) { r.count = 0; r.until = now + 60000; }
      r.count++; attempts.set(ip, r);
      return res.status(401).json({ error: "That API key is not valid." });
    }
    attempts.delete(ip); req.project = result.rows[0];
    await pool.query("UPDATE projects SET access_count=access_count+1 WHERE id=$1", [req.project.id]);
    await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'dashboard_access')", [req.project.id]);
    next();
  } catch (e) { console.error(e); res.status(500).json({ error: "Could not verify project key." }); }
}


function signSession(payload) {
  const body=Buffer.from(JSON.stringify(payload)).toString("base64url");
  const secret=process.env.SESSION_SECRET||process.env.DISCORD_CLIENT_SECRET||"";
  if(!secret) throw new Error("SESSION_SECRET is not configured.");
  return body+"."+crypto.createHmac("sha256",secret).update(body).digest("base64url");
}
function readSession(req) {
  const item=clean(req.headers.cookie).split(";").map(x=>x.trim()).find(x=>x.startsWith("sg_session="));
  if(!item) return null;
  const parts=item.slice(11).split("."),secret=process.env.SESSION_SECRET||process.env.DISCORD_CLIENT_SECRET||"";
  if(parts.length!==2||!secret) return null;
  const expected=crypto.createHmac("sha256",secret).update(parts[0]).digest(), supplied=Buffer.from(parts[1],"base64url");
  if(expected.length!==supplied.length||!crypto.timingSafeEqual(expected,supplied)) return null;
  try{const data=JSON.parse(Buffer.from(parts[0],"base64url").toString("utf8"));return data.exp>Date.now()/1000?data:null;}catch{return null;}
}
app.get("/auth/discord",(req,res)=>{
  const clientId=clean(process.env.DISCORD_CLIENT_ID),secret=clean(process.env.DISCORD_CLIENT_SECRET);
  if(!clientId||!secret)return res.status(503).send("Discord login is not configured. Add the Discord OAuth client ID and secret in Render.");
  const state=crypto.randomBytes(24).toString("base64url");
  res.cookie("sg_oauth_state",state,{httpOnly:true,secure:true,sameSite:"lax",path:"/",maxAge:600000});
  const url=new URL("https://discord.com/oauth2/authorize");
  url.searchParams.set("client_id",clientId);url.searchParams.set("response_type","code");
  url.searchParams.set("redirect_uri",APP_URL+"/auth/discord/callback");url.searchParams.set("scope","identify email");url.searchParams.set("state",state);
  res.redirect(url.toString());
});
app.get("/auth/discord/callback",async(req,res)=>{
  const state=clean(req.query.state),code=clean(req.query.code);
  const stateCookie=clean(req.headers.cookie).split(";").map(x=>x.trim()).find(x=>x.startsWith("sg_oauth_state="));
  const savedState=stateCookie?decodeURIComponent(stateCookie.slice("sg_oauth_state=".length)):"";
  res.clearCookie("sg_oauth_state",{httpOnly:true,secure:true,sameSite:"lax",path:"/"});
  if(!state||!savedState||state!==savedState||!code)return res.status(400).send("Discord sign-in could not be verified. Please return to Synapse Guard and try again.");
  try{
    if (!schemaReady) schemaReady = initDb();
    await schemaReady;
    const clientId=clean(process.env.DISCORD_CLIENT_ID),clientSecret=clean(process.env.DISCORD_CLIENT_SECRET);
    const tokenResponse=await fetch("https://discord.com/api/oauth2/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({client_id:clientId,client_secret:clientSecret,grant_type:"authorization_code",code,redirect_uri:APP_URL+"/auth/discord/callback"})});
    const tokenData=await tokenResponse.json();if(!tokenResponse.ok||!tokenData.access_token)throw new Error("Discord token exchange failed.");
    const profileResponse=await fetch("https://discord.com/api/users/@me",{headers:{Authorization:"Bearer "+tokenData.access_token}});
    const profile=await profileResponse.json();
    if(!profileResponse.ok||!profile.id||!profile.email||profile.verified!==true)throw new Error("A verified Discord email is required. Allow email access and verify your Discord email.");
    await pool.query("INSERT INTO discord_accounts(discord_id,email,username,global_name,avatar,banner,updated_at) VALUES($1,$2,$3,$4,$5,$6,NOW()) ON CONFLICT(discord_id) DO UPDATE SET email=EXCLUDED.email,username=EXCLUDED.username,global_name=EXCLUDED.global_name,avatar=EXCLUDED.avatar,banner=EXCLUDED.banner,updated_at=NOW()",[profile.id,profile.email,profile.username,profile.global_name||null,profile.avatar||null,profile.banner||null]);
    let project=await pool.query("SELECT id,name FROM projects WHERE owner_discord_id=$1 ORDER BY created_at ASC LIMIT 1",[profile.id]);
    if(!project.rowCount){
      const key=newKey(),name=((profile.global_name||profile.username)+"'s Workspace").slice(0,60);
      project=await pool.query("INSERT INTO projects(name,key_hash,owner_discord_id,owner_email) VALUES($1,$2,$3,$4) RETURNING id,name",[name,hashKey(key),profile.id,profile.email]);
      await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'project_created'),($1,'discord_login')",[project.rows[0].id]);
    }else{
      await pool.query("UPDATE projects SET owner_email=$1 WHERE id=$2",[profile.email,project.rows[0].id]);
      await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'discord_login')",[project.rows[0].id]);
    }
    const session=signSession({discordId:profile.id,projectId:project.rows[0].id,exp:Math.floor(Date.now()/1000)+604800});
    res.cookie("sg_session",session,{httpOnly:true,secure:true,sameSite:"lax",path:"/",maxAge:604800000});
    res.setHeader("Cache-Control","no-store");
    res.redirect(303,APP_URL+"/?login=discord");
  }catch(e){console.error("Discord OAuth callback failed:",e.stack||e.message);res.status(500).send("Discord sign-in could not be completed. Return to Synapse Guard and try again.");}
});
app.post("/auth/logout",(req,res)=>{res.clearCookie("sg_session",{httpOnly:true,secure:true,sameSite:"lax",path:"/"});res.json({ok:true});});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected", service: "Synapse Guard" });
  } catch (e) {
    console.error("Health check:", e.message);
    res.status(503).json({ ok: false, database: "unavailable", service: "Synapse Guard" });
  }
});

app.post("/api/projects", ready, async (req, res) => {
  const session=readSession(req);
  if(!session)return res.status(401).json({error:"Sign in with Discord to create and manage multiple projects."});
  const name=clean(req.body.name), accessMode=req.body.accessMode==="public"?"public":"key", hwidLock=accessMode==="key"&&req.body.hwidLock!==false;
  const runtimeType=req.body.runtimeType==="roblox_studio"?"roblox_studio":"standalone_lua";
  const scripts=Array.isArray(req.body.scripts)?req.body.scripts:[];
  if(name.length<2||name.length>60)return res.status(400).json({error:"Project name must be 2–60 characters."});
  if(scripts.length>3)return res.status(400).json({error:"Free plan allows up to 3 scripts per project."});
  for(const item of scripts){if(!clean(item.title)||clean(item.title).length>80||String(item.content||"").length>500000)return res.status(400).json({error:"Each script needs a name and must be under 500 KB."});}
  const key=newKey(),client=await pool.connect();
  try{
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))",[session.discordId]);
    const ownedCount=await client.query("SELECT COUNT(*)::int AS total FROM projects WHERE owner_discord_id=$1",[session.discordId]);
    if(ownedCount.rows[0].total>=3){await client.query("ROLLBACK");return res.status(403).json({error:"Free plan limit reached: you can create up to 3 projects."});}
    const result=await client.query("INSERT INTO projects(name,key_hash,owner_discord_id,owner_email,access_mode,hwid_lock,runtime_type) VALUES($1,$2,$3,(SELECT email FROM discord_accounts WHERE discord_id=$3),$4,$5,$6) RETURNING id,name,created_at,access_mode,hwid_lock,runtime_type",[name,hashKey(key),session.discordId,accessMode,hwidLock,runtimeType]);
    const project=result.rows[0];
    for(const item of scripts)await client.query("INSERT INTO scripts(project_id,title,content) VALUES($1,$2,$3)",[project.id,clean(item.title),String(item.content||"")]);
    await client.query("INSERT INTO events(project_id,event_type) VALUES($1,'project_created')",[project.id]);
    await client.query("COMMIT");
    const cookie=signSession({discordId:session.discordId,projectId:project.id,exp:Math.floor(Date.now()/1000)+604800});
    res.cookie("sg_session",cookie,{httpOnly:true,secure:true,sameSite:"lax",path:"/",maxAge:604800000});
    res.status(201).json({project,apiKey:key,message:"Project created. Copy this API key now; it will not be shown again."});
  }catch(e){await client.query("ROLLBACK");console.error(e);res.status(500).json({error:"Could not create project."});}
  finally{client.release();}
});

app.get("/api/projects/mine", ready, async (req,res) => {
  const session=readSession(req);
  if(!session)return res.status(401).json({error:"Discord sign-in is required."});
  const r=await pool.query("SELECT id,name,created_at,access_mode,hwid_lock,runtime_type FROM projects WHERE owner_discord_id=$1 ORDER BY created_at DESC",[session.discordId]);
  res.json({projects:r.rows});
});
app.post("/api/projects/:id/select", ready, async (req,res) => {
  const session=readSession(req);
  if(!session)return res.status(401).json({error:"Discord sign-in is required."});
  const r=await pool.query("SELECT id,name FROM projects WHERE id=$1 AND owner_discord_id=$2",[req.params.id,session.discordId]);
  if(!r.rowCount)return res.status(404).json({error:"Project not found."});
  const cookie=signSession({discordId:session.discordId,projectId:r.rows[0].id,exp:Math.floor(Date.now()/1000)+604800});
  res.cookie("sg_session",cookie,{httpOnly:true,secure:true,sameSite:"lax",path:"/",maxAge:604800000});
  res.json({project:r.rows[0]});
});
app.post("/api/auth", ready, authenticate, (req, res) => res.json({ project: req.project }));
app.get("/api/me", ready, authenticate, async (req,res) => {
  const session=readSession(req);
  if(!session)return res.json({project:req.project,account:null});
  const r=await pool.query("SELECT discord_id,email,username,global_name,avatar,banner FROM discord_accounts WHERE discord_id=$1",[session.discordId]);
  res.json({project:req.project,account:r.rows[0]||null});
});

app.get("/api/discord/guild-status", ready, authenticate, async (req,res) => {
  const guildId=clean(req.query.guildId);
  if(!/^\d{17,20}$/.test(guildId))return res.status(400).json({error:"Enter a valid Discord server ID."});
  const botToken=clean(process.env.DISCORD_BOT_TOKEN),clientId=clean(process.env.DISCORD_CLIENT_ID);
  if(!botToken||!clientId)return res.status(503).json({error:"Discord bot is not configured yet. Add DISCORD_BOT_TOKEN and DISCORD_CLIENT_ID to the Render environment."});
  const inviteUrl="https://discord.com/oauth2/authorize?"+new URLSearchParams({client_id:clientId,scope:"bot applications.commands",permissions:"0",guild_id:guildId,disable_guild_select:"true"}).toString();
  try{
    const response=await fetch("https://discord.com/api/v10/guilds/"+encodeURIComponent(guildId),{headers:{Authorization:"Bot "+botToken}});
    if(response.ok){const guild=await response.json();return res.json({inGuild:true,guild:{id:guild.id,name:guild.name}})}
    const detail=await response.json().catch(()=>({}));
    if(response.status===404||response.status===403||detail.code===10004||detail.code===50001)return res.json({inGuild:false,inviteUrl});
    console.error("Discord guild check:",response.status,detail);
    return res.status(502).json({error:"Discord could not confirm the bot's membership. Please try again."});
  }catch(e){console.error("Discord guild check:",e.message);return res.status(502).json({error:"Could not contact Discord. Please try again."})}
});

app.get("/api/dashboard", ready, authenticate, async (req, res) => {
  try {
    const id = req.project.id;
    await pool.query("UPDATE license_keys SET status='expired' WHERE project_id=$1 AND status='active' AND expires_at IS NOT NULL AND expires_at<=NOW()", [id]);
    const [allow, keys, blocked, events, scripts, executionTotal, executionDaily] = await Promise.all([
      pool.query("SELECT id,subject,created_at FROM allowlist WHERE project_id=$1 ORDER BY created_at DESC LIMIT 200", [id]),
      pool.query("SELECT id,license_key,status,duration,expires_at,(hwid_hash IS NOT NULL) AS hwid_bound,hwid_reset_count,hwid_reset_limit,bound_at,created_at FROM license_keys WHERE project_id=$1 ORDER BY created_at DESC LIMIT 200", [id]),
      pool.query("SELECT id,subject,reason,created_at FROM blacklist WHERE project_id=$1 ORDER BY created_at DESC LIMIT 200", [id]),
      pool.query("SELECT event_type,COUNT(*)::int AS total FROM events WHERE project_id=$1 GROUP BY event_type", [id]),
      pool.query("SELECT id,title,content,version,protection_engine,created_at,updated_at FROM scripts WHERE project_id=$1 ORDER BY updated_at DESC LIMIT 100", [id]),
      pool.query("SELECT COUNT(*)::int AS total FROM events WHERE project_id=$1 AND event_type='license_validated'", [id]),
      pool.query("SELECT to_char(days.day,'YYYY-MM-DD') AS day,COUNT(e.id)::int AS total FROM generate_series(CURRENT_DATE - INTERVAL '6 days',CURRENT_DATE,INTERVAL '1 day') AS days(day) LEFT JOIN events e ON e.project_id=$1 AND e.event_type='license_validated' AND e.created_at>=days.day AND e.created_at<days.day+INTERVAL '1 day' GROUP BY days.day ORDER BY days.day", [id])
    ]);
    const analytics = {};
    events.rows.forEach(row => analytics[row.event_type] = row.total);
    res.json({ project: req.project, whitelist: allow.rows, keys: keys.rows, blacklist: blocked.rows, analytics, scripts: scripts.rows, scriptExecutionTotal: executionTotal.rows[0].total, executionDaily: executionDaily.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not load project data." });
  }
});

app.patch("/api/project", ready, authenticate, async (req, res) => {
  const name=clean(req.body.name);
  if(name.length<2||name.length>60)return res.status(400).json({error:"Project name must be 2–60 characters."});
  const accessMode=req.body.accessMode==="public"?"public":"key";
  const hwidLock=accessMode==="key"&&req.body.hwidLock!==false;
  try{
    const result=await pool.query("UPDATE projects SET name=$1,access_mode=$2,hwid_lock=$3 WHERE id=$4 RETURNING id,name,created_at,access_count,access_mode,hwid_lock",[name,accessMode,hwidLock,req.project.id]);
    await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'project_settings_updated')",[req.project.id]);
    res.json({project:result.rows[0]});
  }catch(e){res.status(500).json({error:"Could not update project settings."});}
});

app.post("/api/project/rotate-key", ready, authenticate, async (req, res) => {
  const key = newKey();
  try {
    await pool.query("UPDATE projects SET key_hash=$1 WHERE id=$2", [hashKey(key), req.project.id]);
    await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'project_key_rotated')", [req.project.id]);
    res.json({ apiKey: key, message: "The previous key is now invalid. Save this new key securely." });
  } catch (e) { res.status(500).json({ error: "Could not rotate project key." }); }
});

app.post("/api/whitelist", ready, authenticate, async (req, res) => {
  const subject = clean(req.body.subject);
  if (!subject || subject.length > 160) return res.status(400).json({ error: "Enter a valid user identifier." });
  try {
    const r = await pool.query(
      "INSERT INTO allowlist(project_id,subject) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING *",
      [req.project.id, subject]
    );
    if (r.rowCount) await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'whitelist_added')", [req.project.id]);
    res.status(201).json({ item: r.rows[0] || null });
  } catch (e) { res.status(500).json({ error: "Could not add whitelist entry." }); }
});

app.delete("/api/whitelist/:id", ready, authenticate, async (req, res) => {
  await pool.query("DELETE FROM allowlist WHERE id=$1 AND project_id=$2", [req.params.id, req.project.id]);
  res.json({ ok: true });
});

const LICENSE_DAYS = { weekly: 7, monthly: 30, yearly: 365, lifetime: null };

app.post("/api/keys", ready, authenticate, async (req, res) => {
  const duration = clean(req.body.duration || "monthly").toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(LICENSE_DAYS, duration)) {
    return res.status(400).json({ error: "Choose weekly, monthly, yearly or lifetime." });
  }
  const resetLimit = req.body.hwid_reset_limit === undefined ? 1 : Number(req.body.hwid_reset_limit);
  if (!Number.isInteger(resetLimit) || resetLimit < 0 || resetLimit > 10) return res.status(400).json({ error: "HWID reset limit must be between 0 and 10." });
  const licenseKey = "LIC-" + crypto.randomBytes(12).toString("hex").toUpperCase();
  try {
    const r = await pool.query(
      `INSERT INTO license_keys(project_id,license_key,duration,expires_at,hwid_reset_limit)
       VALUES($1,$2,$3,CASE WHEN $4::int IS NULL THEN NULL ELSE NOW()+($4::int * INTERVAL '1 day') END,$5)
       RETURNING id,license_key,status,duration,expires_at,hwid_reset_count,hwid_reset_limit,created_at`,
      [req.project.id, licenseKey, duration, LICENSE_DAYS[duration], resetLimit]
    );
    await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'license_created')", [req.project.id]);
    res.status(201).json({ item: r.rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: "Could not create license key." }); }
});

app.patch("/api/keys/:id", ready, authenticate, async (req, res) => {
  const status = req.body.status === "revoked" ? "revoked" : req.body.status === "active" ? "active" : null;
  const resetLimit = req.body.hwid_reset_limit;
  if (status === null && resetLimit === undefined) return res.status(400).json({ error: "No valid license change supplied." });
  if (resetLimit !== undefined && (!Number.isInteger(resetLimit) || resetLimit < 0 || resetLimit > 10)) {
    return res.status(400).json({ error: "HWID reset limit must be between 0 and 10." });
  }
  try {
    const r = await pool.query(
      `UPDATE license_keys SET
       status=COALESCE($1,status),
       hwid_reset_limit=COALESCE($2,hwid_reset_limit)
       WHERE id=$3 AND project_id=$4 RETURNING id,status,hwid_reset_limit`,
      [status, resetLimit === undefined ? null : resetLimit, req.params.id, req.project.id]
    );
    if (!r.rowCount) return res.status(404).json({ error: "License not found." });
    await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'license_updated')", [req.project.id]);
    res.json({ item: r.rows[0] });
  } catch (e) { res.status(500).json({ error: "Could not update license." }); }
});

app.post("/api/keys/:id/reset-hwid", ready, authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const found = await client.query(
      "SELECT id,hwid_reset_count,hwid_reset_limit FROM license_keys WHERE id=$1 AND project_id=$2 FOR UPDATE",
      [req.params.id, req.project.id]
    );
    if (!found.rowCount) { await client.query("ROLLBACK"); return res.status(404).json({ error: "License not found." }); }
    const license = found.rows[0];
    if (license.hwid_reset_count >= license.hwid_reset_limit) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "This license has used all allowed HWID resets. Increase its reset limit first." });
    }
    await client.query(
      "UPDATE license_keys SET hwid_hash=NULL,bound_at=NULL,hwid_reset_count=hwid_reset_count+1 WHERE id=$1",
      [license.id]
    );
    await client.query("INSERT INTO events(project_id,event_type) VALUES($1,'license_hwid_reset')", [req.project.id]);
    await client.query("COMMIT");
    res.json({ ok: true, resetsUsed: license.hwid_reset_count + 1, resetsAllowed: license.hwid_reset_limit });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e);
    res.status(500).json({ error: "Could not reset this license HWID." });
  } finally { client.release(); }
});

app.post("/api/keys/:id/extend", ready, authenticate, async (req, res) => {
  const duration = clean(req.body.duration || "").toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(LICENSE_DAYS, duration)) return res.status(400).json({ error: "Choose a valid extension duration." });
  try {
    const days = LICENSE_DAYS[duration];
    const r = await pool.query(
      `UPDATE license_keys SET
       duration=$1,
       expires_at=CASE WHEN $1='lifetime' THEN NULL
         ELSE GREATEST(COALESCE(expires_at,NOW()),NOW()) + ($2::int * INTERVAL '1 day') END,
       status='active'
       WHERE id=$3 AND project_id=$4
       RETURNING id,status,duration,expires_at`,
      [duration, days || 0, req.params.id, req.project.id]
    );
    if (!r.rowCount) return res.status(404).json({ error: "License not found." });
    await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'license_extended')", [req.project.id]);
    res.json({ item: r.rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: "Could not extend license." }); }
});

// Public runtime check: project ID is public; license key and client HWID are validated server-side.
// The HWID is hashed before storage and is not returned by the dashboard or this endpoint.
app.post("/api/license/validate", ready, async (req, res) => {
  const projectId = clean(req.body.projectId);
  const licenseKey = clean(req.body.licenseKey).toUpperCase();
  const hwid = clean(req.body.hwid);
  if (!/^[0-9a-f-]{36}$/i.test(projectId)) return res.status(400).json({valid:false,reason:"invalid_request"});
  const projectMode=await pool.query("SELECT access_mode,hwid_lock FROM projects WHERE id=$1",[projectId]);
  if(!projectMode.rowCount)return res.status(404).json({valid:false,reason:"project_not_found"});
  if(projectMode.rows[0].access_mode==="public")return res.json({valid:true,access:"public",hwidBound:false});
  if (licenseKey.length < 12 || licenseKey.length > 100 || (projectMode.rows[0].hwid_lock && (hwid.length < 8 || hwid.length > 200))) {
    return res.status(400).json({ valid: false, reason: "invalid_request" });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const found = await client.query(
      "SELECT id,status,duration,expires_at,hwid_hash FROM license_keys WHERE project_id=$1 AND license_key=$2 FOR UPDATE",
      [projectId, licenseKey]
    );
    if (!found.rowCount) { await client.query("ROLLBACK"); return res.status(404).json({ valid: false, reason: "license_not_found" }); }
    const license = found.rows[0];
    if (license.status !== "active") { await client.query("ROLLBACK"); return res.status(403).json({ valid: false, reason: "license_revoked" }); }
    if (license.expires_at && new Date(license.expires_at).getTime() <= Date.now()) {
      await client.query("UPDATE license_keys SET status='expired' WHERE id=$1", [license.id]);
      await client.query("INSERT INTO events(project_id,event_type) VALUES($1,'license_expired')", [projectId]);
      await client.query("COMMIT");
      return res.status(403).json({ valid: false, reason: "license_expired" });
    }
    const fingerprint = projectMode.rows[0].hwid_lock ? hashKey(hwid) : null;
    if (projectMode.rows[0].hwid_lock && license.hwid_hash && license.hwid_hash !== fingerprint) {
      await client.query("ROLLBACK");
      return res.status(403).json({ valid: false, reason: "hwid_mismatch" });
    }
    if (projectMode.rows[0].hwid_lock && !license.hwid_hash) {
      await client.query("UPDATE license_keys SET hwid_hash=$1,bound_at=NOW(),last_validated_at=NOW() WHERE id=$2", [fingerprint, license.id]);
    } else {
      await client.query("UPDATE license_keys SET last_validated_at=NOW() WHERE id=$1", [license.id]);
    }
    await client.query("INSERT INTO events(project_id,event_type) VALUES($1,$2)", [projectId, "license_validated"]);
    await client.query("COMMIT");
    res.json({ valid: true, duration: license.duration, expiresAt: license.expires_at, hwidBound: !!projectMode.rows[0].hwid_lock });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e);
    res.status(500).json({ valid: false, reason: "validation_unavailable" });
  } finally { client.release(); }
});

app.post("/api/blacklist", ready, authenticate, async (req, res) => {
  const subject = clean(req.body.subject), reason = clean(req.body.reason).slice(0, 240);
  if (!subject || subject.length > 160) return res.status(400).json({ error: "Enter a valid user identifier." });
  try {
    const r = await pool.query(
      "INSERT INTO blacklist(project_id,subject,reason) VALUES($1,$2,$3) ON CONFLICT(project_id,subject) DO UPDATE SET reason=EXCLUDED.reason RETURNING *",
      [req.project.id, subject, reason]
    );
    await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'blacklist_added')", [req.project.id]);
    res.status(201).json({ item: r.rows[0] });
  } catch (e) { res.status(500).json({ error: "Could not add blacklist entry." }); }
});

app.delete("/api/blacklist/:id", ready, authenticate, async (req, res) => {
  await pool.query("DELETE FROM blacklist WHERE id=$1 AND project_id=$2", [req.params.id, req.project.id]);
  res.json({ ok: true });
});

app.post("/api/scripts", ready, authenticate, async (req, res) => {
  const title = clean(req.body.title), content = String(req.body.content || "");
  if (!title || title.length > 80) return res.status(400).json({ error: "Script name must be 1–80 characters." });
  if (content.length > 500000) return res.status(413).json({ error: "Script is too large (500 KB maximum)." });
  const client=await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))",[req.project.id]);
    const count=await client.query("SELECT COUNT(*)::int AS total FROM scripts WHERE project_id=$1",[req.project.id]);
    if(count.rows[0].total>=3){await client.query("ROLLBACK");return res.status(403).json({error:"Free plan limit reached: each project can contain up to 3 scripts."});}
    const r=await client.query("INSERT INTO scripts(project_id,title,content) VALUES($1,$2,$3) RETURNING id,title,content,version,created_at,updated_at",[req.project.id,title,content]);
    await client.query("INSERT INTO script_versions(script_id,version,title,content) VALUES($1,$2,$3,$4)",[r.rows[0].id,r.rows[0].version,r.rows[0].title,r.rows[0].content]);
    await client.query("INSERT INTO events(project_id,event_type) VALUES($1,'script_created')",[req.project.id]);
    await client.query("COMMIT");
    res.status(201).json({item:r.rows[0]});
  } catch(e) { await client.query("ROLLBACK"); res.status(500).json({error:"Could not save script."}); }
  finally { client.release(); }
});

app.patch("/api/scripts/:id", ready, authenticate, async (req, res) => {
  const title = clean(req.body.title), content = String(req.body.content || "");
  if (!title || title.length > 80) return res.status(400).json({ error: "Script name must be 1–80 characters." });
  if (content.length > 500000) return res.status(413).json({ error: "Script is too large (500 KB maximum)." });
  const client=await pool.connect();
  try {
    await client.query("BEGIN");
    const r=await client.query(
      "UPDATE scripts SET title=$1,content=$2,version=version+1,updated_at=NOW() WHERE id=$3 AND project_id=$4 RETURNING id,title,content,version,created_at,updated_at",
      [title,content,req.params.id,req.project.id]
    );
    if(!r.rowCount){await client.query("ROLLBACK");return res.status(404).json({error:"Script not found."});}
    const s=r.rows[0];
    await client.query("INSERT INTO script_versions(script_id,version,title,content) VALUES($1,$2,$3,$4)",[s.id,s.version,s.title,s.content]);
    await client.query("INSERT INTO events(project_id,event_type) VALUES($1,'script_updated')",[req.project.id]);
    await client.query("COMMIT");
    res.json({item:{id:s.id,title:s.title,version:s.version,created_at:s.created_at,updated_at:s.updated_at}});
  } catch(e) { await client.query("ROLLBACK"); console.error(e); res.status(500).json({error:"Could not update script."}); }
  finally { client.release(); }
});

app.get("/api/scripts/:id/versions", ready, authenticate, async (req,res) => {
  try {
    const owned=await pool.query("SELECT id FROM scripts WHERE id=$1 AND project_id=$2",[req.params.id,req.project.id]);
    if(!owned.rowCount)return res.status(404).json({error:"Script not found."});
    const versions=await pool.query("SELECT version,title,created_at,LENGTH(content) AS bytes FROM script_versions WHERE script_id=$1 ORDER BY version DESC LIMIT 50",[req.params.id]);
    res.json({versions:versions.rows});
  } catch(e){console.error(e);res.status(500).json({error:"Could not load script versions."});}
});

app.post("/api/scripts/:id/restore/:version", ready, authenticate, async (req,res) => {
  const version=Number(req.params.version);
  if(!Number.isInteger(version)||version<1)return res.status(400).json({error:"Choose a valid version."});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const current=await client.query("SELECT id,version FROM scripts WHERE id=$1 AND project_id=$2 FOR UPDATE",[req.params.id,req.project.id]);
    if(!current.rowCount){await client.query("ROLLBACK");return res.status(404).json({error:"Script not found."});}
    const snapshot=await client.query("SELECT title,content FROM script_versions WHERE script_id=$1 AND version=$2",[req.params.id,version]);
    if(!snapshot.rowCount){await client.query("ROLLBACK");return res.status(404).json({error:"That version is not available."});}
    const next=current.rows[0].version+1, source=snapshot.rows[0];
    const updated=await client.query("UPDATE scripts SET title=$1,content=$2,version=$3,updated_at=NOW() WHERE id=$4 RETURNING id,title,version,updated_at",[source.title,source.content,next,req.params.id]);
    await client.query("INSERT INTO script_versions(script_id,version,title,content) VALUES($1,$2,$3,$4)",[req.params.id,next,source.title,source.content]);
    await client.query("INSERT INTO events(project_id,event_type) VALUES($1,'script_restored')",[req.project.id]);
    await client.query("COMMIT");
    res.json({item:updated.rows[0],restoredFrom:version});
  }catch(e){await client.query("ROLLBACK");console.error(e);res.status(500).json({error:"Could not restore this version."});}
  finally{client.release();}
});

app.patch("/api/scripts/:id/protection-engine", ready, authenticate, async (req, res) => {
  const engine=clean(req.body.engine);
  if(engine!=="prometheus")return res.status(400).json({error:"Prometheus is the only supported protection engine."});
  try {
    const r=await pool.query("UPDATE scripts SET protection_engine=$1 WHERE id=$2 AND project_id=$3 RETURNING id,protection_engine",[engine,req.params.id,req.project.id]);
    if(!r.rowCount)return res.status(404).json({error:"Script not found."});
    await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,$2)",[req.project.id,"protection_engine_selected"]);
    res.json({item:r.rows[0],note:"Preference saved. Protected build generation is not yet enabled."});
  } catch(e) { res.status(500).json({error:"Could not save protection preference."}); }
});

app.get("/api/scripts/:id/builds/latest", ready, authenticate, async (req,res) => {
  try {
    const owned=await pool.query("SELECT id FROM scripts WHERE id=$1 AND project_id=$2",[req.params.id,req.project.id]);
    if(!owned.rowCount)return res.status(404).json({error:"Script not found."});
    const r=await pool.query("SELECT id,source_version,preset,status,output_content,error_message,created_at FROM script_builds WHERE script_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1",[req.params.id]);
    res.json({build:r.rows[0]||null});
  } catch(e){console.error(e);res.status(500).json({error:"Could not load the latest build."});}
});

app.post("/api/scripts/:id/build", ready, authenticate, async (req,res) => {
  const preset=clean(req.body.preset||"Medium");
  if(!["Weak","Medium","Strong"].includes(preset))return res.status(400).json({error:"Choose Weak, Medium or Strong."});
  const found=await pool.query("SELECT s.id,s.title,s.content,s.version,p.runtime_type FROM scripts s JOIN projects p ON p.id=s.project_id WHERE s.id=$1 AND s.project_id=$2",[req.params.id,req.project.id]);
  if(!found.rowCount)return res.status(404).json({error:"Script not found."});
  const script=found.rows[0];
  if(script.runtime_type!=="standalone_lua")return res.status(400).json({error:"Prometheus builds are currently enabled for standalone Lua projects only. Luau support is still experimental and is not enabled here."});
  const binary=process.env.PROMETHEUS_BIN||path.join(os.homedir(),".local","bin","prometheus-lua");
  try{await fs.access(binary)}catch{return res.status(503).json({error:"Prometheus CLI is not installed on this deployment yet. Check the latest Render build logs."});}
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),"sg-prometheus-"));
  const inputPath=path.join(dir,"source.lua"),outputPath=path.join(dir,"protected.lua");
  try{
    await fs.writeFile(inputPath,script.content,"utf8");
    const result=await new Promise((resolve,reject)=>{
      const child=spawn(binary,["--preset",preset,"--Lua51","--out",outputPath,"--nocolors",inputPath],{cwd:dir,env:{...process.env,NO_COLOR:"1"},stdio:["ignore","pipe","pipe"]});
      let stdout="",stderr="",timedOut=false;
      const timer=setTimeout(()=>{timedOut=true;child.kill("SIGKILL");},45000);
      child.stdout.on("data",b=>{stdout=(stdout+b.toString()).slice(-12000);});
      child.stderr.on("data",b=>{stderr=(stderr+b.toString()).slice(-12000);});
      child.on("error",e=>{clearTimeout(timer);reject(e);});
      child.on("close",code=>{clearTimeout(timer);resolve({code,stdout,stderr,timedOut});});
    });
    if(result.timedOut)throw new Error("Prometheus build timed out after 45 seconds.");
    if(result.code!==0)throw new Error((result.stderr||result.stdout||"Prometheus could not parse this Lua source.").slice(-3000));
    const output=await fs.readFile(outputPath,"utf8");
    if(!output.trim())throw new Error("Prometheus returned an empty output file.");
    if(Buffer.byteLength(output,"utf8")>2000000)throw new Error("Protected output exceeds the 2 MB build limit.");
    const saved=await pool.query("INSERT INTO script_builds(script_id,source_version,preset,status,output_content) VALUES($1,$2,$3,'success',$4) RETURNING id,source_version,preset,status,created_at",[script.id,script.version,preset,output]);
    await pool.query("INSERT INTO events(project_id,event_type) VALUES($1,'script_built')",[req.project.id]);
    res.status(201).json({build:saved.rows[0],output});
  }catch(e){
    const message=String(e.message||"Prometheus build failed.").slice(0,3000);
    try{await pool.query("INSERT INTO script_builds(script_id,source_version,preset,status,error_message) VALUES($1,$2,$3,'failed',$4)",[script.id,script.version,preset,message]);}catch(dbErr){console.error("Build log save:",dbErr.message);}
    console.error("Prometheus build:",message);
    res.status(422).json({error:message});
  }finally{await fs.rm(dir,{recursive:true,force:true}).catch(()=>{});}
});

app.delete("/api/scripts/:id", ready, authenticate, async (req, res) => {
  await pool.query("DELETE FROM scripts WHERE id=$1 AND project_id=$2", [req.params.id, req.project.id]);
  res.json({ ok: true });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

// Vercel invokes this Express app as a serverless function. Keep the persistent
// Discord Gateway bot on a separate always-on worker, never inside a Function.
if (process.env.VERCEL !== "1") {
  app.listen(port, () => {
    console.log("Synapse Guard listening on", port);
    schemaReady = initDb();
    schemaReady.then(() => require("./discord-bot").startDiscordBot(pool))
      .catch(err => console.error("Discord bot startup:", err.message));
  });
}

module.exports = app;
