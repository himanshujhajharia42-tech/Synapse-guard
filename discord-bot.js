const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder } = require("discord.js");
const crypto = require("crypto");
const DAYS = { weekly:7, monthly:30, yearly:365, lifetime:null };
const clean = v => String(v || "").trim();
const hash = v => crypto.createHash("sha256").update(v).digest("hex");

function commands() {
  const durations = [{name:"Weekly · 7 days",value:"weekly"},{name:"Monthly · 30 days",value:"monthly"},{name:"Yearly · 365 days",value:"yearly"},{name:"Lifetime",value:"lifetime"}];
  const duration = o => o.addChoices(...durations);
  return [
    new SlashCommandBuilder().setName("connect-project").setDescription("Connect a Synapse Guard project").addStringOption(o=>o.setName("project_id").setDescription("Project UUID").setRequired(true)).addStringOption(o=>o.setName("project_api_key").setDescription("Private API key, checked once and never stored").setRequired(true)),
    new SlashCommandBuilder().setName("project").setDescription("Show connected project"),
    new SlashCommandBuilder().setName("key-create").setDescription("Create a license").addStringOption(o=>duration(o.setName("duration").setDescription("License duration").setRequired(true))),
    new SlashCommandBuilder().setName("key-list").setDescription("List latest licenses").addIntegerOption(o=>o.setName("limit").setDescription("Number of keys").setMinValue(1).setMaxValue(15)),
    new SlashCommandBuilder().setName("key-info").setDescription("Show license details").addStringOption(o=>o.setName("license_key").setDescription("License key").setRequired(true)),
    new SlashCommandBuilder().setName("key-revoke").setDescription("Revoke a license").addStringOption(o=>o.setName("license_key").setDescription("License key").setRequired(true)),
    new SlashCommandBuilder().setName("key-activate").setDescription("Reactivate a license").addStringOption(o=>o.setName("license_key").setDescription("License key").setRequired(true)),
    new SlashCommandBuilder().setName("key-reset-hwid").setDescription("Reset a device binding").addStringOption(o=>o.setName("license_key").setDescription("License key").setRequired(true)),
    new SlashCommandBuilder().setName("key-extend").setDescription("Extend a license").addStringOption(o=>o.setName("license_key").setDescription("License key").setRequired(true)).addStringOption(o=>duration(o.setName("duration").setDescription("Extension").setRequired(true))),
    new SlashCommandBuilder().setName("whitelist-add").setDescription("Add a whitelisted user").addStringOption(o=>o.setName("user_id").setDescription("User ID or username").setRequired(true)),
    new SlashCommandBuilder().setName("whitelist-remove").setDescription("Remove a whitelisted user").addStringOption(o=>o.setName("user_id").setDescription("Exact user ID or username").setRequired(true)),
    new SlashCommandBuilder().setName("blacklist-add").setDescription("Blacklist a user").addStringOption(o=>o.setName("user_id").setDescription("User ID or username").setRequired(true)).addStringOption(o=>o.setName("reason").setDescription("Optional reason").setMaxLength(240)),
    new SlashCommandBuilder().setName("blacklist-remove").setDescription("Remove a blacklisted user").addStringOption(o=>o.setName("user_id").setDescription("Exact user ID or username").setRequired(true)),
    new SlashCommandBuilder().setName("stats").setDescription("Show project statistics"),
    new SlashCommandBuilder().setName("help").setDescription("Show all bot commands")
  ].map(c=>c.toJSON());
}

async function startDiscordBot(pool) {
  const token=clean(process.env.DISCORD_BOT_TOKEN), owner=clean(process.env.DISCORD_OWNER_ID), clientId=clean(process.env.DISCORD_CLIENT_ID);
  if(!token){console.log("Discord bot disabled: DISCORD_BOT_TOKEN is not configured.");return;}
  if(!/^\d{17,20}$/.test(owner)||!clientId){console.error("Discord bot needs DISCORD_OWNER_ID and DISCORD_CLIENT_ID.");return;}
  await pool.query("CREATE TABLE IF NOT EXISTS discord_integrations (project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE, owner_user_id TEXT NOT NULL, guild_id TEXT, connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
  const rest=new REST({version:"10"}).setToken(token), defs=commands();
  if(process.env.DISCORD_GUILD_ID) await rest.put(Routes.applicationGuildCommands(clientId,process.env.DISCORD_GUILD_ID),{body:defs});
  else await rest.put(Routes.applicationCommands(clientId),{body:defs});
  const bot=new Client({intents:[GatewayIntentBits.Guilds]});
  const log=(id,type)=>pool.query("INSERT INTO events(project_id,event_type) VALUES($1,$2)",[id,type]);
  const findProject=async i=>{const r=await pool.query("SELECT p.id,p.name FROM discord_integrations d JOIN projects p ON p.id=d.project_id WHERE d.owner_user_id=$1 AND (d.guild_id IS NULL OR d.guild_id=$2) LIMIT 1",[i.user.id,i.guildId||""]);return r.rows[0]||null;};
  const findKey=async(id,key)=>{const r=await pool.query("SELECT * FROM license_keys WHERE project_id=$1 AND license_key=$2",[id,clean(key).toUpperCase()]);return r.rows[0]||null;};
  bot.on("interactionCreate",async i=>{
    if(!i.isChatInputCommand())return;
    const n=i.commandName;
    try{
      if(n==="help")return i.reply({ephemeral:true,content:"Synapse Guard commands: /connect-project, /project, /key-create, /key-list, /key-info, /key-revoke, /key-activate, /key-reset-hwid, /key-extend, /whitelist-add, /whitelist-remove, /blacklist-add, /blacklist-remove, /stats. All management commands are owner-only and replies are private."});
      if(n==="connect-project"){
        if(i.user.id!==owner)return i.reply({ephemeral:true,content:"Only the configured bot owner can connect a project."});
        const pid=clean(i.options.getString("project_id")), key=clean(i.options.getString("project_api_key"));
        if(!/^[0-9a-f-]{36}$/i.test(pid)||key.length<20||key.length>160)return i.reply({ephemeral:true,content:"Project ID or API key format is invalid."});
        const p=await pool.query("SELECT id,name FROM projects WHERE id=$1 AND key_hash=$2",[pid,hash(key)]);
        if(!p.rowCount)return i.reply({ephemeral:true,content:"Project credentials did not match. No connection was made."});
        await pool.query("INSERT INTO discord_integrations(project_id,owner_user_id,guild_id) VALUES($1,$2,$3) ON CONFLICT(project_id) DO UPDATE SET owner_user_id=EXCLUDED.owner_user_id,guild_id=EXCLUDED.guild_id,connected_at=NOW()",[pid,owner,i.guildId||null]);
        await log(pid,"discord_project_connected");
        return i.reply({ephemeral:true,content:"Connected project "+p.rows[0].name+". Your API key was verified but not stored."});
      }
      if(i.user.id!==owner)return i.reply({ephemeral:true,content:"You are not authorized to manage this project."});
      const p=await findProject(i);
      if(!p)return i.reply({ephemeral:true,content:"No project connected here. Bot owner: run /connect-project first."});
      const pid=p.id;
      if(n==="project")return i.reply({ephemeral:true,content:"Connected project: "+p.name+" | "+pid});
      if(n==="key-create"){
        const d=i.options.getString("duration"), key="LIC-"+crypto.randomBytes(12).toString("hex").toUpperCase();
        const r=await pool.query("INSERT INTO license_keys(project_id,license_key,duration,expires_at,hwid_reset_limit) VALUES($1,$2,$3,CASE WHEN $4::int IS NULL THEN NULL ELSE NOW()+($4::int*INTERVAL '1 day') END,1) RETURNING expires_at",[pid,key,d,DAYS[d]]);
        await log(pid,"license_created");
        return i.reply({ephemeral:true,content:"License created: "+key+" | Plan: "+d+" | Expiry: "+(r.rows[0].expires_at?new Date(r.rows[0].expires_at).toUTCString():"Never")+". Copy and share it securely."});
      }
      if(n==="key-list"){
        const lim=i.options.getInteger("limit")||10,r=await pool.query("SELECT license_key,status,duration,expires_at FROM license_keys WHERE project_id=$1 ORDER BY created_at DESC LIMIT $2",[pid,lim]);
        const lines=r.rows.map(k=>k.license_key+" | "+k.status+" | "+k.duration+" | "+(k.expires_at?new Date(k.expires_at).toLocaleDateString():"never expires"));
        return i.reply({ephemeral:true,content:lines.length?lines.join("\n"):"No licenses yet."});
      }
      if(n==="key-info"){
        const k=await findKey(pid,i.options.getString("license_key"));if(!k)return i.reply({ephemeral:true,content:"License not found."});
        return i.reply({ephemeral:true,content:k.license_key+" | "+k.status+" | "+k.duration+" | Expiry: "+(k.expires_at?new Date(k.expires_at).toUTCString():"Never")+" | HWID bound: "+!!k.hwid_hash+" | Resets: "+k.hwid_reset_count+"/"+k.hwid_reset_limit});
      }
      if(n==="key-revoke"||n==="key-activate"){
        const k=await findKey(pid,i.options.getString("license_key"));if(!k)return i.reply({ephemeral:true,content:"License not found."});
        const status=n==="key-revoke"?"revoked":"active";await pool.query("UPDATE license_keys SET status=$1 WHERE id=$2",[status,k.id]);await log(pid,"license_updated");
        return i.reply({ephemeral:true,content:"License status updated: "+status});
      }
      if(n==="key-reset-hwid"){
        const k=await findKey(pid,i.options.getString("license_key"));if(!k)return i.reply({ephemeral:true,content:"License not found."});
        if(!k.hwid_hash)return i.reply({ephemeral:true,content:"This license is not device-bound."});
        if(k.hwid_reset_count>=k.hwid_reset_limit)return i.reply({ephemeral:true,content:"Reset limit reached. Increase the allowance in the website first."});
        await pool.query("UPDATE license_keys SET hwid_hash=NULL,bound_at=NULL,hwid_reset_count=hwid_reset_count+1 WHERE id=$1",[k.id]);await log(pid,"license_hwid_reset");
        return i.reply({ephemeral:true,content:"HWID reset. Used "+(k.hwid_reset_count+1)+" of "+k.hwid_reset_limit+" allowed resets."});
      }
      if(n==="key-extend"){
        const k=await findKey(pid,i.options.getString("license_key"));if(!k)return i.reply({ephemeral:true,content:"License not found."});
        const d=i.options.getString("duration"),days=DAYS[d];
        const r=await pool.query("UPDATE license_keys SET duration=$1,expires_at=CASE WHEN $1='lifetime' THEN NULL ELSE GREATEST(COALESCE(expires_at,NOW()),NOW())+($2::int*INTERVAL '1 day') END,status='active' WHERE id=$3 RETURNING expires_at",[d,days||0,k.id]);await log(pid,"license_extended");
        return i.reply({ephemeral:true,content:"License extended. New expiry: "+(r.rows[0].expires_at?new Date(r.rows[0].expires_at).toUTCString():"Never")});
      }
      if(n==="whitelist-add"||n==="blacklist-add"){
        const subject=clean(i.options.getString("user_id"));if(!subject||subject.length>160)return i.reply({ephemeral:true,content:"Invalid user identifier."});
        if(n==="whitelist-add"){await pool.query("INSERT INTO allowlist(project_id,subject) VALUES($1,$2) ON CONFLICT DO NOTHING",[pid,subject]);await log(pid,"whitelist_added");}
        else{const reason=clean(i.options.getString("reason")||"").slice(0,240);await pool.query("INSERT INTO blacklist(project_id,subject,reason) VALUES($1,$2,$3) ON CONFLICT(project_id,subject) DO UPDATE SET reason=EXCLUDED.reason",[pid,subject,reason]);await log(pid,"blacklist_added");}
        return i.reply({ephemeral:true,content:"Added "+subject+" to "+(n==="whitelist-add"?"whitelist":"blacklist")+"."});
      }
      if(n==="whitelist-remove"||n==="blacklist-remove"){
        const table=n==="whitelist-remove"?"allowlist":"blacklist",subject=clean(i.options.getString("user_id"));
        const r=await pool.query("DELETE FROM "+table+" WHERE project_id=$1 AND subject=$2",[pid,subject]);
        return i.reply({ephemeral:true,content:r.rowCount?"Removed "+subject+".":"No matching user found."});
      }
      if(n==="stats"){
        const [k,w,b,a]=await Promise.all([pool.query("SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE status='active')::int active FROM license_keys WHERE project_id=$1",[pid]),pool.query("SELECT COUNT(*)::int total FROM allowlist WHERE project_id=$1",[pid]),pool.query("SELECT COUNT(*)::int total FROM blacklist WHERE project_id=$1",[pid]),pool.query("SELECT access_count FROM projects WHERE id=$1",[pid])]);
        return i.reply({ephemeral:true,content:p.name+" stats | Licenses: "+k.rows[0].total+" ("+k.rows[0].active+" active) | Whitelist: "+w.rows[0].total+" | Blacklist: "+b.rows[0].total+" | Project accesses: "+a.rows[0].access_count});
      }
      return i.reply({ephemeral:true,content:"Unknown command. Use /help."});
    }catch(e){console.error("Discord command error:",e);const msg="Command failed. Check Synapse Guard server logs.";if(i.replied||i.deferred)await i.followUp({ephemeral:true,content:msg}).catch(()=>{});else await i.reply({ephemeral:true,content:msg}).catch(()=>{});}
  });
  await bot.login(token);
  console.log("Synapse Guard Discord bot connected as",bot.user.tag);
}
module.exports={startDiscordBot};
