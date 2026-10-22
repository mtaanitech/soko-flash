require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET || "";
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const PUBLIC_URL = (process.env.PUBLIC_URL || "").replace(/\/$/, "");
const BOOST_MIN = Math.max(1, Number(process.env.BOOST_MIN_KES || 50));
const BOOST_MAX = Math.max(BOOST_MIN, Number(process.env.BOOST_MAX_KES || 10000));
const BOOST_DELAY = Math.max(0, Number(process.env.BOOST_DELAY_MINUTES || 30));
if (JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters. Set it in the environment.");
  process.exit(1);
}
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, "sokoflash.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user',
 status TEXT NOT NULL DEFAULT 'active',
 suspended_until TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS listings (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 title TEXT NOT NULL,
 category TEXT NOT NULL,
 description TEXT NOT NULL,
 price_kes INTEGER NOT NULL,
 image_url TEXT DEFAULT '',
 whatsapp TEXT DEFAULT '',
 location TEXT DEFAULT 'Kenya',
 status TEXT NOT NULL DEFAULT 'active',
 boost_status TEXT NOT NULL DEFAULT 'none',
 boost_type TEXT DEFAULT '',
 boost_budget_kes INTEGER DEFAULT 0,
 boost_days INTEGER DEFAULT 0,
 boost_activated_at TEXT,
 boost_expires_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 listing_id INTEGER NOT NULL REFERENCES listings(id),
 reference TEXT NOT NULL UNIQUE,
 amount_kes INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 verified_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reports (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 listing_id INTEGER NOT NULL REFERENCES listings(id),
 reporter_id INTEGER REFERENCES users(id),
 reason TEXT NOT NULL,
 evidence TEXT DEFAULT '',
 status TEXT NOT NULL DEFAULT 'open',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 admin_id INTEGER,
 action TEXT NOT NULL,
 details TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL
);
`);
const settingDefaults = {
 boost_min_kes: String(BOOST_MIN), boost_max_kes: String(BOOST_MAX),
 boost_delay_minutes: String(BOOST_DELAY), boost_enabled: "true",
 boost_max_days: "30"
};
for (const [k,v] of Object.entries(settingDefaults)) {
  db.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)").run(k,v);
}
const adminEmail = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD || "";
if (adminEmail && adminPassword && !db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail)) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')")
    .run("SokoFlash Admin", adminEmail, hash);
}
app.use(helmet({ contentSecurityPolicy: false }));
// Paystack signs the exact raw request bytes; register this before JSON parsing.
app.post("/api/paystack/webhook", express.raw({ type: "application/json" }), (req, res) => {
  const secret = process.env.PAYSTACK_SECRET_KEY || "";
  const signature = req.headers["x-paystack-signature"];
  const body = Buffer.isBuffer(req.body) ? req.body : Buffer.from("");
  if (!secret || !signature) return res.sendStatus(401);
  const expected = crypto.createHmac("sha512", secret).update(body).digest("hex");
  const a = Buffer.from(String(signature)), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.sendStatus(401);
  let event;
  try { event = JSON.parse(body.toString("utf8")); } catch { return res.sendStatus(400); }
  if (event.event === "charge.success" && event.data && event.data.reference) {
    const payment = db.prepare("SELECT * FROM payments WHERE reference=?").get(String(event.data.reference));
    if (payment && Number(event.data.amount) === payment.amount_kes * 100 && event.data.currency === "KES") verifyPayment(payment.reference);
  }
  return res.sendStatus(200);
});
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use("/api/auth", rateLimit({ windowMs: 15*60*1000, limit: 30, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, "public")));

function fail(res, code, message) { return res.status(code).json({ error: message }); }
function tokenFor(user) {
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d", issuer: "sokoflash" });
}
function auth(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : "";
  try {
    if (!token) throw new Error("missing");
    req.user = jwt.verify(token, JWT_SECRET, { issuer: "sokoflash" });
    const user = db.prepare("SELECT id,email,name,role,status,suspended_until FROM users WHERE id=?").get(req.user.id);
    if (!user || user.status === "banned" || (user.suspended_until && new Date(user.suspended_until) > new Date())) {
      return fail(res, 403, "Account unavailable or temporarily suspended.");
    }
    req.account = user;
    next();
  } catch { return fail(res, 401, "Please sign in again."); }
}
function admin(req, res, next) {
  if (!req.account || req.account.role !== "admin") return fail(res, 403, "Admin access required.");
  next();
}
function audit(adminId, action, details) {
  db.prepare("INSERT INTO audit_log(admin_id,action,details) VALUES(?,?,?)")
    .run(adminId || null, action, String(details).slice(0, 2000));
}
function getSetting(key, fallback) {
  const row = db.prepare("SELECT value FROM settings WHERE key=?").get(key);
  return row ? row.value : String(fallback);
}
function publicListing(row) { return row; }

app.get("/health", (req,res)=>res.json({ok:true, service:"SokoFlash Kenya"}));
app.get("/api/config", (req,res)=>res.json({
  boostMinKes:Number(getSetting("boost_min_kes", BOOST_MIN)),
  boostMaxKes:Number(getSetting("boost_max_kes", BOOST_MAX)),
  boostMaxDays:Number(getSetting("boost_max_days",30)),
  boostEnabled:getSetting("boost_enabled","true")==="true",
  paystackPublicKey:process.env.PAYSTACK_PUBLIC_KEY || ""
}));

app.post("/api/auth/register", async (req,res)=>{
  const name = String(req.body.name||"").trim().slice(0,80);
  const email = String(req.body.email||"").trim().toLowerCase();
  const password = String(req.body.password||"");
  if (name.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8)
    return fail(res,400,"Enter a name, valid email, and password of at least 8 characters.");
  try {
    const hash = await bcrypt.hash(password,12);
    const info = db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name,email,hash);
    const user = db.prepare("SELECT id,name,email,role,status FROM users WHERE id=?").get(info.lastInsertRowid);
    res.status(201).json({token:tokenFor(user),user});
  } catch { return fail(res,409,"That email may already be registered."); }
});
app.post("/api/auth/login", async (req,res)=>{
  const email = String(req.body.email||"").trim().toLowerCase();
  const password = String(req.body.password||"");
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!user || !(await bcrypt.compare(password,user.password_hash))) return fail(res,401,"Email or password is incorrect.");
  if (user.status === "banned" || (user.suspended_until && new Date(user.suspended_until)>new Date()))
    return fail(res,403,"This account is restricted.");
  res.json({token:tokenFor(user),user:{id:user.id,name:user.name,email:user.email,role:user.role,status:user.status}});
});
app.get("/api/auth/me",auth,(req,res)=>res.json({user:req.account}));

app.get("/api/listings",(req,res)=>{
  const q = String(req.query.q||"").trim().slice(0,100);
  const category = String(req.query.category||"").trim().slice(0,60);
  const rows = db.prepare(`
    SELECT l.id,l.user_id,l.title,l.category,l.description,l.price_kes,l.image_url,l.whatsapp,l.location,
      l.boost_status,l.boost_type,l.boost_expires_at,l.created_at,u.name AS seller_name
    FROM listings l JOIN users u ON u.id=l.user_id
    WHERE l.status='active'
      AND (l.boost_status!='active' OR l.boost_expires_at IS NULL OR l.boost_expires_at>datetime('now'))
      AND (?='' OR l.title LIKE ? OR l.description LIKE ? OR l.category LIKE ?)
      AND (?='' OR l.category=?)
    ORDER BY CASE WHEN l.boost_status='active' THEN 0 ELSE 1 END, l.created_at DESC LIMIT 100
  `).all(q,`%${q}%`,`%${q}%`,`%${q}%`,category,category);
  res.json({listings:rows});
});
app.post("/api/listings",auth,(req,res)=>{
  const title=String(req.body.title||"").trim().slice(0,120);
  const category=String(req.body.category||"").trim().slice(0,60);
  const description=String(req.body.description||"").trim().slice(0,3000);
  const price=Number(req.body.priceKes);
  const image=String(req.body.imageUrl||"").trim().slice(0,500);
  const whatsapp=String(req.body.whatsapp||"").replace(/[^\d+]/g,"").slice(0,20);
  const location=String(req.body.location||"Kenya").trim().slice(0,80);
  if(title.length<3||category.length<2||description.length<5||!Number.isSafeInteger(price)||price<0||price>100000000)
    return fail(res,400,"Check title, category, description and price.");
  if(image && !/^https:\/\/\S+/i.test(image)) return fail(res,400,"Image URL must start with https://");
  const info=db.prepare("INSERT INTO listings(user_id,title,category,description,price_kes,image_url,whatsapp,location) VALUES(?,?,?,?,?,?,?,?)")
    .run(req.account.id,title,category,description,price,image,whatsapp,location);
  res.status(201).json({id:info.lastInsertRowid,message:"Listing created."});
});
app.get("/api/my/listings",auth,(req,res)=>{
  res.json({listings:db.prepare("SELECT * FROM listings WHERE user_id=? ORDER BY created_at DESC").all(req.account.id)});
});
app.post("/api/listings/:id/report",auth,(req,res)=>{
  const id=Number(req.params.id), reason=String(req.body.reason||"").trim().slice(0,300), evidence=String(req.body.evidence||"").trim().slice(0,1000);
  const listing=db.prepare("SELECT id,user_id FROM listings WHERE id=? AND status='active'").get(id);
  if(!listing)return fail(res,404,"Listing not found.");
  if(listing.user_id===req.account.id)return fail(res,400,"You cannot report your own listing.");
  if(reason.length<4)return fail(res,400,"Please explain the report reason.");
  db.prepare("INSERT INTO reports(listing_id,reporter_id,reason,evidence) VALUES(?,?,?,?)").run(id,req.account.id,reason,evidence);
  // Do not automatically punish sellers from one unverified report.
  res.status(201).json({message:"Report sent to moderation."});
});

async function paystackRequest(endpoint, payload) {
  if (!process.env.PAYSTACK_SECRET_KEY) throw new Error("Paystack is not configured.");
  const response = await fetch("https://api.paystack.co"+endpoint, {
    method: payload ? "POST" : "GET",
    headers: { Authorization:"Bearer "+process.env.PAYSTACK_SECRET_KEY, "Content-Type":"application/json" },
    body: payload ? JSON.stringify(payload) : undefined
  });
  const data = await response.json();
  if (!response.ok || !data.status) throw new Error(data.message || "Paystack request failed.");
  return data.data;
}
app.post("/api/boosts/checkout",auth,async(req,res)=>{
  try {
    if(getSetting("boost_enabled","true")!=="true")return fail(res,403,"Boosts are temporarily unavailable.");
    const listingId=Number(req.body.listingId), budget=Number(req.body.budgetKes), days=Number(req.body.days);
    const type=String(req.body.type||"boost").slice(0,30);
    const min=Number(getSetting("boost_min_kes",BOOST_MIN)), max=Number(getSetting("boost_max_kes",BOOST_MAX)), maxDays=Number(getSetting("boost_max_days",30));
    const listing=db.prepare("SELECT id,user_id FROM listings WHERE id=? AND status='active'").get(listingId);
    if(!listing)return fail(res,404,"Listing not found.");
    if(listing.user_id!==req.account.id && req.account.role!=="admin")return fail(res,403,"Only the listing owner can boost it.");
    if(!Number.isSafeInteger(budget)||budget<min||budget>max||!Number.isInteger(days)||days<1||days>maxDays)
      return fail(res,400,`Budget must be KSh ${min}-${max}; duration must be 1-${maxDays} days.`);
    if(!["boost","featured"].includes(type))return fail(res,400,"Invalid placement type.");
    const reference="sf_"+crypto.randomBytes(18).toString("hex");
    db.prepare("INSERT INTO payments(user_id,listing_id,reference,amount_kes) VALUES(?,?,?,?)").run(req.account.id,listingId,reference,budget);
    db.prepare("UPDATE listings SET boost_status='pending',boost_type=?,boost_budget_kes=?,boost_days=? WHERE id=?").run(type,budget,days,listingId);
    const data=await paystackRequest("/transaction/initialize",{
      email:req.account.email, amount:budget*100, currency:"KES", reference,
      callback_url:PUBLIC_URL ? PUBLIC_URL+"/?payment=return" : undefined,
      metadata:{user_id:req.account.id,listing_id:listingId,boost_type:type,boost_days:days}
    });
    res.json({authorizationUrl:data.authorization_url,reference});
  } catch(e) { console.error("Boost checkout:",e.message); return fail(res,502,e.message||"Could not start payment."); }
});
app.get("/api/paystack/verify/:reference",auth,async(req,res)=>{
  const payment=db.prepare("SELECT * FROM payments WHERE reference=? AND user_id=?").get(String(req.params.reference),req.account.id);
  if(!payment)return fail(res,404,"Payment reference not found.");
  try {
    const data=await paystackRequest("/transaction/verify/"+encodeURIComponent(payment.reference));
    if(data.status==="success" && Number(data.amount)===payment.amount_kes*100 && data.currency==="KES") {
      verifyPayment(payment.reference);
      return res.json({status:"verified",boostStatus:"pending",message:`Payment verified. Boost stays Pending for ${getSetting("boost_delay_minutes",BOOST_DELAY)} minutes before activation.`});
    }
    return res.json({status:"pending",message:"Payment is not confirmed yet."});
  } catch(e) { return fail(res,502,"Could not verify payment right now."); }
});
function verifyPayment(reference) {
  const pay=db.prepare("SELECT * FROM payments WHERE reference=?").get(reference);
  if(!pay || pay.status==="verified")return;
  const now=new Date().toISOString();
  const tx=db.transaction(()=>{
    db.prepare("UPDATE payments SET status='verified',verified_at=? WHERE reference=? AND status='pending'").run(now,reference);
    db.prepare("UPDATE listings SET boost_status='pending',boost_activated_at=NULL,boost_expires_at=NULL WHERE id=?").run(pay.listing_id);
  });
  tx();
}
// Activate verified boosts after delay; duration starts only at activation.
function processBoosts() {
  const delayMs=Math.max(0,Number(getSetting("boost_delay_minutes",BOOST_DELAY)))*60*1000;
  const payments=db.prepare("SELECT p.*,l.boost_days FROM payments p JOIN listings l ON l.id=p.listing_id WHERE p.status='verified' AND l.boost_status='pending' AND l.boost_activated_at IS NULL").all();
  const now=Date.now();
  for(const p of payments) {
    if(!p.verified_at || now-new Date(p.verified_at).getTime()<delayMs) continue;
    const activated=new Date(now).toISOString();
    const expires=new Date(now+Math.max(1,p.boost_days)*86400000).toISOString();
    db.prepare("UPDATE listings SET boost_status='active',boost_activated_at=?,boost_expires_at=? WHERE id=? AND boost_status='pending' AND boost_activated_at IS NULL").run(activated,expires,p.listing_id);
    db.prepare("UPDATE payments SET status='activated' WHERE id=? AND status='verified'").run(p.id);
  }
  db.prepare("UPDATE listings SET boost_status='expired' WHERE boost_status='active' AND boost_expires_at IS NOT NULL AND boost_expires_at<=?").run(new Date().toISOString());
}
setInterval(processBoosts,15000);
processBoosts();

app.get("/api/admin/overview",auth,admin,(req,res)=>{
  const count=(table,where="1=1")=>db.prepare(`SELECT COUNT(*) n FROM ${table} WHERE ${where}`).get().n;
  const revenue=db.prepare("SELECT COALESCE(SUM(amount_kes),0) n FROM payments WHERE status IN ('verified','activated')").get().n;
  res.json({users:count("users"),listings:count("listings"),activeListings:count("listings","status='active'"),openReports:count("reports","status='open'"),pendingPayments:count("payments","status='pending'"),revenueKes:revenue});
});
app.get("/api/admin/listings",auth,admin,(req,res)=>res.json({listings:db.prepare("SELECT l.*,u.email seller_email,u.name seller_name FROM listings l JOIN users u ON u.id=l.user_id ORDER BY l.created_at DESC LIMIT 300").all()}));
app.patch("/api/admin/listings/:id",auth,admin,(req,res)=>{
  const status=String(req.body.status||"");
  if(!["active","hidden","removed"].includes(status))return fail(res,400,"Invalid listing status.");
  db.prepare("UPDATE listings SET status=? WHERE id=?").run(status,Number(req.params.id));
  audit(req.account.id,"listing_status",`listing=${req.params.id}; status=${status}`);
  res.json({message:"Listing updated."});
});
app.get("/api/admin/reports",auth,admin,(req,res)=>res.json({reports:db.prepare("SELECT r.*,l.title listing_title,u.email reporter_email FROM reports r JOIN listings l ON l.id=r.listing_id LEFT JOIN users u ON u.id=r.reporter_id ORDER BY r.created_at DESC LIMIT 300").all()}));
app.patch("/api/admin/reports/:id",auth,admin,(req,res)=>{
  const status=String(req.body.status||"");
  if(!["open","reviewing","resolved","dismissed"].includes(status))return fail(res,400,"Invalid report status.");
  db.prepare("UPDATE reports SET status=? WHERE id=?").run(status,Number(req.params.id));
  audit(req.account.id,"report_status",`report=${req.params.id}; status=${status}`);
  res.json({message:"Report updated."});
});
app.patch("/api/admin/users/:id/restrict",auth,admin,(req,res)=>{
  const id=Number(req.params.id), hours=Number(req.body.hours), reason=String(req.body.reason||"").trim().slice(0,500);
  if(id===req.account.id)return fail(res,400,"You cannot restrict your own admin account.");
  if(!reason)return fail(res,400,"A reason is required.");
  if(![1,6,12,24,168,720,87600].includes(hours))return fail(res,400,"Use 1, 6, 12, 24, 168, 720, or 87600 hours.");
  const until=hours>=87600?null:new Date(Date.now()+hours*3600000).toISOString();
  db.prepare("UPDATE users SET status=?,suspended_until=? WHERE id=?").run(hours>=87600?"banned":"active",until,id);
  audit(req.account.id,"user_restriction",`user=${id}; hours=${hours}; reason=${reason}`);
  res.json({message:"Restriction saved."});
});
app.patch("/api/admin/settings",auth,admin,(req,res)=>{
  const allowed=["boost_min_kes","boost_max_kes","boost_delay_minutes","boost_enabled","boost_max_days"];
  const tx=db.transaction(()=>{
    for(const key of allowed) if(req.body[key]!==undefined) {
      let value=String(req.body[key]);
      if(key!=="boost_enabled" && (!Number.isFinite(Number(value)) || Number(value)<0))throw new Error("Invalid setting: "+key);
      if(key==="boost_enabled" && !["true","false"].includes(value))throw new Error("Invalid boost_enabled");
      db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(key,value);
    }
  });
  try{tx();audit(req.account.id,"settings_update",JSON.stringify(req.body));res.json({message:"Settings saved."});}
  catch(e){return fail(res,400,e.message);}
});
app.get("/api/admin/audit",auth,admin,(req,res)=>res.json({logs:db.prepare("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 300").all()}));

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`SokoFlash Kenya running on port ${PORT}`));
