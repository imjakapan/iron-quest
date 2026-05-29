require('dotenv').config();   // ใช้สำหรับ local dev (.env) — บน Render ใช้ env vars แทน

const express          = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt           = require('bcryptjs');

const app       = express();
const PORT      = process.env.PORT || 3333;
const MAX_USERS = 10;
const REG_CODE  = 'PTTDigitalNetwork';  // Code ที่ต้องใส่เพื่อสร้าง User

// Trust proxy (Render ใช้ load balancer — ต้องเปิดเพื่อดู IP จริงของ client)
app.set('trust proxy', 1);

// ── Supabase client (service_role key อยู่ฝั่ง server เท่านั้น)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ════════════════════════════════════════════════
//  RATE LIMITING — ป้องกัน brute-force PIN
// ════════════════════════════════════════════════

const loginAttempts = new Map(); // ip → { count, blockedUntil }
const MAX_ATTEMPTS  = 5;
const BLOCK_MS      = 15 * 60 * 1000; // 15 นาที

function checkLoginRate(req, res, next) {
  const ip  = req.ip;
  const now = Date.now();
  const rec = loginAttempts.get(ip) || { count: 0, blockedUntil: 0 };

  if (rec.blockedUntil > now) {
    const mins = Math.ceil((rec.blockedUntil - now) / 60000);
    return res.status(429).json({
      ok:  false,
      msg: `ใส่ PIN ผิดหลายครั้งเกินไป — ถูก block อีก ${mins} นาที`
    });
  }
  req._clientIP = ip;
  next();
}

function recordFail(ip) {
  const rec = loginAttempts.get(ip) || { count: 0, blockedUntil: 0 };
  rec.count++;
  if (rec.count >= MAX_ATTEMPTS) {
    rec.blockedUntil = Date.now() + BLOCK_MS;
    rec.count = 0;
    console.log(`[security] IP ${ip} blocked for 15 min (too many failed logins)`);
  }
  loginAttempts.set(ip, rec);
}

function resetFail(ip) { loginAttempts.delete(ip); }

// ล้าง block ที่หมดเวลาแล้วทุก 30 นาที
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of loginAttempts.entries()) {
    if (rec.blockedUntil < now && rec.count === 0) loginAttempts.delete(ip);
  }
}, 30 * 60 * 1000);

// ════════════════════════════════════════════════
//  HELPERS
// ════════════════════════════════════════════════

function defState() {
  return {
    fp:0, exp:0, lv:1,
    streak:0, lastWO:null,
    wo:0, totalFP:0, prs:0, penalties:0,
    soberDays:0, cleanDays:0,
    wkStart:null, wkWO:0, wkPR:0, wkCardio:0, wkProt:0, wkSleep:0, wkClean:0,
    wkLog:[], wkQId:null, wkQDone:false,
    dqDate:null, dqIds:[], dqDone:[],
    lastHabit:null, ach:[], purchases:[], log:[]
  };
}

function trimState(s) {
  if (!s) return defState();
  const d = typeof s === 'string' ? JSON.parse(s) : JSON.parse(JSON.stringify(s));
  if (Array.isArray(d.log))       d.log       = d.log.slice(-20);
  if (Array.isArray(d.purchases)) d.purchases = d.purchases.slice(-20);
  return d;
}

// เช็คว่า PIN ใน DB เป็น bcrypt hash หรือ plain text (สำหรับ user เก่า)
function isHashed(pin) {
  return typeof pin === 'string' && (pin.startsWith('$2a$') || pin.startsWith('$2b$'));
}

// ════════════════════════════════════════════════
//  MIDDLEWARE
// ════════════════════════════════════════════════

app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));   // serve index.html

// ════════════════════════════════════════════════
//  API ENDPOINTS
// ════════════════════════════════════════════════

// GET /api/users
app.get('/api/users', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('players')
      .select('username, avatar, game_data')
      .order('created_at');
    if (error) throw error;
    res.json({
      ok: true,
      users: data.map(r => ({
        username: r.username,
        avatar:   r.avatar,
        lv:       r.game_data?.lv      || 1,
        totalFP:  r.game_data?.totalFP || 0,
        streak:   r.game_data?.streak  || 0,
        wo:       r.game_data?.wo      || 0,
      }))
    });
  } catch(e) { res.status(500).json({ ok: false, msg: e.message }); }
});

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { username, pin, avatar, regCode } = req.body || {};

  if (!username || !pin)
    return res.status(400).json({ ok: false, msg: 'username and pin required' });
  if (regCode !== REG_CODE)
    return res.status(403).json({ ok: false, msg: 'Registration Code ไม่ถูกต้อง' });
  if (!/^\d{6}$/.test(pin))
    return res.status(400).json({ ok: false, msg: 'PIN ต้องเป็น 6 หลักเท่านั้น' });
  if (username.length > 16)
    return res.status(400).json({ ok: false, msg: 'Username สูงสุด 16 ตัวอักษร' });

  try {
    const { count } = await supabase
      .from('players')
      .select('*', { count: 'exact', head: true });
    if (count >= MAX_USERS)
      return res.status(409).json({ ok: false, msg: `ผู้ใช้เต็มแล้ว (สูงสุด ${MAX_USERS} คน)` });

    const pinHash = await bcrypt.hash(pin, 12);  // cost factor 12 = ปลอดภัยดี
    const { error } = await supabase.from('players').insert({
      username,
      pin:       pinHash,
      avatar:    avatar || '🧙',
      game_data: defState()
    });
    if (error) {
      if (error.code === '23505')
        return res.status(409).json({ ok: false, msg: 'Username นี้มีแล้ว กรุณาเลือกชื่ออื่น' });
      throw error;
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ ok: false, msg: e.message }); }
});

// POST /api/login  (มี rate limiting)
app.post('/api/login', checkLoginRate, async (req, res) => {
  const { username, pin } = req.body || {};
  const ip = req._clientIP;
  if (!username || !pin)
    return res.status(400).json({ ok: false, msg: 'username and pin required' });

  try {
    const { data, error } = await supabase
      .from('players')
      .select('username, pin, avatar, game_data')
      .ilike('username', username)
      .single();

    if (error || !data) {
      recordFail(ip);
      return res.status(401).json({ ok: false, msg: 'ไม่พบ User นี้' });
    }

    // รองรับทั้ง hashed PIN และ plain text (auto-migrate user เก่า)
    let valid = false;
    if (isHashed(data.pin)) {
      valid = await bcrypt.compare(String(pin), data.pin);
    } else {
      // user เก่าที่ยังเก็บ plain text → เปรียบเทียบแล้ว hash ทันที
      valid = data.pin === String(pin);
      if (valid) {
        const newHash = await bcrypt.hash(String(pin), 12);
        await supabase.from('players')
          .update({ pin: newHash })
          .ilike('username', username);
        console.log(`[migration] Auto-hashed PIN for user: ${username}`);
      }
    }

    if (!valid) {
      recordFail(ip);
      const rec = loginAttempts.get(ip) || { count: 0 };
      const remaining = MAX_ATTEMPTS - rec.count;
      return res.status(401).json({
        ok:  false,
        msg: `PIN ไม่ถูกต้อง (เหลือ ${remaining} ครั้งก่อนถูก block 15 นาที)`
      });
    }

    resetFail(ip);
    res.json({
      ok:       true,
      username: data.username,
      avatar:   data.avatar,
      data:     data.game_data || defState()
    });
  } catch(e) { res.status(500).json({ ok: false, msg: e.message }); }
});

// POST /api/save
app.post('/api/save', async (req, res) => {
  const { username, pin, data } = req.body || {};
  if (!username || !pin || !data)
    return res.status(400).json({ ok: false, msg: 'missing fields' });
  try {
    const { data: found, error } = await supabase
      .from('players').select('pin').ilike('username', username).single();
    if (error || !found) return res.status(404).json({ ok: false, msg: 'ไม่พบ User' });

    const valid = isHashed(found.pin)
      ? await bcrypt.compare(String(pin), found.pin)
      : found.pin === String(pin);
    if (!valid) return res.status(401).json({ ok: false, msg: 'PIN ไม่ถูกต้อง' });

    const { error: upErr } = await supabase.from('players')
      .update({ game_data: trimState(data), last_saved: new Date().toISOString() })
      .ilike('username', username);
    if (upErr) throw upErr;
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ ok: false, msg: e.message }); }
});

// DELETE /api/user
app.delete('/api/user', async (req, res) => {
  const { username, pin } = req.body || {};
  if (!username || !pin)
    return res.status(400).json({ ok: false, msg: 'missing fields' });
  try {
    const { data: found, error } = await supabase
      .from('players').select('pin').ilike('username', username).single();
    if (error || !found) return res.status(404).json({ ok: false, msg: 'ไม่พบ User' });

    const valid = isHashed(found.pin)
      ? await bcrypt.compare(String(pin), found.pin)
      : found.pin === String(pin);
    if (!valid) return res.status(401).json({ ok: false, msg: 'PIN ไม่ถูกต้อง' });

    const { error: delErr } = await supabase.from('players')
      .delete().ilike('username', username);
    if (delErr) throw delErr;
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ ok: false, msg: e.message }); }
});

app.listen(PORT, () => {
  console.log(`⚔️  IRON QUEST → http://localhost:${PORT}`);
  if (!process.env.SUPABASE_URL) console.warn('⚠️  SUPABASE_URL not set!');
});
