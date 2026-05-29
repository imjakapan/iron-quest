const express          = require('express');
const { createClient } = require('@supabase/supabase-js');
const path             = require('path');

const app       = express();
const PORT      = process.env.PORT || 3333;
const MAX_USERS = 5;

// ── Supabase client (service_role = bypass RLS, เก็บไว้ server เท่านั้น ห้าม expose ใน frontend)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── Helpers
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
  return d; // return object — Supabase JSONB รับ object ได้เลย
}

// ── Middleware
app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));  // serve index.html และไฟล์ static ทั้งหมด

// ── GET /api/users → รายชื่อ users ทั้งหมด + stats
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

// ── POST /api/register
app.post('/api/register', async (req, res) => {
  const { username, pin, avatar } = req.body || {};
  if (!username || !pin)     return res.status(400).json({ ok: false, msg: 'username and pin required' });
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ ok: false, msg: 'PIN must be 4 digits' });
  if (username.length > 16)  return res.status(400).json({ ok: false, msg: 'Username max 16 chars' });
  try {
    const { count } = await supabase
      .from('players')
      .select('*', { count: 'exact', head: true });
    if (count >= MAX_USERS)
      return res.status(409).json({ ok: false, msg: `Max ${MAX_USERS} users reached` });

    const { error } = await supabase.from('players').insert({
      username,
      pin,
      avatar:    avatar || '🧙',
      game_data: defState()
    });
    if (error) {
      if (error.code === '23505')
        return res.status(409).json({ ok: false, msg: 'Username already taken' });
      throw error;
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ ok: false, msg: e.message }); }
});

// ── POST /api/login
app.post('/api/login', async (req, res) => {
  const { username, pin } = req.body || {};
  if (!username || !pin) return res.status(400).json({ ok: false, msg: 'username and pin required' });
  try {
    const { data, error } = await supabase
      .from('players')
      .select('username, pin, avatar, game_data')
      .ilike('username', username)
      .single();
    if (error || !data) return res.status(401).json({ ok: false, msg: 'User not found' });
    if (data.pin !== String(pin)) return res.status(401).json({ ok: false, msg: 'Wrong PIN' });
    res.json({
      ok:       true,
      username: data.username,
      avatar:   data.avatar,
      data:     data.game_data || defState()
    });
  } catch(e) { res.status(500).json({ ok: false, msg: e.message }); }
});

// ── POST /api/save
app.post('/api/save', async (req, res) => {
  const { username, pin, data } = req.body || {};
  if (!username || !pin || !data)
    return res.status(400).json({ ok: false, msg: 'username, pin and data required' });
  try {
    const { data: found, error } = await supabase
      .from('players')
      .select('pin')
      .ilike('username', username)
      .single();
    if (error || !found) return res.status(404).json({ ok: false, msg: 'User not found' });
    if (found.pin !== String(pin)) return res.status(401).json({ ok: false, msg: 'Wrong PIN' });

    const { error: upErr } = await supabase
      .from('players')
      .update({ game_data: trimState(data), last_saved: new Date().toISOString() })
      .ilike('username', username);
    if (upErr) throw upErr;
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ ok: false, msg: e.message }); }
});

// ── DELETE /api/user
app.delete('/api/user', async (req, res) => {
  const { username, pin } = req.body || {};
  if (!username || !pin) return res.status(400).json({ ok: false, msg: 'missing fields' });
  try {
    const { data: found, error } = await supabase
      .from('players')
      .select('pin')
      .ilike('username', username)
      .single();
    if (error || !found) return res.status(404).json({ ok: false, msg: 'User not found' });
    if (found.pin !== String(pin)) return res.status(401).json({ ok: false, msg: 'Wrong PIN' });

    const { error: delErr } = await supabase
      .from('players')
      .delete()
      .ilike('username', username);
    if (delErr) throw delErr;
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ ok: false, msg: e.message }); }
});

// ── Start
app.listen(PORT, () => {
  console.log(`⚔️  IRON QUEST → http://localhost:${PORT}`);
  if (!process.env.SUPABASE_URL) console.warn('⚠️  SUPABASE_URL not set!');
});
