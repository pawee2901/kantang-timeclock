/**
 * ระบบลงเวลาปฏิบัติงานออนไลน์ — วิทยาลัยการอาชีพกันตัง
 * เซิร์ฟเวอร์ Node.js (Express) บน Render + ฐานข้อมูล Supabase
 *
 * ตัวแปรสภาพแวดล้อม (ตั้งใน Render → Environment):
 *   SUPABASE_URL  — Project URL ของ Supabase
 *   SUPABASE_KEY  — Secret key (sb_secret_...) หรือ service_role key  ⚠ ความลับ
 *   PIN_SALT      — ข้อความสุ่มยาว ๆ สำหรับแฮช PIN                 ⚠ ความลับ ห้ามเปลี่ยนหลังใช้งาน
 *   INIT_ADMIN    — (ใช้ครั้งแรก/ฉุกเฉิน) "รหัส:PIN" เช่น "S001:123456" — ตั้ง PIN ให้แอดมินที่ยังไม่มี PIN ตอนเซิร์ฟเวอร์เริ่ม
 */
'use strict';

const express = require('express');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const TZ = 'Asia/Bangkok';
// รับได้ทั้ง https://xxx.supabase.co และแบบที่คัดลอกมาพร้อม /rest/v1 หรือ / ต่อท้าย
const SUPABASE_URL = String(process.env.SUPABASE_URL || '').trim()
  .replace(/\/+$/, '').replace(/\/rest\/v1$/i, '').replace(/\/+$/, '');
const SUPABASE_KEY = String(process.env.SUPABASE_KEY || '').trim();
const PIN_SALT = String(process.env.PIN_SALT || '');

const MAX_FAIL = 5;                    // ใส่ PIN ผิดได้กี่ครั้งต่อรหัส
const LOCK_MS = 15 * 60 * 1000;        // ล็อกนานเท่าไรเมื่อผิดเกิน
const IP_MAX_LOGIN = 30;               // พยายามเข้าสู่ระบบได้กี่ครั้งต่อ IP ใน 15 นาที
const SETTINGS_CACHE_MS = 5 * 60 * 1000;

const missing = ['SUPABASE_URL', 'SUPABASE_KEY', 'PIN_SALT'].filter((k) => !String(process.env[k] || '').trim());
if (missing.length) {
  console.error('❌ ยังไม่ได้ตั้งค่า Environment: ' + missing.join(', '));
  process.exit(1);
}
if (PIN_SALT.length < 32) console.warn('⚠ PIN_SALT สั้นเกินไป ควรยาวอย่างน้อย 32 ตัวอักษร');
if (!/^https:\/\/[a-z0-9-]+\.supabase\.(co|in)$/i.test(SUPABASE_URL)) {
  console.warn('⚠ SUPABASE_URL ดูไม่เหมือน Project URL (ควรเป็น https://xxxx.supabase.co): ' + SUPABASE_URL);
}
console.log('เชื่อมต่อฐานข้อมูล: ' + SUPABASE_URL + ' (คีย์แบบ ' +
            (SUPABASE_KEY.startsWith('sb_secret_') ? 'secret' : SUPABASE_KEY.startsWith('sb_') ? '⚠ publishable — ใช้ไม่ได้ ต้องเป็น secret' : 'legacy JWT') + ')');

/* ============================================================
 * 1) การยืนยันตัวตน (รหัสบุคลากร + PIN, เก็บเป็นแฮชเท่านั้น)
 * ============================================================ */

const failCount = new Map();   // empId -> { n, until }

async function login(empId, pin) {
  empId = clean(empId);
  pin = clean(pin);
  if (!empId || !pin) return { ok: false, msg: 'กรุณากรอกรหัสบุคลากรและ PIN' };

  const f = failCount.get(empId);
  if (f && f.until > Date.now() && f.n >= MAX_FAIL) {
    return fail(empId, 'login', 'ใส่ PIN ผิดเกิน ' + MAX_FAIL + ' ครั้ง กรุณารอ 15 นาทีแล้วลองใหม่');
  }

  const emp = await findEmployee(empId);
  if (!emp) return fail(empId, 'login', 'ไม่พบรหัสบุคลากรนี้ในระบบ');
  if (emp.status !== 'active') return fail(empId, 'login', 'บัญชีนี้ถูกระงับการใช้งาน ติดต่องานบุคลากร');
  if (!emp.pinHash) return fail(empId, 'login', 'ยังไม่ได้ตั้ง PIN ติดต่องานบุคลากรเพื่อตั้ง PIN');
  if (!safeEqual(hashPin(empId, pin), emp.pinHash)) {
    const cur = f && f.until > Date.now() ? f.n : 0;
    failCount.set(empId, { n: cur + 1, until: Date.now() + LOCK_MS });
    return fail(empId, 'login', 'PIN ไม่ถูกต้อง');
  }

  failCount.delete(empId);
  log(empId, 'login', 'สำเร็จ');
  return { ok: true, empId, name: emp.name, position: emp.position, role: emp.role, token: dayToken(empId) };
}

/** โทเคนรายวันแบบ stateless: HMAC(รหัส + วันที่) — หมดอายุอัตโนมัติเมื่อขึ้นวันใหม่ (เวลาไทย) */
function dayToken(empId) {
  return crypto.createHmac('sha256', PIN_SALT).update('token|' + empId + '|' + bkk().date).digest('hex');
}

function verifyToken(empId, token) {
  return typeof token === 'string' && safeEqual(token, dayToken(empId));
}

/* ============================================================
 * 2) ลงเวลาเข้า–ออก + ตรวจ Geofencing
 * ============================================================ */

async function clock(empId, token, action, lat, lng, accuracy) {
  empId = clean(empId);
  if (!verifyToken(empId, token)) return { ok: false, expired: true, msg: 'เซสชันหมดอายุ กรุณาเข้าสู่ระบบใหม่' };

  const emp = await findEmployee(empId);
  if (!emp || emp.status !== 'active') return fail(empId, action, 'ไม่มีสิทธิ์ใช้งาน');

  if (action !== 'เข้า' && action !== 'ออก') return fail(empId, String(action), 'ประเภทการลงเวลาไม่ถูกต้อง');
  lat = Number(lat); lng = Number(lng); accuracy = Math.round(Number(accuracy) || 0);
  if (!isFinite(lat) || !isFinite(lng) || lat === 0) {
    return fail(empId, action, 'ไม่พบพิกัด GPS กรุณาเปิดตำแหน่ง (Location) แล้วลองใหม่');
  }

  // --- ตรวจพื้นที่ (Geofencing) — ทำฝั่งเซิร์ฟเวอร์ทั้งหมด ---
  const s = await getSettings();
  const dist = Math.round(haversine(lat, lng, Number(s.SITE_LAT), Number(s.SITE_LNG)));
  const inArea = dist <= Number(s.RADIUS_M);
  if (!inArea && String(s.ALLOW_OUTSIDE).toUpperCase() !== 'YES') {
    return fail(empId, action,
      'คุณอยู่นอกพื้นที่วิทยาลัย (ห่างจุดกำหนด ' + dist + ' เมตร, กำหนดไม่เกิน ' + s.RADIUS_M + ' เมตร)');
  }

  const now = new Date();
  const { date, time } = bkk(now);
  let status = 'ปกติ';
  if (action === 'เข้า' && time > s.WORK_START + ':59') status = 'มาสาย';
  if (action === 'ออก' && time < s.WORK_END + ':00') status = 'ออกก่อนเวลา';

  // --- บันทึก: unique constraint ในฐานข้อมูลกันลงเวลาซ้ำ (แม่นยำแม้กดพร้อมกัน) ---
  const res = await sb('POST', 'attendance', {
    ts: now.toISOString(), work_date: date, work_time: time,
    emp_id: empId, emp_name: emp.name, action, status,
    lat, lng, dist_m: dist, in_area: inArea, accuracy_m: accuracy
  }, { Prefer: 'return=minimal' });
  if (res.code === 409 && res.data && res.data.code === '23505') {
    return fail(empId, action, 'วันนี้คุณลงเวลา "' + action + '" ไปแล้ว');
  }
  check(res);

  log(empId, action, 'สำเร็จ ' + date + ' ' + time + ' ระยะ ' + dist + ' ม.');
  return {
    ok: true,
    msg: 'ลงเวลา' + action + 'สำเร็จ เวลา ' + time + (status !== 'ปกติ' ? ' (' + status + ')' : ''),
    time, status, dist
  };
}

async function getHistory(empId, token) {
  empId = clean(empId);
  if (!verifyToken(empId, token)) return { ok: false, expired: true, msg: 'เซสชันหมดอายุ' };
  const rows = await sbGet('attendance?select=work_date,work_time,action,status&emp_id=eq.' + enc(empId) +
                           '&order=ts.desc&limit=40');
  return { ok: true, rows: rows.map((r) => ({ date: r.work_date, time: r.work_time, action: r.action, status: r.status })) };
}

/* ============================================================
 * 3) หน้าแอดมิน (เฉพาะบทบาท admin — ตรวจสิทธิ์จากฐานข้อมูลทุกคำสั่ง)
 * ============================================================ */

async function asAdmin(empId, token, fn) {
  empId = clean(empId);
  if (!verifyToken(empId, token)) return { ok: false, expired: true, msg: 'เซสชันหมดอายุ' };
  const me = await findEmployee(empId);
  if (!me || me.status !== 'active' || me.role !== 'admin') return fail(empId, 'admin', 'ไม่มีสิทธิ์ผู้ดูแลระบบ');
  return fn(me);
}

const adminDay = (empId, token, date) => asAdmin(empId, token, async () => {
  date = /^\d{4}-\d{2}-\d{2}$/.test(date || '') ? date : bkk().date;
  const all = await sbAll('employees?select=emp_id,name,position,dept,status&order=emp_id');
  const att = await sbAll('attendance?select=emp_id,action,work_time,status,dist_m&work_date=eq.' + date + '&order=id');
  const map = {};
  att.forEach((a) => { (map[a.emp_id] = map[a.emp_id] || {})[a.action] = a; });
  // รวมคนที่ถูกระงับภายหลังแต่มีการลงเวลาในวันนั้น เพื่อให้รายงานย้อนหลังครบ
  const emps = all.filter((e) => e.status === 'active' || map[e.emp_id]);
  const rows = emps.map((e) => {
    const i = (map[e.emp_id] || {})['เข้า'], o = (map[e.emp_id] || {})['ออก'];
    return {
      empId: e.emp_id, name: e.name, position: e.position, dept: e.dept,
      inTime: i ? i.work_time : '', inStatus: i ? i.status : '', inDist: i ? i.dist_m : null,
      outTime: o ? o.work_time : '', outStatus: o ? o.status : '', outDist: o ? o.dist_m : null
    };
  });
  return { ok: true, date, today: bkk().date, rows };
});

const adminListEmployees = (empId, token) => asAdmin(empId, token, async () => {
  const rows = await sbAll('employees?select=emp_id,name,position,dept,role,status,pin_hash&order=emp_id');
  return {
    ok: true,
    rows: rows.map((e) => ({ empId: e.emp_id, name: e.name, position: e.position, dept: e.dept,
                             role: e.role, status: e.status, hasPin: !!e.pin_hash }))   // ไม่ส่งค่าแฮชออกไป
  };
});

const adminSaveEmployee = (empId, token, d, isNew) => asAdmin(empId, token, async (me) => {
  d = d || {};
  const id = clean(d.empId);
  const rec = {
    name: clean(d.name), position: clean(d.position), dept: clean(d.dept),
    role: d.role === 'admin' ? 'admin' : 'user',
    status: d.status === 'inactive' ? 'inactive' : 'active'
  };
  if (!/^[A-Za-z0-9_-]{1,20}$/.test(id)) return { ok: false, msg: 'รหัสบุคลากรใช้ได้เฉพาะ A–Z, 0–9, - และ _ ไม่เกิน 20 ตัว' };
  if (!rec.name || rec.name.length > 120) return { ok: false, msg: 'กรุณากรอกชื่อ-สกุล (ไม่เกิน 120 ตัวอักษร)' };
  if (rec.position.length > 120 || rec.dept.length > 120) return { ok: false, msg: 'ตำแหน่ง/กลุ่มงานยาวเกินไป' };
  if (id === me.empId && (rec.role !== 'admin' || rec.status !== 'active')) {
    return { ok: false, msg: 'ไม่สามารถถอดสิทธิ์แอดมินหรือระงับบัญชีของตัวเองได้' };
  }

  if (isNew) {
    const res = await sb('POST', 'employees', Object.assign({ emp_id: id }, rec), { Prefer: 'return=minimal' });
    if (res.code === 409 && res.data && res.data.code === '23505') return { ok: false, msg: 'รหัสบุคลากร "' + id + '" มีอยู่แล้ว' };
    check(res);
    log(me.empId, 'admin-add', 'เพิ่มบุคลากร ' + id + ' ' + rec.name);
  } else {
    rec.updated_at = new Date().toISOString();
    const out = check(await sb('PATCH', 'employees?emp_id=eq.' + enc(id), rec, { Prefer: 'return=representation' }));
    if (!out || !out.length) return { ok: false, msg: 'ไม่พบรหัสบุคลากร "' + id + '"' };
    log(me.empId, 'admin-edit', 'แก้ไขบุคลากร ' + id + ' (' + rec.role + ', ' + rec.status + ')');
  }
  return { ok: true, msg: 'บันทึกข้อมูล ' + rec.name + ' เรียบร้อยแล้ว' };
});

const adminSetPin = (empId, token, targetId, pin) => asAdmin(empId, token, async (me) => {
  targetId = clean(targetId);
  pin = clean(pin);
  if (!/^\d{4,6}$/.test(pin)) return { ok: false, msg: 'PIN ต้องเป็นตัวเลข 4–6 หลัก' };
  const emp = await findEmployee(targetId);
  if (!emp) return { ok: false, msg: 'ไม่พบรหัสบุคลากร "' + targetId + '"' };
  await savePin(targetId, pin);
  log(me.empId, 'set-pin', 'ตั้ง PIN ใหม่ให้ ' + targetId);
  return { ok: true, msg: 'ตั้ง PIN ให้ ' + emp.name + ' เรียบร้อยแล้ว — แจ้ง PIN ให้เจ้าตัวโดยตรง' };
});

const adminReport = (empId, token, ym) => asAdmin(empId, token, async () => {
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(ym || '')) return { ok: false, msg: 'รูปแบบเดือนไม่ถูกต้อง' };
  const att = await sbAll('attendance?select=emp_id,work_date,action,status&work_date=gte.' + ym + '-01' +
                          '&work_date=lt.' + nextMonth(ym) + '&order=id');
  const byEmp = {};
  att.forEach((r) => {
    const days = byEmp[r.emp_id] = byEmp[r.emp_id] || {};
    const d = days[r.work_date] = days[r.work_date] || { in: false, out: false, late: false, early: false };
    if (r.action === 'เข้า') { d.in = true; if (r.status === 'มาสาย') d.late = true; }
    if (r.action === 'ออก') { d.out = true; if (r.status === 'ออกก่อนเวลา') d.early = true; }
  });
  const emps = await sbAll('employees?select=emp_id,name,position,dept&status=eq.active&order=emp_id');
  const rows = emps.map((e) => {
    const days = Object.values(byEmp[e.emp_id] || {});
    return {
      empId: e.emp_id, name: e.name, position: e.position, dept: e.dept,
      present: days.filter((d) => d.in).length,
      late: days.filter((d) => d.late).length,
      early: days.filter((d) => d.early).length,
      noOut: days.filter((d) => d.in && !d.out).length
    };
  });
  return { ok: true, ym, rows };
});

const adminExportMonth = (empId, token, ym) => asAdmin(empId, token, async () => {
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(ym || '')) return { ok: false, msg: 'รูปแบบเดือนไม่ถูกต้อง' };
  const rows = await sbAll('attendance?select=work_date,work_time,emp_id,emp_name,action,status,lat,lng,dist_m,in_area,accuracy_m' +
                           '&work_date=gte.' + ym + '-01&work_date=lt.' + nextMonth(ym) + '&order=ts');
  return { ok: true, ym, rows };
});

const adminGetSettings = (empId, token) => asAdmin(empId, token, async () => {
  const s = {};
  (await sbGet('settings?select=key,value&order=key')).forEach((r) => { s[r.key] = r.value; });
  return { ok: true, settings: s };
});

const adminSaveSettings = (empId, token, d) => asAdmin(empId, token, async (me) => {
  d = d || {};
  const v = {
    SITE_LAT: clean(d.SITE_LAT), SITE_LNG: clean(d.SITE_LNG), RADIUS_M: clean(d.RADIUS_M),
    WORK_START: clean(d.WORK_START), WORK_END: clean(d.WORK_END),
    ALLOW_OUTSIDE: clean(d.ALLOW_OUTSIDE).toUpperCase() === 'YES' ? 'YES' : 'NO'
  };
  const lat = Number(v.SITE_LAT), lng = Number(v.SITE_LNG), rad = Number(v.RADIUS_M);
  const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/;
  if (!v.SITE_LAT || !isFinite(lat) || lat < -90 || lat > 90) return { ok: false, msg: 'ละติจูดไม่ถูกต้อง' };
  if (!v.SITE_LNG || !isFinite(lng) || lng < -180 || lng > 180) return { ok: false, msg: 'ลองจิจูดไม่ถูกต้อง' };
  if (!/^\d+$/.test(v.RADIUS_M) || rad < 10 || rad > 5000) return { ok: false, msg: 'รัศมีต้องเป็นจำนวนเต็ม 10–5000 เมตร' };
  if (!HHMM.test(v.WORK_START)) return { ok: false, msg: 'เวลาเริ่มงานต้องเป็นรูปแบบ HH:MM เช่น 08:30' };
  if (!HHMM.test(v.WORK_END)) return { ok: false, msg: 'เวลาเลิกงานต้องเป็นรูปแบบ HH:MM เช่น 16:30' };

  check(await sb('POST', 'settings?on_conflict=key', Object.keys(v).map((k) => ({ key: k, value: v[k] })),
                 { Prefer: 'resolution=merge-duplicates,return=minimal' }));
  settingsCache = null;
  log(me.empId, 'admin-settings', JSON.stringify(v));
  return { ok: true, msg: 'บันทึกการตั้งค่าเรียบร้อยแล้ว มีผลทันที' };
});

const adminLogs = (empId, token) => asAdmin(empId, token, async () => {
  const rows = await sbGet('logs?select=ts,emp_id,action,result&order=ts.desc&limit=150');
  return {
    ok: true,
    rows: rows.map((r) => {
      const t = bkk(new Date(r.ts));
      return { ts: t.date + ' ' + t.time, empId: r.emp_id, action: r.action, result: r.result };
    })
  };
});

/* ============================================================
 * 4) ติดต่อ Supabase (REST API)
 * ============================================================ */

async function sb(method, pathQuery, body, headers) {
  const h = Object.assign({ apikey: SUPABASE_KEY }, headers || {});
  // คีย์แบบใหม่ (sb_secret_...) ใช้แค่ apikey ส่วนคีย์แบบเดิม (JWT) ต้องส่ง Authorization ด้วย
  if (!SUPABASE_KEY.startsWith('sb_')) h.Authorization = 'Bearer ' + SUPABASE_KEY;
  if (body !== undefined) h['Content-Type'] = 'application/json';
  const res = await fetch(SUPABASE_URL + '/rest/v1/' + pathQuery, {
    method, headers: h,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(15000)
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
  return { code: res.status, data };
}

function check(res) {
  if (res.code >= 300) {
    const d = res.data || {};
    throw new Error('ฐานข้อมูลตอบกลับ ' + res.code + ': ' + (d.message || JSON.stringify(d)));
  }
  return res.data;
}

async function sbGet(pathQuery) { return check(await sb('GET', pathQuery)); }

/** ดึงทุกแถว (Supabase ส่งได้ครั้งละ 1000 แถว) — path ต้องมี order= เพื่อแบ่งหน้าได้ถูกต้อง */
async function sbAll(pathQuery) {
  const PAGE = 1000;
  let out = [];
  for (let offset = 0; ; offset += PAGE) {
    const rows = await sbGet(pathQuery + '&limit=' + PAGE + '&offset=' + offset);
    out = out.concat(rows);
    if (rows.length < PAGE) return out;
  }
}

/* ============================================================
 * 5) ฟังก์ชันช่วยเหลือ
 * ============================================================ */

async function findEmployee(empId) {
  empId = clean(empId);
  if (!empId) return null;
  const rows = await sbGet('employees?select=*&emp_id=eq.' + enc(empId) + '&limit=1');
  if (!rows.length) return null;
  const e = rows[0];
  return { empId: e.emp_id, name: e.name, position: e.position, dept: e.dept,
           role: e.role, status: e.status, pinHash: e.pin_hash || '' };
}

async function savePin(empId, pin) {
  check(await sb('PATCH', 'employees?emp_id=eq.' + enc(empId),
                 { pin_hash: hashPin(empId, pin), updated_at: new Date().toISOString() },
                 { Prefer: 'return=minimal' }));
  failCount.delete(empId);   // ปลดล็อกการใส่ PIN ผิด
}

let settingsCache = null;
async function getSettings() {
  if (settingsCache && settingsCache.exp > Date.now()) return settingsCache.s;
  const s = {};
  (await sbGet('settings?select=key,value')).forEach((r) => { s[r.key] = String(r.value).trim(); });
  settingsCache = { s, exp: Date.now() + SETTINGS_CACHE_MS };
  return s;
}

function hashPin(empId, pin) {
  return crypto.createHash('sha256').update(empId + ':' + pin + ':' + PIN_SALT, 'utf8').digest('hex');
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/** ระยะทางระหว่างพิกัดสองจุด (เมตร) — สูตร Haversine */
function haversine(lat1, lng1, lat2, lng2) {
  const R = 6371000, rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad, dLng = (lng2 - lng1) * rad;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

const bkkFmt = new Intl.DateTimeFormat('en-CA', {
  timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'
});
/** วันที่/เวลาตามเวลาไทย */
function bkk(d) {
  const p = {};
  bkkFmt.formatToParts(d || new Date()).forEach((x) => { p[x.type] = x.value; });
  return { date: p.year + '-' + p.month + '-' + p.day, time: p.hour + ':' + p.minute + ':' + p.second };
}

function nextMonth(ym) {
  const y = Number(ym.slice(0, 4)), m = Number(ym.slice(5, 7));
  return m === 12 ? (y + 1) + '-01-01' : y + '-' + String(m + 1).padStart(2, '0') + '-01';
}

function log(empId, action, result) {
  sb('POST', 'logs', { emp_id: empId, action, result }, { Prefer: 'return=minimal' })
    .catch((e) => console.error('log failed:', e.message));   // ไม่ให้ log ล้มแล้วพาระบบล้ม
}

function fail(empId, action, msg) {
  log(empId, action, 'ล้มเหลว: ' + msg);
  return { ok: false, msg };
}

function clean(v) { return String(v == null ? '' : v).trim(); }
function enc(v) { return encodeURIComponent(v); }

/* ============================================================
 * 6) เว็บเซิร์ฟเวอร์
 * ============================================================ */

const API = {
  login, clock, getHistory,
  adminDay, adminListEmployees, adminSaveEmployee, adminSetPin,
  adminReport, adminExportMonth, adminGetSettings, adminSaveSettings, adminLogs
};

const ipHits = new Map();   // ip -> { n, reset } — จำกัดจำนวนครั้งที่พยายามเข้าสู่ระบบต่อ IP
function ipLimited(ip) {
  const now = Date.now();
  const h = ipHits.get(ip);
  if (!h || h.reset < now) { ipHits.set(ip, { n: 1, reset: now + LOCK_MS }); return false; }
  h.n++;
  return h.n > IP_MAX_LOGIN;
}
setInterval(() => {   // ล้างข้อมูลที่หมดอายุ
  const now = Date.now();
  for (const [k, v] of ipHits) if (v.reset < now) ipHits.delete(k);
  for (const [k, v] of failCount) if (v.until < now) failCount.delete(k);
}, 10 * 60 * 1000).unref();

const app = express();
app.set('trust proxy', 1);   // Render อยู่หลัง proxy
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'geolocation=(self), camera=(), microphone=()'
  });
  next();
});
app.use(express.json({ limit: '50kb' }));

app.post('/api/:fn', async (req, res) => {
  const fn = Object.prototype.hasOwnProperty.call(API, req.params.fn) ? API[req.params.fn] : null;
  if (!fn) return res.status(404).json({ ok: false, msg: 'ไม่พบคำสั่งนี้' });
  if (req.params.fn === 'login' && ipLimited(req.ip)) {
    return res.status(429).json({ ok: false, msg: 'พยายามเข้าสู่ระบบบ่อยเกินไป กรุณารอ 15 นาที' });
  }
  const args = Array.isArray(req.body && req.body.args) ? req.body.args.slice(0, 8) : [];
  try {
    res.set('Cache-Control', 'no-store').json(await fn(...args));
  } catch (e) {
    console.error('[' + req.params.fn + ']', e);
    res.status(500).json({ ok: false, msg: 'ระบบขัดข้องชั่วคราว กรุณาลองใหม่อีกครั้ง' });
  }
});

/** ใช้ตรวจว่าเซิร์ฟเวอร์ทำงาน + ปลุกฐานข้อมูล (ให้บริการ ping เรียกเป็นระยะ กัน Render/Supabase หลับ) */
app.get('/healthz', async (req, res) => {
  try {
    await sbGet('settings?select=key&limit=1');
    res.set('Cache-Control', 'no-store').json({ ok: true, time: bkk() });
  } catch (e) {
    console.error('[healthz]', e.message);
    res.status(503).json({ ok: false });
  }
});

app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: 0 }));

/** ตั้ง PIN แอดมินคนแรก / กรณีฉุกเฉิน — ทำเฉพาะเมื่อบัญชีนั้นยังไม่มี PIN */
async function initAdmin() {
  const v = clean(process.env.INIT_ADMIN);
  if (!v) return;
  const [id, pin] = v.split(':').map(clean);
  if (!id || !/^\d{4,6}$/.test(pin || '')) { console.warn('⚠ INIT_ADMIN ต้องเป็นรูปแบบ รหัส:PIN เช่น S001:123456'); return; }
  try {
    const emp = await findEmployee(id);
    if (!emp) return console.warn('⚠ INIT_ADMIN: ไม่พบรหัส ' + id + ' ในตาราง employees');
    if (emp.role !== 'admin') return console.warn('⚠ INIT_ADMIN: ' + id + ' ไม่ใช่ admin');
    if (emp.pinHash) return console.log('INIT_ADMIN: ' + id + ' มี PIN อยู่แล้ว — ไม่เปลี่ยน (ลบ INIT_ADMIN ออกได้เลย)');
    await savePin(id, pin);
    log(id, 'set-pin', 'ตั้ง PIN จาก INIT_ADMIN');
    console.log('✅ INIT_ADMIN: ตั้ง PIN ให้ ' + emp.name + ' แล้ว — ลบตัวแปร INIT_ADMIN ออกจาก Render ได้เลย');
  } catch (e) {
    console.error('INIT_ADMIN ล้มเหลว:', e.message);
  }
}

if (require.main === module) {
  app.listen(PORT, () => {
    console.log('ระบบลงเวลา วก.กันตัง พร้อมใช้งานที่พอร์ต ' + PORT);
    initAdmin();
  });
}

module.exports = { app, API, hashPin, dayToken, bkk, nextMonth };
