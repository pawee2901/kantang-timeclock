-- ============================================================
-- ระบบลงเวลาปฏิบัติงานออนไลน์ — วิทยาลัยการอาชีพกันตัง
-- โครงสร้างฐานข้อมูล Supabase (PostgreSQL)
--
-- วิธีใช้: Supabase Dashboard → SQL Editor → New query
--          วางไฟล์นี้ทั้งไฟล์ → กด Run (รันซ้ำได้ ไม่ทำให้ข้อมูลหาย)
-- ============================================================

-- 1) บุคลากร
create table if not exists public.employees (
  emp_id      text primary key,                       -- รหัสบุคลากร
  name        text not null,                          -- ชื่อ-สกุล
  position    text not null default '',               -- ตำแหน่ง
  dept        text not null default '',               -- กลุ่มงาน
  role        text not null default 'user'   check (role   in ('admin', 'user')),
  status      text not null default 'active' check (status in ('active', 'inactive')),
  pin_hash    text,                                   -- แฮช PIN (ห้ามแก้เอง ตั้งผ่านหน้าแอดมินเท่านั้น)
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- 2) การลงเวลา
create table if not exists public.attendance (
  id          bigint generated always as identity primary key,
  ts          timestamptz not null default now(),     -- เวลาที่บันทึกจริง
  work_date   date not null,                          -- วันที่ (เวลาไทย)
  work_time   time not null,                          -- เวลา (เวลาไทย)
  emp_id      text not null references public.employees (emp_id) on update cascade,
  emp_name    text not null,
  action      text not null check (action in ('เข้า', 'ออก')),
  status      text not null,                          -- ปกติ / มาสาย / ออกก่อนเวลา
  lat         double precision,
  lng         double precision,
  dist_m      integer,                                -- ระยะห่างจากวิทยาลัย (เมตร)
  in_area     boolean,
  accuracy_m  integer,                                -- ความแม่นยำ GPS (เมตร)
  -- กันลงเวลาซ้ำ: 1 คน ลงเวลา "เข้า" และ "ออก" ได้อย่างละ 1 ครั้งต่อวัน
  constraint attendance_once_per_day unique (work_date, emp_id, action)
);
create index if not exists attendance_emp_ts_idx on public.attendance (emp_id, ts desc);

-- 3) ค่าตั้งค่าระบบ
create table if not exists public.settings (
  key          text primary key,
  value        text not null,
  description  text not null default ''
);
insert into public.settings (key, value, description) values
  ('SITE_LAT',      '7.354011',  'ละติจูดของวิทยาลัย'),
  ('SITE_LNG',      '99.534258', 'ลองจิจูดของวิทยาลัย'),
  ('RADIUS_M',      '300',       'รัศมีพื้นที่ที่อนุญาต (เมตร)'),
  ('WORK_START',    '08:30',     'เวลาเริ่มงาน — ลงเวลาเข้าหลังจากนี้ = มาสาย'),
  ('WORK_END',      '16:30',     'เวลาเลิกงาน — ลงเวลาออกก่อนนี้ = ออกก่อนเวลา'),
  ('ALLOW_OUTSIDE', 'NO',        'YES = ยอมให้ลงเวลานอกพื้นที่ได้ (ใช้เฉพาะตอนทดสอบ)')
on conflict (key) do nothing;

-- 4) บันทึกเหตุการณ์ (รวมที่ล้มเหลว)
create table if not exists public.logs (
  id      bigint generated always as identity primary key,
  ts      timestamptz not null default now(),
  emp_id  text,
  action  text,
  result  text
);
create index if not exists logs_ts_idx on public.logs (ts desc);

-- ============================================================
-- ความปลอดภัย: ปิดการเข้าถึงจากภายนอกทั้งหมด
-- เปิด RLS โดยไม่สร้าง policy = คีย์ anon/publishable อ่านเขียนไม่ได้เลย
-- มีเพียง Apps Script ที่ใช้ secret/service_role key เท่านั้นที่เข้าถึงได้
-- ============================================================
alter table public.employees  enable row level security;
alter table public.attendance enable row level security;
alter table public.settings   enable row level security;
alter table public.logs       enable row level security;

revoke all on public.employees, public.attendance, public.settings, public.logs from anon, authenticated;
