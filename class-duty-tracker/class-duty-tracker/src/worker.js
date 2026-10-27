const COOKIE = 'duty_session';
const SESSION_SECONDS = 60 * 60 * 24 * 7;
function thaiFixedHoliday(date) { const mmdd=date.slice(5); const fixed={ '01-01':'วันขึ้นปีใหม่','04-06':'วันจักรี','05-01':'วันแรงงานแห่งชาติ','05-04':'วันฉัตรมงคล','06-03':'วันเฉลิมพระชนมพรรษาสมเด็จพระราชินี','07-28':'วันเฉลิมพระชนมพรรษาพระบาทสมเด็จพระเจ้าอยู่หัว','08-12':'วันแม่แห่งชาติ','10-13':'วันนวมินทรมหาราช','10-23':'วันปิยมหาราช','12-05':'วันพ่อแห่งชาติ','12-10':'วันรัฐธรรมนูญ','12-31':'วันสิ้นปี'}; if(fixed[mmdd])return fixed[mmdd]; if(['04-13','04-14','04-15'].includes(mmdd))return 'เทศกาลสงกรานต์'; return null; }
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
const fail = (message, status = 400) => json({ error: message }, status);
const dateOk = d => typeof d === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(d) && !Number.isNaN(Date.parse(`${d}T00:00:00Z`));
const getCookie = (req, name) => (req.headers.get('Cookie') || '').split(';').map(x => x.trim()).find(x => x.startsWith(name + '='))?.slice(name.length + 1);
const bytesToHex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const randomHex = n => { const a = new Uint8Array(n); crypto.getRandomValues(a); return bytesToHex(a); };
async function passwordHash(password, saltHex) {
  const salt = Uint8Array.from(saltHex.match(/.{2}/g).map(x => parseInt(x, 16)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 210000, hash: 'SHA-256' }, key, 256);
  return bytesToHex(bits);
}
async function currentAdmin(req, env) {
  const token = getCookie(req, COOKIE);
  if (!token) return null;
  const row = await env.DB.prepare('SELECT a.id,a.username,a.display_name FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.id=? AND s.expires_at>? AND a.active=1').bind(token, Math.floor(Date.now()/1000)).first();
  return row || null;
}
async function audit(env, admin, action, type, id, before, after) {
  await env.DB.prepare('INSERT INTO audit_logs(admin_id,action,entity_type,entity_id,before_json,after_json) VALUES(?,?,?,?,?,?)')
    .bind(admin?.id || null, action, type, id == null ? null : String(id), before == null ? null : JSON.stringify(before), after == null ? null : JSON.stringify(after)).run();
}
async function body(req) { try { return await req.json(); } catch { return null; } }
function csvEscape(v) { const s = String(v ?? ''); return '"' + s.replace(/"/g, '""') + '"'; }
function csvResponse(rows, filename) {
  const csv = '\ufeff' + rows.map(row => row.map(csvEscape).join(',')).join('\r\n');
  return new Response(csv, { headers: { 'content-type': 'text/csv; charset=utf-8', 'content-disposition': `attachment; filename="${filename}"`, 'cache-control': 'no-store' } });
}
async function api(req, env, url) {
  const path = url.pathname;
  const method = req.method;
  if (method === 'GET' && path === '/api/health') return json({ ok: true, service: 'class-duty-tracker' });
  if (method === 'GET' && path === '/api/setup-status') {
    const { n } = await env.DB.prepare('SELECT COUNT(*) AS n FROM admins').first();
    return json({ setupRequired: n === 0 });
  }
  if (method === 'POST' && path === '/api/setup') {
    if (!env.BOOTSTRAP_SECRET) return fail('ยังไม่ได้ตั้งค่า BOOTSTRAP_SECRET ใน Cloudflare Worker Secrets', 503);
    const data = await body(req);
    if (!data || data.bootstrapSecret !== env.BOOTSTRAP_SECRET) return fail('รหัสติดตั้งไม่ถูกต้อง', 403);
    const { n } = await env.DB.prepare('SELECT COUNT(*) AS n FROM admins').first();
    if (n > 0) return fail('ระบบมีบัญชีแอดมินแล้ว ปิดการตั้งค่าเริ่มต้นแล้ว', 409);
    if (!/^[a-zA-Z0-9_.-]{4,40}$/.test(data.username || '') || (data.password || '').length < 12 || (data.displayName || '').trim().length < 2) return fail('ชื่อผู้ใช้ 4–40 ตัวอักษร และรหัสผ่านอย่างน้อย 12 ตัวอักษร พร้อมชื่อแสดงผล');
    const salt = randomHex(16), hash = await passwordHash(data.password, salt);
    await env.DB.prepare('INSERT INTO admins(username,display_name,password_hash,password_salt) VALUES(?,?,?,?)').bind(data.username, data.displayName.trim(), hash, salt).run();
    return json({ ok: true, message: 'สร้างบัญชีแอดมินแล้ว กรุณาเข้าสู่ระบบ' }, 201);
  }
  if (method === 'POST' && path === '/api/login') {
    const data = await body(req);
    if (!data || typeof data.username !== 'string' || typeof data.password !== 'string') return fail('กรอกชื่อผู้ใช้และรหัสผ่าน');
    const admin = await env.DB.prepare('SELECT * FROM admins WHERE username=? COLLATE NOCASE AND active=1').bind(data.username.trim()).first();
    if (!admin) return fail('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 401);
    const check = await passwordHash(data.password, admin.password_salt);
    if (check !== admin.password_hash) return fail('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 401);
    const token = randomHex(32), expires = Math.floor(Date.now()/1000) + SESSION_SECONDS;
    await env.DB.prepare('INSERT INTO sessions(id,admin_id,expires_at) VALUES(?,?,?)').bind(token, admin.id, expires).run();
    return json({ ok: true, admin: { id: admin.id, username: admin.username, displayName: admin.display_name } }, 200, { 'set-cookie': `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_SECONDS}` });
  }
  if (method === 'POST' && path === '/api/logout') {
    const token = getCookie(req, COOKIE); if (token) await env.DB.prepare('DELETE FROM sessions WHERE id=?').bind(token).run();
    return json({ ok: true }, 200, { 'set-cookie': `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0` });
  }
  const admin = await currentAdmin(req, env);
  if (method === 'GET' && path === '/api/me') return json({ admin: admin || null });

  if (method === 'GET' && path === '/api/students') {
    const includeInactive = url.searchParams.get('all') === '1' && !!admin;
    const rows = await env.DB.prepare(`SELECT id,roll_number,full_name,class_name,active,created_at,updated_at FROM students ${includeInactive ? '' : 'WHERE active=1'} ORDER BY CAST(roll_number AS INTEGER), roll_number, full_name`).all();
    return json({ students: rows.results });
  }
  if (method === 'POST' && path === '/api/students') {
    if (!admin) return fail('ต้องเข้าสู่ระบบแอดมินก่อน', 401);
    const d = await body(req); if (!d || !String(d.rollNumber||'').trim() || !String(d.fullName||'').trim() || !String(d.className||'').trim()) return fail('กรุณากรอกเลขที่ ชื่อ–สกุล และชั้นเรียนให้ครบ');
    const result = await env.DB.prepare('INSERT INTO students(roll_number,full_name,class_name) VALUES(?,?,?)').bind(String(d.rollNumber).trim(), String(d.fullName).trim(), String(d.className).trim()).run();
    const student = await env.DB.prepare('SELECT * FROM students WHERE id=?').bind(result.meta.last_row_id).first();
    await audit(env, admin, 'create', 'student', student.id, null, student);
    return json({ student }, 201);
  }
  const studentMatch = path.match(/^\/api\/students\/(\d+)$/);
  if (studentMatch && ['PATCH','DELETE'].includes(method)) {
    if (!admin) return fail('ต้องเข้าสู่ระบบแอดมินก่อน', 401);
    const id = Number(studentMatch[1]); const before = await env.DB.prepare('SELECT * FROM students WHERE id=?').bind(id).first(); if (!before) return fail('ไม่พบรายชื่อนักเรียน',404);
    if (method === 'DELETE') {
      await env.DB.prepare('UPDATE students SET active=0,updated_at=datetime(\'now\') WHERE id=?').bind(id).run();
      const after = await env.DB.prepare('SELECT * FROM students WHERE id=?').bind(id).first(); await audit(env,admin,'deactivate','student',id,before,after); return json({student:after});
    }
    const d = await body(req); if (!d) return fail('ข้อมูลไม่ถูกต้อง');
    const roll = String(d.rollNumber ?? before.roll_number).trim(), name = String(d.fullName ?? before.full_name).trim(), cls = String(d.className ?? before.class_name).trim();
    if (!roll || !name || !cls) return fail('ห้ามเว้นเลขที่ ชื่อ–สกุล หรือชั้นเรียน');
    await env.DB.prepare('UPDATE students SET roll_number=?,full_name=?,class_name=?,active=?,updated_at=datetime(\'now\') WHERE id=?').bind(roll,name,cls,d.active === false ? 0 : 1,id).run();
    const after = await env.DB.prepare('SELECT * FROM students WHERE id=?').bind(id).first(); await audit(env,admin,'update','student',id,before,after); return json({student:after});
  }
  if (method === 'GET' && path === '/api/holidays') {
    const start = url.searchParams.get('start') || '2000-01-01', end = url.searchParams.get('end') || '2100-12-31';
    const rows = await env.DB.prepare('SELECT day_date,kind,title FROM school_days WHERE day_date BETWEEN ? AND ? ORDER BY day_date').bind(start,end).all(); const map=new Map(rows.results.map(x=>[x.day_date,x])); const a=new Date(start+'T00:00:00Z'), b=new Date(end+'T00:00:00Z'); for(let dt=new Date(a);dt<=b;dt.setUTCDate(dt.getUTCDate()+1)){const d=dt.toISOString().slice(0,10),name=thaiFixedHoliday(d);if(name&&!map.has(d))map.set(d,{day_date:d,kind:'holiday',title:name,automatic:true});} return json({days:[...map.values()].sort((x,y)=>x.day_date.localeCompare(y.day_date))});
  }
  if (method === 'POST' && path === '/api/holidays') {
    if (!admin) return fail('ต้องเข้าสู่ระบบแอดมินก่อน',401);
    const d = await body(req); if (!d || !dateOk(d.date) || !['holiday','school_day'].includes(d.kind) || !String(d.title||'').trim()) return fail('กรุณาระบุวันที่ ประเภทวัน และชื่อวันให้ถูกต้อง');
    const before = await env.DB.prepare('SELECT * FROM school_days WHERE day_date=?').bind(d.date).first();
    await env.DB.prepare('INSERT INTO school_days(day_date,kind,title,updated_by,updated_at) VALUES(?,?,?,?,datetime(\'now\')) ON CONFLICT(day_date) DO UPDATE SET kind=excluded.kind,title=excluded.title,updated_by=excluded.updated_by,updated_at=datetime(\'now\')').bind(d.date,d.kind,String(d.title).trim(),admin.id).run();
    const after = await env.DB.prepare('SELECT * FROM school_days WHERE day_date=?').bind(d.date).first(); await audit(env,admin,'upsert','school_day',d.date,before,after); return json({day:after});
  }
  if (method === 'DELETE' && path.startsWith('/api/holidays/')) {
    if (!admin) return fail('ต้องเข้าสู่ระบบแอดมินก่อน',401);
    const date = decodeURIComponent(path.slice('/api/holidays/'.length)); if (!dateOk(date)) return fail('วันที่ไม่ถูกต้อง');
    const before = await env.DB.prepare('SELECT * FROM school_days WHERE day_date=?').bind(date).first(); await env.DB.prepare('DELETE FROM school_days WHERE day_date=?').bind(date).run(); await audit(env,admin,'delete','school_day',date,before,null); return json({ok:true});
  }
  if (method === 'GET' && path === '/api/day') {
    const date = url.searchParams.get('date'); if (!dateOk(date)) return fail('กรุณาระบุวันที่รูปแบบ YYYY-MM-DD');
    const record = await env.DB.prepare('SELECT * FROM daily_records WHERE day_date=?').bind(date).first();
    const students = await env.DB.prepare(`SELECT s.id,s.roll_number,s.full_name,s.class_name,s.active,e.status,e.note FROM students s LEFT JOIN duty_entries e ON e.student_id=s.id AND e.day_date=? WHERE s.active=1 OR e.id IS NOT NULL ORDER BY CAST(s.roll_number AS INTEGER),s.roll_number,s.full_name`).bind(date).all();
    const schoolDay = await env.DB.prepare('SELECT * FROM school_days WHERE day_date=?').bind(date).first() || (thaiFixedHoliday(date) ? {day_date:date,kind:'holiday',title:thaiFixedHoliday(date),automatic:true} : null);
    return json({date,record,schoolDay,students:students.results.map(s=>({...s,status:record ? (s.status || 'not_done') : null}))});
  }
  if (method === 'PUT' && path === '/api/day') {
    if (!admin) return fail('ต้องเข้าสู่ระบบแอดมินก่อน',401);
    const d = await body(req); if (!d || !dateOk(d.date) || !Array.isArray(d.entries)) return fail('ข้อมูลวันที่หรือรายการไม่ถูกต้อง');
    const existing = await env.DB.prepare('SELECT * FROM daily_records WHERE day_date=?').bind(d.date).first();
    const validIds = await env.DB.prepare('SELECT id FROM students WHERE active=1 UNION SELECT student_id AS id FROM duty_entries WHERE day_date=?').bind(d.date).all(); const allowed = new Set(validIds.results.map(x=>x.id));
    for (const e of d.entries) if (!allowed.has(Number(e.studentId)) || !['done','not_done','excused'].includes(e.status)) return fail('พบรายการนักเรียนหรือสถานะที่ไม่ถูกต้อง');
    await env.DB.prepare('INSERT INTO daily_records(day_date,saved_by,saved_at,confirmed) VALUES(?,?,datetime(\'now\'),?) ON CONFLICT(day_date) DO UPDATE SET saved_by=excluded.saved_by,saved_at=datetime(\'now\'),confirmed=excluded.confirmed').bind(d.date,admin.id,d.confirmed ? 1 : 0).run();
    for (const e of d.entries) {
      const before = await env.DB.prepare('SELECT * FROM duty_entries WHERE day_date=? AND student_id=?').bind(d.date,Number(e.studentId)).first();
      await env.DB.prepare('INSERT INTO duty_entries(day_date,student_id,status,note,updated_by,updated_at) VALUES(?,?,?,?,?,datetime(\'now\')) ON CONFLICT(day_date,student_id) DO UPDATE SET status=excluded.status,note=excluded.note,updated_by=excluded.updated_by,updated_at=datetime(\'now\')').bind(d.date,Number(e.studentId),e.status,String(e.note||'').slice(0,500),admin.id).run();
      const after = await env.DB.prepare('SELECT * FROM duty_entries WHERE day_date=? AND student_id=?').bind(d.date,Number(e.studentId)).first();
      if (JSON.stringify(before) !== JSON.stringify(after)) await audit(env,admin,before?'update':'create','duty_entry',`${d.date}:${e.studentId}`,before,after);
    }
    await audit(env,admin,existing?'update':'create','daily_record',d.date,existing,{date:d.date,confirmed:!!d.confirmed,entryCount:d.entries.length});
    return json({ok:true,date:d.date,savedAt:new Date().toISOString()});
  }
  if (method === 'GET' && path === '/api/summary') {
    const month = url.searchParams.get('month') || new Date().toISOString().slice(0,7); if (!/^\d{4}-\d{2}$/.test(month)) return fail('เดือนต้องเป็น YYYY-MM');
    const start = `${month}-01`, end = `${month}-${new Date(Number(month.slice(0,4)),Number(month.slice(5,7)),0).getDate().toString().padStart(2,'0')}`;
    const counts = await env.DB.prepare(`SELECT COUNT(*) AS records, SUM(CASE WHEN e.status='done' THEN 1 ELSE 0 END) AS done, SUM(CASE WHEN e.status='not_done' THEN 1 ELSE 0 END) AS not_done, SUM(CASE WHEN e.status='excused' THEN 1 ELSE 0 END) AS excused FROM daily_records r LEFT JOIN duty_entries e ON e.day_date=r.day_date WHERE r.day_date BETWEEN ? AND ?`).bind(start,end).first();
    const days = await env.DB.prepare('SELECT day_date,confirmed,saved_at FROM daily_records WHERE day_date BETWEEN ? AND ? ORDER BY day_date DESC').bind(start,end).all();
    const studentStats = await env.DB.prepare(`SELECT s.id,s.roll_number,s.full_name,s.class_name, SUM(CASE WHEN e.status='done' THEN 1 ELSE 0 END) AS done, SUM(CASE WHEN e.status='not_done' THEN 1 ELSE 0 END) AS not_done, SUM(CASE WHEN e.status='excused' THEN 1 ELSE 0 END) AS excused, SUM(CASE WHEN e.status IN ('done','not_done') THEN 1 ELSE 0 END) AS eligible FROM students s LEFT JOIN duty_entries e ON e.student_id=s.id AND e.day_date BETWEEN ? AND ? WHERE s.active=1 GROUP BY s.id ORDER BY CAST(s.roll_number AS INTEGER),s.roll_number`).bind(start,end).all();
    const holidayRows = await env.DB.prepare('SELECT day_date,kind,title FROM school_days WHERE day_date BETWEEN ? AND ?').bind(start,end).all();
    const holidayMap = new Map(holidayRows.results.map(x=>[x.day_date,x]));
    let schoolDays=0, holidays=0; const daysInMonth = Number(end.slice(-2));
    for (let i=1;i<=daysInMonth;i++){const d=`${month}-${String(i).padStart(2,'0')}`,dt=new Date(`${d}T00:00:00Z`),dow=dt.getUTCDay(),override=holidayMap.get(d),autoHoliday=thaiFixedHoliday(d);if(override){if(override.kind==='school_day')schoolDays++;else holidays++;}else if(autoHoliday||dow===0||dow===6)holidays++;else schoolDays++;}
    const students = studentStats.results.map(s=>({...s,percent:s.eligible ? Math.round((s.done/s.eligible)*1000)/10 : 0})).sort((a,b)=>b.percent-a.percent || b.done-a.done || Number(a.roll_number)-Number(b.roll_number));
    return json({month,counts:{...counts,records:Number(counts.records||0),done:Number(counts.done||0),not_done:Number(counts.not_done||0),excused:Number(counts.excused||0)},schoolDays,holidays,days:days.results,students,holidayOverrides:[...holidayRows.results,...Array.from({length:daysInMonth},(_,i)=>{const d=`${month}-${String(i+1).padStart(2,'0')}`;return !holidayMap.has(d)&&thaiFixedHoliday(d)?{day_date:d,kind:'holiday',title:thaiFixedHoliday(d),automatic:true}:null}).filter(Boolean)]});
  }
  if (method === 'GET' && path === '/api/export.csv') {
    const month = url.searchParams.get('month') || new Date().toISOString().slice(0,7); if (!/^\d{4}-\d{2}$/.test(month)) return fail('เดือนต้องเป็น YYYY-MM');
    const rows = await env.DB.prepare(`SELECT e.day_date,s.roll_number,s.full_name,s.class_name,CASE e.status WHEN 'done' THEN 'ทำเวรแล้ว' WHEN 'not_done' THEN 'ไม่ทำเวร' ELSE 'ลา/ได้รับยกเว้น' END AS status,e.note FROM duty_entries e JOIN students s ON s.id=e.student_id WHERE e.day_date LIKE ? ORDER BY e.day_date,CAST(s.roll_number AS INTEGER)`).bind(`${month}-%`).all();
    return csvResponse([['วันที่','เลขที่','ชื่อ-สกุล','ชั้นเรียน','สถานะ','หมายเหตุ'],...rows.results.map(r=>[r.day_date,r.roll_number,r.full_name,r.class_name,r.status,r.note])],`duty-report-${month}.csv`);
  }
  if (method === 'GET' && path === '/api/backup.json') {
    if (!admin) return fail('ต้องเข้าสู่ระบบแอดมินก่อน',401);
    const [students,schoolDays,dailyRecords,dutyEntries,auditLogs] = await Promise.all([
      env.DB.prepare('SELECT * FROM students').all(),env.DB.prepare('SELECT * FROM school_days').all(),env.DB.prepare('SELECT * FROM daily_records').all(),env.DB.prepare('SELECT * FROM duty_entries').all(),env.DB.prepare('SELECT * FROM audit_logs ORDER BY id').all()
    ]);
    return new Response(JSON.stringify({format:'class-duty-tracker-backup-v1',createdAt:new Date().toISOString(),students:students.results,schoolDays:schoolDays.results,dailyRecords:dailyRecords.results,dutyEntries:dutyEntries.results,auditLogs:auditLogs.results},null,2),{headers:{'content-type':'application/json; charset=utf-8','content-disposition':`attachment; filename="duty-backup-${new Date().toISOString().slice(0,10)}.json"`,'cache-control':'no-store'}});
  }
  if (method === 'GET' && path === '/api/audit') {
    if (!admin) return fail('ต้องเข้าสู่ระบบแอดมินก่อน',401);
    const rows = await env.DB.prepare('SELECT l.id,l.action,l.entity_type,l.entity_id,l.before_json,l.after_json,l.created_at,a.username,a.display_name FROM audit_logs l LEFT JOIN admins a ON a.id=l.admin_id ORDER BY l.id DESC LIMIT 300').all(); return json({logs:rows.results});
  }
  if (method === 'GET' && path === '/api/admins') {
    if (!admin) return fail('ต้องเข้าสู่ระบบแอดมินก่อน',401);
    const rows = await env.DB.prepare('SELECT id,username,display_name,active,created_at FROM admins ORDER BY id').all(); return json({admins:rows.results});
  }
  if (method === 'POST' && path === '/api/admins') {
    if (!admin) return fail('ต้องเข้าสู่ระบบแอดมินก่อน',401);
    const d=await body(req); if(!d || !/^[a-zA-Z0-9_.-]{4,40}$/.test(d.username||'') || (d.password||'').length<12 || String(d.displayName||'').trim().length<2) return fail('ชื่อผู้ใช้ 4–40 ตัว รหัสผ่านอย่างน้อย 12 ตัว และชื่อแสดงผลอย่างน้อย 2 ตัว');
    const salt=randomHex(16),hash=await passwordHash(d.password,salt);
    try { const r=await env.DB.prepare('INSERT INTO admins(username,display_name,password_hash,password_salt) VALUES(?,?,?,?)').bind(d.username,String(d.displayName).trim(),hash,salt).run(); const after=await env.DB.prepare('SELECT id,username,display_name,active,created_at FROM admins WHERE id=?').bind(r.meta.last_row_id).first(); await audit(env,admin,'create','admin',after.id,null,after); return json({admin:after},201); } catch { return fail('ชื่อผู้ใช้นี้ถูกใช้แล้ว',409); }
  }
  const adminMatch=path.match(/^\/api\/admins\/(\d+)$/);
  if(adminMatch && method==='PATCH') {
    if(!admin) return fail('ต้องเข้าสู่ระบบแอดมินก่อน',401); const id=Number(adminMatch[1]); if(id===admin.id) return fail('ไม่สามารถปิดใช้งานบัญชีที่กำลังเข้าสู่ระบบอยู่');
    const before=await env.DB.prepare('SELECT id,username,display_name,active,created_at FROM admins WHERE id=?').bind(id).first(); if(!before)return fail('ไม่พบบัญชีแอดมิน',404); const d=await body(req); if(!d || typeof d.active!=='boolean')return fail('ข้อมูลไม่ถูกต้อง');
    await env.DB.prepare('UPDATE admins SET active=? WHERE id=?').bind(d.active?1:0,id).run(); if(!d.active) await env.DB.prepare('DELETE FROM sessions WHERE admin_id=?').bind(id).run(); const after=await env.DB.prepare('SELECT id,username,display_name,active,created_at FROM admins WHERE id=?').bind(id).first(); await audit(env,admin,'update','admin',id,before,after); return json({admin:after});
  }
  if (method === 'GET' && path === '/api/settings') {
    const rows = await env.DB.prepare('SELECT key,value FROM settings').all(); return json({settings:Object.fromEntries(rows.results.map(x=>[x.key,x.value]))});
  }
  if (method === 'PUT' && path === '/api/settings') {
    if (!admin) return fail('ต้องเข้าสู่ระบบแอดมินก่อน',401); const d=await body(req); if(!d || typeof d.class_label!=='string' || !d.class_label.trim()) return fail('กรุณาระบุชื่อห้องเรียน');
    const before=await env.DB.prepare("SELECT value FROM settings WHERE key='class_label'").first(); await env.DB.prepare("INSERT INTO settings(key,value,updated_at) VALUES('class_label',?,datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=datetime('now')").bind(d.class_label.trim().slice(0,100)).run(); await audit(env,admin,'update','setting','class_label',before,{value:d.class_label.trim()}); return json({ok:true});
  }
  return fail('ไม่พบ API ที่ร้องขอ',404);
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try { return await api(request, env, url); }
      catch (e) { console.error('API error', e); return json({error:'เกิดข้อผิดพลาดภายในระบบ',detail:env.ENVIRONMENT==='development'?String(e):undefined},500); }
    }
    return env.ASSETS.fetch(request);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async()=>{
      await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(Math.floor(Date.now()/1000)).run();
      if (!env.BACKUPS) return;
      const [students,schoolDays,dailyRecords,dutyEntries,auditLogs] = await Promise.all([env.DB.prepare('SELECT * FROM students').all(),env.DB.prepare('SELECT * FROM school_days').all(),env.DB.prepare('SELECT * FROM daily_records').all(),env.DB.prepare('SELECT * FROM duty_entries').all(),env.DB.prepare('SELECT * FROM audit_logs ORDER BY id').all()]);
      const payload={format:'class-duty-tracker-backup-v1',createdAt:new Date().toISOString(),students:students.results,schoolDays:schoolDays.results,dailyRecords:dailyRecords.results,dutyEntries:dutyEntries.results,auditLogs:auditLogs.results};
      const key='daily/'+new Date().toISOString().slice(0,10)+'.json'; await env.BACKUPS.put(key,JSON.stringify(payload),{httpMetadata:{contentType:'application/json'}});
    })());
  }
};
