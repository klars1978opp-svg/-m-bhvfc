require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const db = require('./db');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET || (isProd ? null : 'dev-only-secret-change-me');
if (!sessionSecret) throw new Error('SESSION_SECRET is required in production');

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:'],
    frameSrc: ['https://www.youtube.com', 'https://www.youtube-nocookie.com', 'https://player.vimeo.com'],
    mediaSrc: ["'self'", 'https:', 'http:'],
    connectSrc: ["'self'"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"]
  }
}}));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, 'data') }),
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'true', maxAge: 1000 * 60 * 60 * 8 }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many login attempts. Please try again later.' } });
app.use('/api/login', loginLimiter);
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));

function now() { return new Date().toISOString(); }
function clean(value, max = 5000) { return String(value ?? '').trim().slice(0, max); }
function validDate(s) { return /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(`${s}T00:00:00Z`)); }
function validUrl(s) { if (!s) return true; try { const u = new URL(s); return ['http:', 'https:'].includes(u.protocol); } catch { return false; } }
function csrfFor(req) { if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString('hex'); return req.session.csrf; }
function auth(req, res, next) { if (!req.session.userId) return res.status(401).json({ error: 'Authentication required.' }); const u = db.prepare('SELECT id,fullName,username,role,isActive FROM users WHERE id=?').get(req.session.userId); if (!u || !u.isActive) { req.session.destroy(() => {}); return res.status(401).json({ error: 'Authentication required.' }); } req.user = u; next(); }
function roles(...allowed) { return (req,res,next) => { if (!allowed.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden.' }); next(); }; }
function csrf(req,res,next) { if (['GET','HEAD','OPTIONS'].includes(req.method)) return next(); if (!req.session.csrf || req.get('x-csrf-token') !== req.session.csrf) return res.status(403).json({ error: 'Invalid security token.' }); next(); }
function ensureStudentId(req,res,next) { const id = Number(req.params.id); if (!Number.isInteger(id) || id < 1) return res.status(400).json({error:'Invalid student ID.'}); if (req.user.role === 'STUDENT' && id !== req.user.id) return res.status(403).json({error:'You can only access your own records.'}); req.studentId=id; next(); }
function gradeNumber(v) { if (v === null || v === '' || v === undefined) return null; const n = Number(v); return Number.isFinite(n) && n >= 0 && n <= 100 ? n : NaN; }

app.get('/api/session', (req,res) => {
  if (!req.session.userId) return res.json({ authenticated:false });
  const user = db.prepare('SELECT id,fullName,username,role,isActive FROM users WHERE id=?').get(req.session.userId);
  if (!user || !user.isActive) return res.json({ authenticated:false });
  res.json({ authenticated:true, user, csrf: csrfFor(req) });
});
app.post('/api/login', (req,res) => {
  const username=clean(req.body.username,100); const password=String(req.body.password||'');
  const user=db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!user || !user.isActive || !bcrypt.compareSync(password,user.passwordHash)) return res.status(401).json({error:'Invalid username or password.'});
  req.session.regenerate(err=>{ if(err) return res.status(500).json({error:'Could not create session.'}); req.session.userId=user.id; req.session.csrf=crypto.randomBytes(24).toString('hex'); res.json({user:{id:user.id,fullName:user.fullName,username:user.username,role:user.role},csrf:req.session.csrf}); });
});
app.post('/api/logout', auth, csrf, (req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get('/api/lectures', auth, (req,res)=>res.json(db.prepare(`SELECT l.id,l.title,l.description,l.videoUrl,l.createdAt,l.updatedAt,u.fullName AS createdByName FROM lectures l JOIN users u ON u.id=l.createdBy ORDER BY l.createdAt DESC`).all()));
app.post('/api/lectures', auth, roles('ADMIN','TEACHER'), csrf, (req,res)=>{ const title=clean(req.body.title,200), description=clean(req.body.description,5000), videoUrl=clean(req.body.videoUrl,2000); if(!title||!validUrl(videoUrl)) return res.status(400).json({error:'Title and a valid http(s) video URL are required.'}); const info=db.prepare('INSERT INTO lectures(title,description,videoUrl,createdBy) VALUES(?,?,?,?)').run(title,description,videoUrl,req.user.id); res.status(201).json(db.prepare('SELECT * FROM lectures WHERE id=?').get(info.lastInsertRowid)); });
app.put('/api/lectures/:id', auth, roles('ADMIN','TEACHER'), csrf, (req,res)=>{ const id=Number(req.params.id), title=clean(req.body.title,200), description=clean(req.body.description,5000), videoUrl=clean(req.body.videoUrl,2000); if(!Number.isInteger(id)||!title||!validUrl(videoUrl)) return res.status(400).json({error:'Invalid lecture data.'}); const info=db.prepare('UPDATE lectures SET title=?,description=?,videoUrl=?,updatedAt=? WHERE id=?').run(title,description,videoUrl,now(),id); if(!info.changes) return res.status(404).json({error:'Lecture not found.'}); res.json(db.prepare('SELECT * FROM lectures WHERE id=?').get(id)); });
app.delete('/api/lectures/:id', auth, roles('ADMIN','TEACHER'), csrf, (req,res)=>{ const info=db.prepare('DELETE FROM lectures WHERE id=?').run(Number(req.params.id)); if(!info.changes) return res.status(404).json({error:'Lecture not found.'}); res.json({ok:true}); });

app.get('/api/announcements', auth, (req,res)=>res.json(db.prepare(`SELECT a.id,a.title,a.content,a.createdAt,a.updatedAt,u.fullName AS createdByName FROM announcements a JOIN users u ON u.id=a.createdBy ORDER BY a.createdAt DESC`).all()));
app.post('/api/announcements', auth, roles('ADMIN','TEACHER'), csrf, (req,res)=>{ const title=clean(req.body.title,200),content=clean(req.body.content,10000); if(!title||!content)return res.status(400).json({error:'Title and content are required.'}); const info=db.prepare('INSERT INTO announcements(title,content,createdBy) VALUES(?,?,?)').run(title,content,req.user.id); res.status(201).json(db.prepare('SELECT * FROM announcements WHERE id=?').get(info.lastInsertRowid)); });
app.put('/api/announcements/:id', auth, roles('ADMIN','TEACHER'), csrf, (req,res)=>{ const id=Number(req.params.id),title=clean(req.body.title,200),content=clean(req.body.content,10000); if(!Number.isInteger(id)||!title||!content)return res.status(400).json({error:'Invalid announcement data.'}); const info=db.prepare('UPDATE announcements SET title=?,content=?,updatedAt=? WHERE id=?').run(title,content,now(),id); if(!info.changes)return res.status(404).json({error:'Announcement not found.'}); res.json(db.prepare('SELECT * FROM announcements WHERE id=?').get(id)); });
app.delete('/api/announcements/:id', auth, roles('ADMIN','TEACHER'), csrf, (req,res)=>{ const info=db.prepare('DELETE FROM announcements WHERE id=?').run(Number(req.params.id)); if(!info.changes)return res.status(404).json({error:'Announcement not found.'}); res.json({ok:true}); });

app.get('/api/students', auth, roles('ADMIN','TEACHER'), (req,res)=>res.json(db.prepare(`SELECT id,fullName,username,role,isActive,createdAt,updatedAt FROM users WHERE role='STUDENT' ORDER BY fullName`).all()));
app.get('/api/accounts', auth, roles('ADMIN'), (req,res)=>res.json(db.prepare(`SELECT id,fullName,username,role,isActive,createdAt,updatedAt FROM users ORDER BY role,fullName`).all()));

app.get('/api/students/:id/absences', auth, ensureStudentId, (req,res)=>res.json(db.prepare(`SELECT id,studentId,date,note,createdAt,updatedAt FROM absences WHERE studentId=? ORDER BY date DESC,id DESC`).all(req.studentId)));
app.post('/api/absences', auth, roles('ADMIN','TEACHER'), csrf, (req,res)=>{ const studentId=Number(req.body.studentId),date=clean(req.body.date,10),note=clean(req.body.note,2000); const student=db.prepare("SELECT id FROM users WHERE id=? AND role='STUDENT'").get(studentId); if(!student||!validDate(date))return res.status(400).json({error:'Valid student and date are required.'}); const info=db.prepare('INSERT INTO absences(studentId,date,note,createdBy) VALUES(?,?,?,?)').run(studentId,date,note,req.user.id); res.status(201).json(db.prepare('SELECT * FROM absences WHERE id=?').get(info.lastInsertRowid)); });
app.put('/api/absences/:id', auth, roles('ADMIN','TEACHER'), csrf, (req,res)=>{ const id=Number(req.params.id),date=clean(req.body.date,10),note=clean(req.body.note,2000); if(!Number.isInteger(id)||!validDate(date))return res.status(400).json({error:'Invalid absence data.'}); const info=db.prepare('UPDATE absences SET date=?,note=?,updatedAt=? WHERE id=?').run(date,note,now(),id); if(!info.changes)return res.status(404).json({error:'Absence not found.'}); res.json(db.prepare('SELECT * FROM absences WHERE id=?').get(id)); });
app.delete('/api/absences/:id', auth, roles('ADMIN','TEACHER'), csrf, (req,res)=>{ const info=db.prepare('DELETE FROM absences WHERE id=?').run(Number(req.params.id)); if(!info.changes)return res.status(404).json({error:'Absence not found.'}); res.json({ok:true}); });
app.get('/api/absences', auth, roles('ADMIN','TEACHER'), (req,res)=>res.json(db.prepare(`SELECT a.id,a.studentId,a.date,a.note,a.createdAt,u.fullName AS studentName FROM absences a JOIN users u ON u.id=a.studentId ORDER BY a.date DESC`).all()));

app.get('/api/students/:id/grades', auth, ensureStudentId, (req,res)=>{ const row=db.prepare('SELECT id,studentId,daily,monthly,final,updatedAt FROM grades WHERE studentId=?').get(req.studentId); res.json(row||{id:null,studentId:req.studentId,daily:null,monthly:null,final:null}); });
app.post('/api/grades', auth, roles('ADMIN'), csrf, (req,res)=>{ const studentId=Number(req.body.studentId); const student=db.prepare("SELECT id FROM users WHERE id=? AND role='STUDENT'").get(studentId); const daily=gradeNumber(req.body.daily),monthly=gradeNumber(req.body.monthly),final=gradeNumber(req.body.final); if(!student||[daily,monthly,final].some(Number.isNaN))return res.status(400).json({error:'Invalid grade data.'}); db.prepare(`INSERT INTO grades(studentId,daily,monthly,final,updatedBy) VALUES(?,?,?,?,?) ON CONFLICT(studentId) DO UPDATE SET daily=excluded.daily,monthly=excluded.monthly,final=excluded.final,updatedBy=excluded.updatedBy,updatedAt=CURRENT_TIMESTAMP`).run(studentId,daily,monthly,final,req.user.id); res.json(db.prepare('SELECT id,studentId,daily,monthly,final,updatedAt FROM grades WHERE studentId=?').get(studentId)); });
app.put('/api/grades/:id', auth, roles('ADMIN'), csrf, (req,res)=>{ const id=Number(req.params.id); const daily=gradeNumber(req.body.daily),monthly=gradeNumber(req.body.monthly),final=gradeNumber(req.body.final); if(!Number.isInteger(id)||[daily,monthly,final].some(Number.isNaN))return res.status(400).json({error:'Invalid grade data.'}); const info=db.prepare('UPDATE grades SET daily=?,monthly=?,final=?,updatedBy=?,updatedAt=? WHERE id=?').run(daily,monthly,final,req.user.id,now(),id); if(!info.changes)return res.status(404).json({error:'Grade record not found.'}); res.json(db.prepare('SELECT id,studentId,daily,monthly,final,updatedAt FROM grades WHERE id=?').get(id)); });
app.delete('/api/grades/:id', auth, roles('ADMIN'), csrf, (req,res)=>{ const info=db.prepare('DELETE FROM grades WHERE id=?').run(Number(req.params.id)); if(!info.changes)return res.status(404).json({error:'Grade record not found.'}); res.json({ok:true}); });

app.post('/api/users', auth, roles('ADMIN'), csrf, (req,res)=>{ const fullName=clean(req.body.fullName,200),username=clean(req.body.username,100),password=String(req.body.password||''),role=clean(req.body.role,20).toUpperCase(); if(!fullName||!username||password.length<10||!['STUDENT','TEACHER'].includes(role))return res.status(400).json({error:'Full name, username, valid role and a password of at least 10 characters are required.'}); try { const info=db.prepare('INSERT INTO users(fullName,username,passwordHash,role) VALUES(?,?,?,?)').run(fullName,username,bcrypt.hashSync(password,12),role); res.status(201).json(db.prepare('SELECT id,fullName,username,role,isActive,createdAt,updatedAt FROM users WHERE id=?').get(info.lastInsertRowid)); } catch(e){ if(String(e.message).includes('UNIQUE')) return res.status(409).json({error:'Username already exists.'}); throw e; } });
app.put('/api/users/:id', auth, roles('ADMIN'), csrf, (req,res)=>{ const id=Number(req.params.id),fullName=clean(req.body.fullName,200),username=clean(req.body.username,100); const isActive=req.body.isActive?1:0; if(!Number.isInteger(id)||!fullName||!username)return res.status(400).json({error:'Invalid account data.'}); const info=db.prepare('UPDATE users SET fullName=?,username=?,isActive=?,updatedAt=? WHERE id=?').run(fullName,username,isActive,now(),id); if(!info.changes)return res.status(404).json({error:'Account not found.'}); res.json(db.prepare('SELECT id,fullName,username,role,isActive,createdAt,updatedAt FROM users WHERE id=?').get(id)); });
app.post('/api/users/:id/reset-password', auth, roles('ADMIN'), csrf, (req,res)=>{ const id=Number(req.params.id),password=String(req.body.password||''); if(password.length<10)return res.status(400).json({error:'Password must be at least 10 characters.'}); const info=db.prepare('UPDATE users SET passwordHash=?,updatedAt=? WHERE id=?').run(bcrypt.hashSync(password,12),now(),id); if(!info.changes)return res.status(404).json({error:'Account not found.'}); res.json({ok:true}); });
app.delete('/api/users/:id', auth, roles('ADMIN'), csrf, (req,res)=>{ const id=Number(req.params.id); if(id===req.user.id)return res.status(400).json({error:'You cannot delete your own admin account.'}); const target=db.prepare('SELECT role FROM users WHERE id=?').get(id); if(!target)return res.status(404).json({error:'Account not found.'}); if(target.role==='ADMIN')return res.status(400).json({error:'The primary admin account cannot be deleted here.'}); db.prepare('DELETE FROM users WHERE id=?').run(id); res.json({ok:true}); });

app.get('*', (req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

if (require.main === module) app.listen(PORT, ()=>console.log(`Platform running on port ${PORT}`));
module.exports=app;
