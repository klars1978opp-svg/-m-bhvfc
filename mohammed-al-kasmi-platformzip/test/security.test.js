const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const fs = require('fs');
const path = require('path');
for (const f of ['test.db','sessions.db','sessions.db-shm','sessions.db-wal']) { try { fs.unlinkSync(path.join(__dirname,'..','data',f)); } catch {} }
const app = require('../server');

async function login(agent, username, password){
  const r=await agent.post('/api/login').send({username,password});
  assert.equal(r.status,200); return r.body.csrf;
}

test('unauthenticated users only get login/session shell and protected APIs reject access', async()=>{
  const r=await request(app).get('/api/lectures'); assert.equal(r.status,401);
  const page=await request(app).get('/'); assert.equal(page.status,200); assert.match(page.text,/Mohammed Al-Kasmi Educational Platform/);
});

test('student identity and private-data isolation are enforced server-side', async()=>{
  const a=request.agent(app); const csrf=await login(a,'ahmed','Student@12345!');
  const s=await a.get('/api/session'); assert.equal(s.body.user.fullName,'Ahmed Hassan'); assert.equal(s.body.user.role,'STUDENT');
  const own=await a.get('/api/students/3/grades'); assert.equal(own.status,200); assert.equal(own.body.studentId,3);
  const other=await a.get('/api/students/4/grades'); assert.equal(other.status,403);
  const ownAbs=await a.get('/api/students/3/absences'); assert.equal(ownAbs.status,200);
  const otherAbs=await a.get('/api/students/4/absences'); assert.equal(otherAbs.status,403);
  const gradeMutation=await a.post('/api/grades').set('x-csrf-token',csrf).send({studentId:3,daily:1,monthly:1,final:1}); assert.equal(gradeMutation.status,403);
  const absenceMutation=await a.post('/api/absences').set('x-csrf-token',csrf).send({studentId:3,date:'2026-08-27'}); assert.equal(absenceMutation.status,403);
  const lectureMutation=await a.post('/api/lectures').set('x-csrf-token',csrf).send({title:'x',description:'x',videoUrl:'https://example.com/v'}); assert.equal(lectureMutation.status,403);
});

test('teacher can manage content and absences but cannot modify grades', async()=>{
  const a=request.agent(app); const csrf=await login(a,'teacher','Teacher@12345!');
  const lec=await a.post('/api/lectures').set('x-csrf-token',csrf).send({title:'Test',description:'Desc',videoUrl:'https://example.com/video'}); assert.equal(lec.status,201);
  const ann=await a.post('/api/announcements').set('x-csrf-token',csrf).send({title:'Test',content:'Hello'}); assert.equal(ann.status,201);
  const abs=await a.post('/api/absences').set('x-csrf-token',csrf).send({studentId:3,date:'2026-08-27',note:'Test'}); assert.equal(abs.status,201);
  const grades=await a.post('/api/grades').set('x-csrf-token',csrf).send({studentId:3,daily:99,monthly:99,final:99}); assert.equal(grades.status,403);
  const accounts=await a.get('/api/accounts'); assert.equal(accounts.status,403);
});

test('admin can create students and manage grades; unauthorized admin APIs reject others', async()=>{
  const a=request.agent(app); const csrf=await login(a,'admin','Admin@12345!');
  const create=await a.post('/api/users').set('x-csrf-token',csrf).send({fullName:'New Student',username:'newstudent',password:'LongPassword!1',role:'STUDENT'}); assert.equal(create.status,201); assert.equal(create.body.role,'STUDENT');
  const grade=await a.post('/api/grades').set('x-csrf-token',csrf).send({studentId:create.body.id,daily:88,monthly:91,final:90}); assert.equal(grade.status,200); assert.equal(grade.body.final,90);
  const noCsrf=await a.post('/api/grades').send({studentId:create.body.id,daily:1,monthly:1,final:1}); assert.equal(noCsrf.status,403);
});
