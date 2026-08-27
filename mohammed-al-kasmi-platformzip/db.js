const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const dbPath = process.env.NODE_ENV === 'test' ? path.join(dataDir, 'test.db') : path.join(dataDir, 'platform.db');
const db = new Database(dbPath);
db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 fullName TEXT NOT NULL,
 username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 passwordHash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('ADMIN','TEACHER','STUDENT')),
 isActive INTEGER NOT NULL DEFAULT 1 CHECK(isActive IN (0,1)),
 createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updatedAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS lectures (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 description TEXT NOT NULL DEFAULT '',
 videoUrl TEXT NOT NULL DEFAULT '',
 createdBy INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updatedAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS announcements (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 content TEXT NOT NULL,
 createdBy INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updatedAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS absences (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 studentId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 date TEXT NOT NULL,
 note TEXT NOT NULL DEFAULT '',
 createdBy INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updatedAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS grades (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 studentId INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
 daily REAL,
 monthly REAL,
 final REAL,
 updatedBy INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updatedAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_absences_student_date ON absences(studentId, date DESC);
CREATE INDEX IF NOT EXISTS idx_lectures_created ON lectures(createdAt DESC);
CREATE INDEX IF NOT EXISTS idx_announcements_created ON announcements(createdAt DESC);
`);

function seed() {
  const count = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
  if (count > 0) return;
  const insertUser = db.prepare(`INSERT INTO users(fullName, username, passwordHash, role) VALUES(?,?,?,?)`);
  const admin = insertUser.run('Platform Administrator', 'admin', bcrypt.hashSync('Admin@12345!', 12), 'ADMIN').lastInsertRowid;
  const teacher = insertUser.run('Mohammed Al-Kasmi', 'teacher', bcrypt.hashSync('Teacher@12345!', 12), 'TEACHER').lastInsertRowid;
  const ahmed = insertUser.run('Ahmed Hassan', 'ahmed', bcrypt.hashSync('Student@12345!', 12), 'STUDENT').lastInsertRowid;
  const sara = insertUser.run('Sara Ali', 'sara', bcrypt.hashSync('Student@12345!', 12), 'STUDENT').lastInsertRowid;
  const omar = insertUser.run('Omar Khalid', 'omar', bcrypt.hashSync('Student@12345!', 12), 'STUDENT').lastInsertRowid;
  const lecture = db.prepare('INSERT INTO lectures(title,description,videoUrl,createdBy) VALUES(?,?,?,?)');
  lecture.run('Present Perfect', 'Learn how to form and use the present perfect tense in everyday English.', 'https://www.youtube.com/watch?v=9bZkp7q19f0', teacher);
  lecture.run('Giving Advice', 'Useful structures for giving clear and polite advice.', 'https://www.youtube.com/watch?v=dQw4w9WgXcQ', teacher);
  const announcement = db.prepare('INSERT INTO announcements(title,content,createdBy) VALUES(?,?,?)');
  announcement.run('Welcome to the platform', 'Your lectures, announcements, attendance and grades are now available in one private space.', teacher);
  announcement.run('Monthly exam reminder', 'Please review the assigned lectures before the next monthly assessment.', teacher);
  const absence = db.prepare('INSERT INTO absences(studentId,date,note,createdBy) VALUES(?,?,?,?)');
  absence.run(ahmed, '2026-08-18', 'Absent without prior notice.', teacher);
  absence.run(ahmed, '2026-08-25', 'Medical appointment.', teacher);
  absence.run(sara, '2026-08-20', 'Family commitment.', teacher);
  const grade = db.prepare('INSERT INTO grades(studentId,daily,monthly,final,updatedBy) VALUES(?,?,?,?,?)');
  grade.run(ahmed, 85, 90, 88, admin);
  grade.run(sara, 92, 94, 93, admin);
  grade.run(omar, 78, 86, 82, admin);
}
seed();

module.exports = db;
