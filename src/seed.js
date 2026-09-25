// Run with: npm run seed
// Populates demo accounts and a few starter records so you have something
// to look at immediately. Safe to run more than once — it skips anything
// that already exists.

require('dotenv').config();
const bcrypt = require('bcryptjs');
const db = require('./db');

function upsertUser(name, email, password, role, studentId) {
  const existing = db.prepare(`SELECT id FROM users WHERE email = ?`).get(email);
  if (existing) return;
  db.prepare(
    `INSERT INTO users (name, email, password_hash, role, student_id) VALUES (?, ?, ?, ?, ?)`
  ).run(name, email, bcrypt.hashSync(password, 10), role, studentId || null);
}

function upsertStudent(id, name, track) {
  db.prepare(`INSERT OR IGNORE INTO students (id, name, track) VALUES (?, ?, ?)`).run(id, name, track);
}

upsertStudent('MIA-0232', 'Maryam Siti Fatimah', 'Advanced');
upsertUser('Maryam Siti Fatimah', 'maryam.demo@example.com', 'demo123', 'student', 'MIA-0232');
upsertUser("Ustadhah Amina Yusuf", 'admin.demo@example.com', 'demo123', 'admin', null);

const hasPayment = db.prepare(`SELECT id FROM payments WHERE student_id = 'MIA-0232'`).get();
if (!hasPayment) {
  db.prepare(
    `INSERT INTO payments (student_id, desc, due, amount, status) VALUES (?, ?, ?, ?, ?)`
  ).run('MIA-0232', 'Term 3 Tuition Fee', '2026-09-30', 40000, 'due');
}

const hasLecture = db.prepare(`SELECT id FROM lectures`).get();
if (!hasLecture) {
  db.prepare(
    `INSERT INTO lectures (title, teacher, track, day, time, mode) VALUES (?, ?, ?, ?, ?, ?)`
  ).run('Arabic Grammar (Syntax) — Session 12', 'Ustadh Kamil Rahman', 'Advanced', 'Mon & Wed', '8:00–9:30 PM', 'In-person, Hall A');
}

console.log('Seed complete. Demo logins:');
console.log('  Student: maryam.demo@example.com / demo123');
console.log('  Staff:   admin.demo@example.com / demo123');
