// db.js — SQLite database connection and schema.
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DB_PATH = process.env.DB_PATH || './data/academy.db';
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK(role IN ('student','admin')),
  student_id    TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS students (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  track      TEXT NOT NULL DEFAULT 'Not yet assigned',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS lectures (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  title    TEXT NOT NULL,
  teacher  TEXT NOT NULL,
  track    TEXT NOT NULL,
  day      TEXT NOT NULL,
  time     TEXT NOT NULL,
  mode     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS results (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  subject    TEXT NOT NULL,
  term       TEXT NOT NULL,
  score      TEXT NOT NULL,
  grade      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payments (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  desc       TEXT NOT NULL,
  due        TEXT NOT NULL,
  amount     REAL NOT NULL,
  status     TEXT NOT NULL DEFAULT 'due' CHECK(status IN ('due','paid')),
  paid_on    TEXT,
  txn        TEXT
);

CREATE TABLE IF NOT EXISTS registrations (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  name            TEXT NOT NULL,
  dob             TEXT,
  gender          TEXT,
  address         TEXT,
  guardian_name   TEXT,
  guardian_phone  TEXT,
  guardian_email  TEXT,
  track           TEXT NOT NULL,
  intake          TEXT,
  prev_school     TEXT,
  notes           TEXT,
  contact         TEXT NOT NULL,
  payment_amount  INTEGER NOT NULL DEFAULT 10000,
  payment_ref     TEXT,
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notifications (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  type    TEXT NOT NULL,
  message TEXT NOT NULL,
  to_addr TEXT NOT NULL,
  date    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS exam_registrations (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  term       TEXT NOT NULL,
  courses    TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(student_id, term)
);

CREATE TABLE IF NOT EXISTS notif_settings (
  key   TEXT PRIMARY KEY,
  value INTEGER NOT NULL
);
`);

const defaults = { registrationAlerts: 1, feeReminders: 1 };
const insertSetting = db.prepare(
  'INSERT OR IGNORE INTO notif_settings (key, value) VALUES (?, ?)'
);
for (const [key, value] of Object.entries(defaults)) insertSetting.run(key, value);

module.exports = db;
