require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const db = require('./db');
const { signToken, requireAuth, requireAdmin } = require('./auth');

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json());

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || null;

/* ---------------------------------------------------------------------- */
/* Helpers                                                                  */
/* ---------------------------------------------------------------------- */

function nextStudentId() {
  const row = db.prepare(`SELECT id FROM students ORDER BY id DESC`).all()
    .map(r => parseInt((r.id.match(/(\d+)/) || [0, 230])[1], 10))
    .sort((a, b) => b - a)[0] || 230;
  return 'MIA-0' + (row + 1);
}

function studentBalanceAndStatus(studentId) {
  const due = db.prepare(
    `SELECT COALESCE(SUM(amount),0) as total FROM payments WHERE student_id = ? AND status = 'due'`
  ).get(studentId).total;
  return { balance: due, status: due > 0 ? 'Fee due' : 'Active' };
}

function logNotification(type, message, to) {
  db.prepare(`INSERT INTO notifications (type, message, to_addr) VALUES (?, ?, ?)`).run(type, message, to);
}

function getSetting(key) {
  const row = db.prepare(`SELECT value FROM notif_settings WHERE key = ?`).get(key);
  return row ? !!row.value : true;
}

/* ---------------------------------------------------------------------- */
/* Auth                                                                     */
/* ---------------------------------------------------------------------- */

app.post('/api/auth/signup', (req, res) => {
  const { name, email, password, role, track } = req.body || {};
  if (!name || !email || !password || !['student', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'name, email, password and a valid role are required.' });
  }
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const existing = db.prepare(`SELECT id FROM users WHERE email = ?`).get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'An account with that email already exists.' });

  const passwordHash = bcrypt.hashSync(password, 10);
  let studentId = null;

  const tx = db.transaction(() => {
    if (role === 'student') {
      studentId = nextStudentId();
      db.prepare(`INSERT INTO students (id, name, track) VALUES (?, ?, ?)`)
        .run(studentId, name, track || 'Not yet assigned');
    }
    db.prepare(
      `INSERT INTO users (name, email, password_hash, role, student_id) VALUES (?, ?, ?, ?, ?)`
    ).run(name, email.toLowerCase(), passwordHash, role, studentId);
  });
  tx();

  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email.toLowerCase());
  res.json({ token: signToken(user), user: publicUser(user) });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get((email || '').toLowerCase());
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }
  res.json({ token: signToken(user), user: publicUser(user) });
});

function publicUser(user) {
  return { name: user.name, email: user.email, role: user.role, studentId: user.student_id };
}

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

/* ---------------------------------------------------------------------- */
/* Profile (self-service)                                                   */
/* ---------------------------------------------------------------------- */

app.put('/api/me/profile', requireAuth, (req, res) => {
  const { name, track, email } = req.body || {};
  const tx = db.transaction(() => {
    if (name) db.prepare(`UPDATE users SET name = ? WHERE id = ?`).run(name, req.user.id);
    if (email && email.toLowerCase() !== req.user.email) {
      const taken = db.prepare(`SELECT id FROM users WHERE email = ?`).get(email.toLowerCase());
      if (taken) throw new Error('EMAIL_TAKEN');
      db.prepare(`UPDATE users SET email = ? WHERE id = ?`).run(email.toLowerCase(), req.user.id);
    }
    if (req.user.studentId) {
      db.prepare(`UPDATE students SET name = COALESCE(?, name), track = COALESCE(?, track) WHERE id = ?`)
        .run(name || null, track || null, req.user.studentId);
    }
  });
  try {
    tx();
  } catch (e) {
    if (e.message === 'EMAIL_TAKEN') return res.status(409).json({ error: 'That email is already in use.' });
    throw e;
  }
  const user = db.prepare(`SELECT * FROM users WHERE id = ?`).get(req.user.id);
  res.json({ token: signToken(user), user: publicUser(user) });
});

/* ---------------------------------------------------------------------- */
/* Students (staff directory + a student's own record)                      */
/* ---------------------------------------------------------------------- */

app.get('/api/students', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT * FROM students ORDER BY id`).all();
  res.json(rows.map(s => ({ ...s, ...studentBalanceAndStatus(s.id) })));
});

app.get('/api/students/me', requireAuth, (req, res) => {
  if (!req.user.studentId) return res.status(404).json({ error: 'No student record on this account.' });
  const s = db.prepare(`SELECT * FROM students WHERE id = ?`).get(req.user.studentId);
  if (!s) return res.status(404).json({ error: 'Student record not found.' });
  res.json({ ...s, ...studentBalanceAndStatus(s.id) });
});

/* ---------------------------------------------------------------------- */
/* Lectures                                                                  */
/* ---------------------------------------------------------------------- */

app.get('/api/lectures', requireAuth, (req, res) => {
  res.json(db.prepare(`SELECT * FROM lectures ORDER BY id DESC`).all());
});

app.post('/api/lectures', requireAuth, requireAdmin, (req, res) => {
  const { title, teacher, track, day, time, mode } = req.body || {};
  if (!title || !teacher || !track || !day || !time || !mode) {
    return res.status(400).json({ error: 'All lecture fields are required.' });
  }
  const info = db.prepare(
    `INSERT INTO lectures (title, teacher, track, day, time, mode) VALUES (?, ?, ?, ?, ?, ?)`
  ).run(title, teacher, track, day, time, mode);
  res.json(db.prepare(`SELECT * FROM lectures WHERE id = ?`).get(info.lastInsertRowid));
});

app.put('/api/lectures/:id', requireAuth, requireAdmin, (req, res) => {
  const { title, teacher, track, day, time, mode } = req.body || {};
  db.prepare(
    `UPDATE lectures SET title=?, teacher=?, track=?, day=?, time=?, mode=? WHERE id=?`
  ).run(title, teacher, track, day, time, mode, req.params.id);
  res.json(db.prepare(`SELECT * FROM lectures WHERE id = ?`).get(req.params.id));
});

app.delete('/api/lectures/:id', requireAuth, requireAdmin, (req, res) => {
  db.prepare(`DELETE FROM lectures WHERE id = ?`).run(req.params.id);
  res.json({ ok: true });
});

/* ---------------------------------------------------------------------- */
/* Results                                                                   */
/* ---------------------------------------------------------------------- */

app.get('/api/results/mine', requireAuth, (req, res) => {
  if (!req.user.studentId) return res.json([]);
  res.json(db.prepare(`SELECT * FROM results WHERE student_id = ? ORDER BY id DESC`).all(req.user.studentId));
});

app.get('/api/results', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT results.*, students.name as student_name
    FROM results JOIN students ON students.id = results.student_id
    ORDER BY results.id DESC
  `).all();
  res.json(rows);
});

app.post('/api/results', requireAuth, requireAdmin, (req, res) => {
  const { studentId, subject, term, score, grade } = req.body || {};
  if (!studentId || !subject || !term || !score || !grade) {
    return res.status(400).json({ error: 'All result fields are required.' });
  }
  const info = db.prepare(
    `INSERT INTO results (student_id, subject, term, score, grade) VALUES (?, ?, ?, ?, ?)`
  ).run(studentId, subject, term, score, grade);
  res.json(db.prepare(`SELECT * FROM results WHERE id = ?`).get(info.lastInsertRowid));
});

app.put('/api/results/:id', requireAuth, requireAdmin, (req, res) => {
  const { subject, term, score, grade } = req.body || {};
  db.prepare(`UPDATE results SET subject=?, term=?, score=?, grade=? WHERE id=?`)
    .run(subject, term, score, grade, req.params.id);
  res.json(db.prepare(`SELECT * FROM results WHERE id = ?`).get(req.params.id));
});

app.delete('/api/results/:id', requireAuth, requireAdmin, (req, res) => {
  db.prepare(`DELETE FROM results WHERE id = ?`).run(req.params.id);
  res.json({ ok: true });
});

/* ---------------------------------------------------------------------- */
/* Payments                                                                  */
/* ---------------------------------------------------------------------- */

app.get('/api/payments/mine', requireAuth, (req, res) => {
  if (!req.user.studentId) return res.json([]);
  res.json(db.prepare(`SELECT * FROM payments WHERE student_id = ? ORDER BY id DESC`).all(req.user.studentId));
});

app.get('/api/payments', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT * FROM students ORDER BY id`).all();
  res.json(rows.map(s => ({ id: s.id, name: s.name, track: s.track, ...studentBalanceAndStatus(s.id) })));
});

// Confirms and records a payment. With Paystack configured, this re-checks
// the transaction with Paystack itself (via its /transaction/verify endpoint)
// before marking anything paid — never trusts the browser's word alone that
// a charge succeeded. Without Paystack configured, it falls back to the old
// simulated flow so the portal keeps working for testing before you set your
// keys.
app.post('/api/payments/:id/pay', requireAuth, async (req, res) => {
  const payment = db.prepare(`SELECT * FROM payments WHERE id = ?`).get(req.params.id);
  if (!payment || payment.student_id !== req.user.studentId) {
    return res.status(404).json({ error: 'Payment not found.' });
  }
  if (payment.status === 'paid') return res.json(payment);

  let txn;
  if (PAYSTACK_SECRET_KEY) {
    const { reference } = req.body || {};
    if (!reference) return res.status(400).json({ error: 'Missing payment reference.' });
    try {
      const verifyRes = await fetch(
        `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
        { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } }
      );
      const data = await verifyRes.json();
      const tx = data && data.data;
      const expectedAmount = Math.round(payment.amount * 100);
      if (
        !data.status || !tx || tx.status !== 'success' ||
        tx.amount !== expectedAmount ||
        !tx.metadata || String(tx.metadata.paymentId) !== String(payment.id)
      ) {
        return res.status(402).json({ error: 'Payment was not completed successfully.' });
      }
      txn = tx.reference;
    } catch (e) {
      return res.status(500).json({ error: 'Could not confirm payment: ' + e.message });
    }
  } else {
    txn = 'TXN-' + Math.random().toString(36).slice(2, 8).toUpperCase();
  }

  db.prepare(`UPDATE payments SET status='paid', paid_on=date('now'), txn=? WHERE id=?`).run(txn, payment.id);
  res.json(db.prepare(`SELECT * FROM payments WHERE id = ?`).get(payment.id));
});

/* ---------------------------------------------------------------------- */
/* Registrations (public intake + staff review)                             */
/* ---------------------------------------------------------------------- */

// Public — no auth. This is the endpoint the public registration form posts to.
app.post('/api/registrations', (req, res) => {
  const { name, track, contact } = req.body || {};
  if (!name || !track || !contact) return res.status(400).json({ error: 'name, track and contact are required.' });

  const info = db.prepare(`INSERT INTO registrations (name, track, contact) VALUES (?, ?, ?)`)
    .run(name, track, contact);

  if (getSetting('registrationAlerts')) {
    logNotification('registration', `New registration from ${name} for ${track}`, 'maknazulirfanacademy@gmail.com (staff)');
  }
  res.json(db.prepare(`SELECT * FROM registrations WHERE id = ?`).get(info.lastInsertRowid));
});

app.get('/api/registrations', requireAuth, requireAdmin, (req, res) => {
  res.json(db.prepare(`SELECT * FROM registrations ORDER BY id DESC`).all());
});

app.post('/api/registrations/:id/approve', requireAuth, requireAdmin, (req, res) => {
  const reg = db.prepare(`SELECT * FROM registrations WHERE id = ?`).get(req.params.id);
  if (!reg) return res.status(404).json({ error: 'Registration not found.' });

  const studentId = nextStudentId();
  const contactEmail = (reg.contact || '').trim().toLowerCase();
  const looksLikeEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail);

  let tempPassword = null;
  let loginEmail = null;
  let accountNote = 'No login created — the contact given was not an email address. Have them use "Create account" with their own email, or add one manually.';

  const tx = db.transaction(() => {
    db.prepare(`INSERT INTO students (id, name, track) VALUES (?, ?, ?)`).run(studentId, reg.name, reg.track);
    db.prepare(
      `INSERT INTO payments (student_id, desc, due, amount, status) VALUES (?, 'Registration & Materials', 'Within 14 days of enrollment', 80, 'due')`
    ).run(studentId);

    if (looksLikeEmail) {
      const existing = db.prepare(`SELECT id FROM users WHERE email = ?`).get(contactEmail);
      if (existing) {
        accountNote = `An account already exists with ${contactEmail}. Ask the family to sign in with their existing password, or contact the office to link this student to that account.`;
      } else {
        tempPassword = Math.random().toString(36).slice(2, 8) + Math.random().toString(36).slice(2, 4).toUpperCase();
        const passwordHash = bcrypt.hashSync(tempPassword, 10);
        db.prepare(
          `INSERT INTO users (name, email, password_hash, role, student_id) VALUES (?, ?, ?, 'student', ?)`
        ).run(reg.name, contactEmail, passwordHash, studentId);
        loginEmail = contactEmail;
        accountNote = null;
      }
    }

    db.prepare(`DELETE FROM registrations WHERE id = ?`).run(reg.id);
  });
  tx();

  logNotification(
    'enrollment',
    tempPassword
      ? `Enrollment confirmed for ${reg.name}. Login: ${loginEmail} / temporary password: ${tempPassword}`
      : `Enrollment confirmed for ${reg.name}. ${accountNote}`,
    reg.contact
  );
  res.json({ studentId, loginEmail, tempPassword, accountNote });
});

/* ---------------------------------------------------------------------- */
/* Notifications (staff only)                                               */
/* ---------------------------------------------------------------------- */

app.get('/api/notifications', requireAuth, requireAdmin, (req, res) => {
  res.json(db.prepare(`SELECT * FROM notifications ORDER BY id DESC`).all());
});

app.get('/api/notif-settings', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT * FROM notif_settings`).all();
  res.json(Object.fromEntries(rows.map(r => [r.key, !!r.value])));
});

app.put('/api/notif-settings/:key', requireAuth, requireAdmin, (req, res) => {
  db.prepare(`INSERT INTO notif_settings (key, value) VALUES (?, ?)
              ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
    .run(req.params.key, req.body.value ? 1 : 0);
  res.json({ ok: true });
});

app.post('/api/notifications/send-fee-reminders', requireAuth, requireAdmin, (req, res) => {
  const dues = db.prepare(`
    SELECT payments.*, students.name as student_name
    FROM payments JOIN students ON students.id = payments.student_id
    WHERE payments.status = 'due'
  `).all();
  const emailByStudent = Object.fromEntries(
    db.prepare(`SELECT student_id, email FROM users WHERE student_id IS NOT NULL`).all()
      .map(u => [u.student_id, u.email])
  );
  dues.forEach(p => {
    logNotification(
      'reminder',
      `Fee reminder: ${p.desc} ($${p.amount}) due ${p.due} — ${p.student_name}`,
      emailByStudent[p.student_id] || 'guardian on file'
    );
  });
  res.json({ sent: dues.length });
});

/* ---------------------------------------------------------------------- */

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Public — tells the front-end whether real Paystack checkout is configured,
// and gives it the public key (safe to expose — it's not a secret).
app.get('/api/config', (req, res) => {
  res.json({ paystackPublicKey: process.env.PAYSTACK_PUBLIC_KEY || null });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Academy API listening on port ${port}`));
