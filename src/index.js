require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const db = require('./db');
const { signToken, requireAuth, requireAdmin } = require('./auth');

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json());

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
    `SELECT COALESCE(SUM(amount),0
