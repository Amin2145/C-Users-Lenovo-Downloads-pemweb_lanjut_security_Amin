const express    = require('express');
const cors       = require('cors');
const cookieParser = require('cookie-parser');
const csrf       = require('csurf');
const bodyParser = require('body-parser');
const sqlite3    = require('sqlite3').verbose();

const app  = express();
const port = 4000;

// ── State: mode rentan bisa di-toggle dari frontend ──────────────────────────
let vulnerableMode = false;

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true,
}));
app.use(cookieParser());
app.use(bodyParser.json());

// CSRF hanya aktif di mode AMAN
const csrfProtection = csrf({ cookie: true });

// ── SQLite in-memory ──────────────────────────────────────────────────────────
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run('CREATE TABLE user_input (id INTEGER PRIMARY KEY, content TEXT, mode TEXT)');
});

// ── Middleware kondisional CSRF ───────────────────────────────────────────────
function conditionalCsrf(req, res, next) {
  if (vulnerableMode) return next();         // bypass CSRF di mode rentan
  return csrfProtection(req, res, next);
}

// ── Endpoints ─────────────────────────────────────────────────────────────────

// Token CSRF
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Toggle mode rentan/aman
app.post('/api/toggle-mode', (req, res) => {
  vulnerableMode = !vulnerableMode;
  res.json({ vulnerableMode, message: vulnerableMode ? 'Mode RENTAN aktif!' : 'Mode AMAN aktif.' });
});

// Status mode saat ini
app.get('/api/mode', (req, res) => {
  res.json({ vulnerableMode });
});

// POST data — perilaku berubah sesuai mode
app.post('/api/data', conditionalCsrf, (req, res) => {
  const input = req.body.input;

  if (vulnerableMode) {
    // RENTAN: string concatenation langsung → SQL Injection bisa berhasil
    const sql = `INSERT INTO user_input(content, mode) VALUES ('${input}', 'vulnerable')`;
    db.run(sql, (err) => {
      if (err) {
        // Di mode rentan, kita kembalikan error database mentah supaya terlihat efeknya
        return res.status(500).json({ message: `DB Error (Mode Rentan): ${err.message}`, sql });
      }
      res.json({ message: 'Input disimpan (TANPA keamanan) — Mode Rentan!', sql });
    });
  } else {
    // AMAN: parameterized query
    db.run('INSERT INTO user_input(content, mode) VALUES (?, ?)', [input, 'safe'], (err) => {
      if (err) return res.status(500).send('DB Error');
      res.json({ message: 'Input berhasil disimpan dengan aman!' });
    });
  }
});

// Endpoint CORS Test — untuk demonstrasi kebijakan CORS
app.get('/api/cors-test', (req, res) => {
  const origin = req.headers['origin'] || 'Tidak ada Origin';
  const allowedOrigin = 'http://localhost:5173';
  const isAllowed = origin === allowedOrigin;

  res.json({
    requestOrigin: origin,
    allowedOrigin,
    isAllowed,
    message: isAllowed
      ? `✅ Origin "${origin}" diizinkan oleh server.`
      : `❌ Origin "${origin}" TIDAK diizinkan. Server hanya menerima dari "${allowedOrigin}".`,
    corsHeaders: {
      'Access-Control-Allow-Origin': allowedOrigin,
      'Access-Control-Allow-Credentials': 'true',
    },
  });
});

app.listen(port, () => console.log(`Server berjalan di http://localhost:${port} | Mode: ${vulnerableMode ? 'RENTAN' : 'AMAN'}`));
