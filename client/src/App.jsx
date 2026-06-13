import React, { useState, useEffect } from 'react';
import DOMPurify from 'dompurify';
import axios from 'axios';
import Quiz from './Quiz';
import './App.css';

const API = 'http://localhost:4000';

const PAYLOADS = [
  { label: '<script>alert(1)</script>', value: '<script>alert(1)</script>', type: 'xss' },
  { label: '<img src=x onerror=alert(1)>', value: '<img src=x onerror=alert(1)>', type: 'xss' },
  { label: "'); DROP TABLE user_input; --", value: "'); DROP TABLE user_input; --", type: 'sqli' },
  { label: "' OR '1'='1", value: "' OR '1'='1", type: 'sqli' },
  { label: 'Halo, Dunia!', value: 'Halo, Dunia!', type: 'safe' },
];

const INFO_CARDS = [
  { cls: 'xss',  icon: '⚡', title: 'XSS (Cross-Site Scripting)',      desc: 'Penyerang menyuntikkan skrip berbahaya ke halaman yang dilihat pengguna lain.',           fix: '✅ Solusi: DOMPurify menghapus semua HTML berbahaya sebelum ditampilkan.' },
  { cls: 'csrf', icon: '🎭', title: 'CSRF (Cross-Site Request Forgery)', desc: 'Mengelabui pengguna yang sudah login untuk mengirimkan permintaan yang tidak diinginkan.', fix: '✅ Solusi: Middleware csurf memvalidasi token rahasia di setiap permintaan POST.' },
  { cls: 'sqli', icon: '💉', title: 'SQL Injection',                     desc: 'Perintah SQL berbahaya disisipkan ke dalam query untuk memanipulasi database.',             fix: '✅ Solusi: Parameterized query (?) memperlakukan input sebagai data, bukan kode.' },
  { cls: 'cors', icon: '🌐', title: 'Kebijakan CORS',                    desc: 'Browser memblokir permintaan lintas-asal dari domain yang tidak dipercaya.',                fix: '✅ Solusi: Server hanya mengizinkan http://localhost:5173 dengan kredensial.' },
];

const CODE_SNIPPETS = [
  {
    title: 'XSS Protection', type: 'xss',
    vuln: `// ❌ RENTAN: Render langsung tanpa sanitasi
<div dangerouslySetInnerHTML=
  {{ __html: userInput }} />
// <script>alert(1)</script> akan DIEKSEKUSI!`,
    safe: `// ✅ AMAN: Sanitasi dengan DOMPurify
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);
<div dangerouslySetInnerHTML=
  {{ __html: clean }} />`,
  },
  {
    title: 'SQL Injection', type: 'sqli',
    vuln: `// ❌ RENTAN: String concatenation
const sql = \`INSERT INTO tabel
  VALUES ('\${input}')\`;
// '); DROP TABLE tabel; --
// akan MENGHAPUS database!`,
    safe: `// ✅ AMAN: Parameterized Query
db.run(
  "INSERT INTO tabel VALUES (?)",
  [input]  // input = data, bukan kode
);`,
  },
  {
    title: 'CSRF Protection', type: 'csrf',
    vuln: `// ❌ RENTAN: POST tanpa token
axios.post('/api/data', { input });
// Siapapun bisa memalsukan request
// ini dari website lain!`,
    safe: `// ✅ AMAN: Sertakan X-CSRF-Token
const res = await axios.get('/api/csrf-token');
axios.defaults.headers.post['X-CSRF-Token']
  = res.data.csrfToken;
// Backend menolak request tanpa token`,
  },
  {
    title: 'CORS Policy', type: 'cors',
    vuln: `// ❌ RENTAN: Izinkan semua origin
app.use(cors({
  origin: '*'  // Semua domain bisa akses!
}));`,
    safe: `// ✅ AMAN: Whitelist origin tertentu
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
  // Hanya frontend kita yang bisa akses
}));`,
  },
];

function ResultCard({ type, children }) {
  return <div className={`result-card ${type}`}>{children}</div>;
}

function SecurityPipeline({ pipeState }) {
  const nodes = [
    { key: 'input',  icon: '📝', label: 'Input' },
    { key: 'xss',   icon: '⚡', label: 'DOMPurify' },
    { key: 'csrf',  icon: '🎭', label: 'CSRF Token' },
    { key: 'cors',  icon: '🌐', label: 'CORS' },
    { key: 'sqli',  icon: '💉', label: 'Param Query' },
    { key: 'db',    icon: '🗄️', label: 'Database' },
  ];
  return (
    <div className="pipeline">
      {nodes.map((n, i) => (
        <React.Fragment key={n.key}>
          <div className={`pipe-node ${pipeState[n.key] || ''}`}>
            <span className="pipe-icon">{n.icon}</span>
            <span className="pipe-label">{n.label}</span>
          </div>
          {i < nodes.length - 1 && <span className="pipe-arrow">→</span>}
        </React.Fragment>
      ))}
    </div>
  );
}

const initStats = () => {
  try { return JSON.parse(localStorage.getItem('sec_stats')) || { xss: 0, sqli: 0, csrf: 0, cors: 0, safe: 0, total: 0 }; }
  catch { return { xss: 0, sqli: 0, csrf: 0, cors: 0, safe: 0, total: 0 }; }
};

export default function App() {
  const [input, setInput]           = useState('');
  const [output, setOutput]         = useState(null);
  const [activeTab, setActiveTab]   = useState('demo');
  const [csrfReady, setCsrfReady]   = useState(false);
  const [vulnerableMode, setVulnerableMode] = useState(false);
  const [attackLog, setAttackLog]   = useState([]);
  const [stats, setStats]           = useState(initStats);
  const [pipeState, setPipeState]   = useState({});
  const [theme, setTheme]           = useState(() => localStorage.getItem('theme') || 'dark');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  };

  useEffect(() => {
    axios.get(`${API}/api/csrf-token`, { withCredentials: true })
      .then(res => { axios.defaults.headers.post['X-CSRF-Token'] = res.data.csrfToken; setCsrfReady(true); })
      .catch(err => console.error('Gagal ambil token CSRF:', err));
  }, []);

  const addLog = (type, payload, result) => {
    const entry = { time: new Date().toLocaleTimeString('id-ID'), type, payload: payload.slice(0, 40), result };
    setAttackLog(prev => [entry, ...prev].slice(0, 50));
  };

  const updateStats = (type) => {
    setStats(prev => {
      const next = { ...prev, [type]: (prev[type] || 0) + 1, total: prev.total + 1 };
      localStorage.setItem('sec_stats', JSON.stringify(next));
      return next;
    });
  };

  const handleToggleMode = async () => {
    try {
      const res = await axios.post(`${API}/api/toggle-mode`);
      const isVuln = res.data.vulnerableMode;
      setVulnerableMode(isVuln);
      if (!isVuln) {
        // Ambil ulang CSRF token setelah kembali ke mode aman
        const t = await axios.get(`${API}/api/csrf-token`, { withCredentials: true });
        axios.defaults.headers.post['X-CSRF-Token'] = t.data.csrfToken;
      }
    } catch { alert('Gagal toggle mode. Pastikan server berjalan.'); }
  };

  const handleSubmit = async () => {
    if (!input.trim()) return;
    const sanitized = DOMPurify.sanitize(input);
    const isXss  = input !== sanitized;
    const isSqli = /['\";]|drop\s|select\s|insert\s|delete\s|update\s/i.test(input);

    // Animasi pipeline
    setPipeState({ input: 'active-ok' });
    await delay(200);
    setPipeState({ input: 'active-ok', xss: isXss ? 'active-err' : 'active-ok' });
    await delay(200);
    setPipeState(p => ({ ...p, csrf: 'active-ok' }));
    await delay(200);
    setPipeState(p => ({ ...p, cors: 'active-ok' }));
    await delay(200);
    setPipeState(p => ({ ...p, sqli: isSqli ? 'active-warn' : 'active-ok' }));
    await delay(200);
    setPipeState(p => ({ ...p, db: 'active-ok' }));

    try {
      const res = await axios.post(`${API}/api/data`, { input }, { withCredentials: true });
      const cards = [];

      if (vulnerableMode) {
        cards.push(
          <ResultCard key="vuln-warn" type="warning">
            <strong>⚠️ Mode Rentan Aktif — {res.data.message}</strong>
            {res.data.sql && <><br/>Query yang dieksekusi: <code>{res.data.sql}</code></>}
          </ResultCard>
        );
      } else {
        cards.push(
          <ResultCard key="ok" type="success">
            <strong>✅ Server Menerima — Data Berhasil Disimpan dengan Aman</strong>
            Input disimpan ke SQLite menggunakan parameterized query.
          </ResultCard>
        );
      }

      if (isXss) {
        cards.push(
          <ResultCard key="xss" type="danger">
            <strong>⚡ Serangan XSS Terdeteksi &amp; Dinetralkan</strong>
            DOMPurify menghapus payload berbahaya sebelum ditampilkan.<br />
            <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>
              Input asli: <code>{input}</code><br />
              Output aman: <strong>{sanitized === '' ? '[Dihapus Sepenuhnya]' : sanitized}</strong>
            </span>
          </ResultCard>
        );
        addLog('xss', input, '❌ Diblokir');
        updateStats('xss');
      } else if (isSqli) {
        addLog('sqli', input, '❌ Diblokir');
        updateStats('sqli');
      } else {
        addLog('safe', input, '✅ Aman');
        updateStats('safe');
      }

      if (isSqli) {
        cards.push(
          <ResultCard key="sqli" type="info">
            <strong>💉 SQL Injection Terdeteksi — Ditangani dengan Aman</strong>
            Karakter <code>'</code> atau perintah <code>DROP/SELECT</code> ditemukan.
            {vulnerableMode
              ? <><br/><strong style={{color:'var(--red)'}}>⚠️ Mode Rentan: Query langsung dieksekusi tanpa sanitasi SQL!</strong></>
              : <><br/>Backend menggunakan <strong>parameterized query</strong> — disimpan sebagai teks biasa.</>}
          </ResultCard>
        );
      }

      if (!isXss && !isSqli) {
        cards.push(
          <ResultCard key="clean" type="success">
            <strong>✅ Input Bersih — Tidak Ada Ancaman Terdeteksi</strong>
            Tidak ada XSS, SQL Injection, atau karakter berbahaya ditemukan.
          </ResultCard>
        );
      }

      setOutput(cards);
    } catch (err) {
      setOutput(
        <ResultCard type="warning">
          <strong>⚠️ Pengiriman Gagal</strong>
          {err.response ? `Respons server: ${err.response.status}` : err.message}
        </ResultCard>
      );
    }
  };

  const simulateCsrf = async () => {
    setPipeState({ input: 'active-ok', xss: 'active-ok', csrf: 'active-err' });
    try {
      const malicious = axios.create();
      await malicious.post(`${API}/api/data`, { input: 'Diretas!' });
      setOutput(<ResultCard type="warning"><strong>⚠️ Tidak Terduga: Permintaan Berhasil</strong></ResultCard>);
    } catch (err) {
      const status = err.response?.status;
      addLog('csrf', 'Tanpa Token CSRF', '❌ Diblokir');
      updateStats('csrf');
      if (status === 403) {
        setOutput(
          <ResultCard type="purple">
            <strong>🎭 Serangan CSRF Diblokir! (403 Forbidden)</strong>
            Backend menolak karena tidak ada header <code>X-CSRF-Token</code> yang valid.<br />
            <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
              Ini persis yang terjadi ketika hacker mencoba memalsukan permintaan dari situs lain.
              Tanpa token rahasia yang hanya dimiliki browser Anda, server langsung menolak.
            </span>
          </ResultCard>
        );
      } else {
        setOutput(
          <ResultCard type="purple">
            <strong>🎭 Serangan CSRF Diblokir! (Error CORS/Jaringan)</strong>
            Browser sendiri menolak permintaan lintas-asal — lapisan perlindungan tambahan.<br />
            <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>Error: {err.message}</span>
          </ResultCard>
        );
      }
    }
  };

  const simulateCors = async () => {
    setPipeState({ input: 'active-ok', xss: 'active-ok', csrf: 'active-ok', cors: 'active-err' });
    addLog('cors', 'Origin: hacker.com', '❌ Diblokir');
    updateStats('cors');
    try {
      const res = await axios.get(`${API}/api/cors-test`, { withCredentials: true });
      setOutput(
        <ResultCard type="info">
          <strong>🌐 Hasil Uji Kebijakan CORS</strong>
          {res.data.message}<br />
          <span style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
            Origin permintaan: <code>{res.data.requestOrigin}</code><br />
            Origin yang diizinkan: <code>{res.data.allowedOrigin}</code><br />
            <br />
            <strong>Catatan:</strong> Request ini berhasil karena berasal dari origin yang benar ({res.data.allowedOrigin}).
            Jika dikirim dari domain lain (misal hacker.com), browser akan memblokir responsnya secara otomatis.
          </span>
        </ResultCard>
      );
    } catch (err) {
      setOutput(<ResultCard type="danger"><strong>🌐 CORS Memblokir Request</strong>{err.message}</ResultCard>);
    }
  };

  const handleExport = () => {
    const lines = [
      '=== LAPORAN SESI DEMO KEAMANAN WEB ===',
      `Waktu: ${new Date().toLocaleString('id-ID')}`,
      '',
      '--- STATISTIK ---',
      `Total Percobaan : ${stats.total}`,
      `XSS Diblokir   : ${stats.xss}`,
      `SQLi Diblokir  : ${stats.sqli}`,
      `CSRF Diblokir  : ${stats.csrf}`,
      `CORS Diblokir  : ${stats.cors}`,
      `Input Aman     : ${stats.safe}`,
      '',
      '--- LOG SERANGAN ---',
      ...attackLog.map(e => `[${e.time}] [${e.type.toUpperCase()}] "${e.payload}" → ${e.result}`),
      '',
      '--- KESIMPULAN ---',
      'Semua serangan yang terdeteksi berhasil diblokir oleh sistem keamanan:',
      '  • XSS: DOMPurify menghapus tag berbahaya sebelum render',
      '  • CSRF: csurf middleware memvalidasi token di setiap POST',
      '  • SQL Injection: Parameterized query mencegah eksekusi SQL berbahaya',
      '  • CORS: Server hanya menerima request dari origin yang diizinkan',
    ];
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `laporan-keamanan-${Date.now()}.txt`; a.click();
    URL.revokeObjectURL(url);
  };

  const handleClear = () => { setInput(''); setOutput(null); setPipeState({}); };
  const handleClearLog = () => { setAttackLog([]); setStats({ xss:0, sqli:0, csrf:0, cors:0, safe:0, total:0 }); localStorage.removeItem('sec_stats'); };

  const tabs = [
    { key: 'demo',  label: '🛡️ Demo Langsung' },
    { key: 'about', label: '📖 Cara Kerja' },
    { key: 'code',  label: '💻 Kode Sumber' },
    { key: 'quiz',  label: '🧩 Quiz' },
  ];

  return (
    <div className="app-wrapper">
      <header className="app-header">
        <div className="header-badge"><span className="dot" /> Demo Keamanan Web</div>
        <h1 className="app-title">React + Express yang Aman</h1>
        <p className="app-subtitle">Demonstrasi interaktif perlindungan XSS, CSRF, SQL Injection, dan CORS.</p>
        <div className="security-tags">
          <span className="sec-tag xss">⚡ XSS</span>
          <span className="sec-tag csrf">🎭 CSRF</span>
          <span className="sec-tag sqli">💉 SQL Injection</span>
          <span className="sec-tag cors">🌐 CORS</span>
        </div>
      </header>

      {/* Statistik */}
      <div className="stats-bar">
        {[
          { key:'total', label:'Total Percobaan' },
          { key:'xss',   label:'XSS Diblokir' },
          { key:'sqli',  label:'SQLi Diblokir' },
          { key:'csrf',  label:'CSRF Diblokir' },
          { key:'cors',  label:'CORS Diblokir' },
          { key:'safe',  label:'Input Aman' },
        ].map(s => (
          <div key={s.key} className={`stat-card ${s.key}`}>
            <div className="stat-num">{stats[s.key] || 0}</div>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Vulnerable Mode Banner */}
      {vulnerableMode && (
        <div className="vuln-banner">
          <span>⚠️ MODE RENTAN AKTIF — Semua proteksi dinonaktifkan untuk demo!</span>
          <button className="btn-vuln-toggle vuln" onClick={handleToggleMode}>Aktifkan Mode Aman</button>
        </div>
      )}

      <div className="status-bar">
        <div className="dot-green" />
        <span style={{ flex: 1 }}>
          {csrfReady ? 'Token CSRF aktif — Semua lapisan keamanan berjalan. Server di port 4000.' : 'Menghubungkan ke backend…'}
        </span>
        <button
          className="btn-theme-toggle"
          onClick={toggleTheme}
          style={{ marginRight: '8px' }}
          title={theme === 'dark' ? 'Ganti ke Mode Terang' : 'Ganti ke Mode Gelap'}
        >
          {theme === 'dark' ? '☀️ Terang' : '🌙 Gelap'}
        </button>
        <button
          className={`btn-vuln-toggle ${vulnerableMode ? 'vuln' : 'safe'}`}
          onClick={handleToggleMode}
        >
          {vulnerableMode ? '🔴 Mode: RENTAN' : '🟢 Mode: AMAN'}
        </button>
      </div>

      <div className="main-card">
        <div className="card-header">
          {tabs.map(t => (
            <button key={t.key} className={`tab-btn ${activeTab === t.key ? 'active' : ''}`} onClick={() => setActiveTab(t.key)}>
              {t.label}
            </button>
          ))}
        </div>

        <div className="card-body">

          {/* ── TAB: DEMO ── */}
          {activeTab === 'demo' && (
            <>
              <div className="section-label"><span className="icon">📝</span> Input Uji Coba</div>
              <textarea className="input-area" value={input} onChange={e => setInput(e.target.value)}
                placeholder={"Coba: <script>alert(1)</script>  atau  '); DROP TABLE user_input; --"} />

              <div className="inject-chips">
                <span className="inject-label">⚡ Inject cepat:</span>
                {PAYLOADS.map(p => (
                  <button key={p.value} className={`chip ${p.type}`} onClick={() => setInput(p.value)}>{p.label}</button>
                ))}
              </div>

              <div className="btn-row">
                <button className="btn btn-blue"    onClick={handleSubmit}>✅ Kirim dengan Aman</button>
                <button className="btn btn-red"     onClick={simulateCsrf}>🎭 Simulasi Serangan CSRF</button>
                <button className="btn btn-cyan"    onClick={simulateCors}>🌐 Uji Kebijakan CORS</button>
                <button className="btn btn-outline" onClick={handleClear}>🗑 Bersihkan</button>
              </div>

              <div className="section-label"><span className="icon">🔀</span> Alur Keamanan</div>
              <SecurityPipeline pipeState={pipeState} />

              <div className="output-section">
                <div className="section-label"><span className="icon">🔍</span> Hasil Analisis Keamanan</div>
                <div className="output-box">
                  {output ?? <span className="output-empty">Kirimkan sesuatu di atas untuk melihat hasil analisis keamanan…</span>}
                </div>
              </div>

              {/* Log Serangan */}
              <div className="log-panel">
                <div className="log-header">
                  <span>📋 Log Serangan Real-Time</span>
                  <button className="btn btn-outline" style={{ padding: '4px 10px', fontSize: '0.75rem' }} onClick={handleClearLog}>Bersihkan</button>
                </div>
                <div className="log-entries">
                  {attackLog.length === 0
                    ? <div className="log-empty">Belum ada aktivitas yang dicatat…</div>
                    : attackLog.map((e, i) => (
                      <div key={i} className="log-entry">
                        <span className="log-time">{e.time}</span>
                        <span className={`log-badge ${e.type}`}>{e.type.toUpperCase()}</span>
                        <span className="log-payload">{e.payload}</span>
                        <span className={`log-result ${e.result.includes('❌') ? 'blocked' : 'warning'}`}>{e.result}</span>
                      </div>
                    ))
                  }
                </div>
              </div>
            </>
          )}

          {/* ── TAB: CARA KERJA ── */}
          {activeTab === 'about' && (
            <>
              <div className="section-label" style={{ marginBottom: 20 }}><span className="icon">🛡️</span> Lapisan Keamanan dalam Aplikasi Ini</div>
              <div className="info-grid">
                {INFO_CARDS.map(c => (
                  <div key={c.cls} className={`info-card ${c.cls}`}>
                    <div className="info-card-icon">{c.icon}</div>
                    <div className="info-card-title">{c.title}</div>
                    <div className="info-card-desc">{c.desc}</div>
                    <div className="info-card-fix">{c.fix}</div>
                  </div>
                ))}
              </div>
              <ResultCard type="info">
                <strong>📦 Teknologi yang Digunakan</strong>
                <strong>Frontend:</strong> React 19 + Vite · <code>dompurify</code> · <code>axios</code><br />
                <strong>Backend:</strong> Express · <code>csurf</code> · <code>sqlite3</code> · <code>cors</code> · <code>cookie-parser</code>
              </ResultCard>
              <div style={{ marginTop: 16 }}>
                <ResultCard type="success">
                  <strong>🧪 Cara Melakukan Pengujian</strong>
                  1. Buka tab <strong>Demo Langsung</strong> → klik chip inject cepat → tekan <strong>Kirim dengan Aman</strong><br />
                  2. Klik <strong>Simulasi Serangan CSRF</strong> untuk melihat error 403 Forbidden<br />
                  3. Klik <strong>Uji Kebijakan CORS</strong> untuk melihat penjelasan kebijakan CORS<br />
                  4. Toggle <strong>Mode Rentan</strong> untuk melihat perbedaan saat perlindungan dimatikan<br />
                  5. Kerjakan <strong>Quiz</strong> untuk menguji pemahaman Anda!
                </ResultCard>
              </div>
            </>
          )}

          {/* ── TAB: KODE SUMBER ── */}
          {activeTab === 'code' && (
            <>
              <div className="section-label" style={{ marginBottom: 20 }}><span className="icon">💻</span> Perbandingan Kode Rentan vs Aman</div>
              {CODE_SNIPPETS.map(s => (
                <div key={s.type} style={{ marginBottom: 20 }}>
                  <div className="section-label"><span className={`sec-tag ${s.type}`}>{s.title}</span></div>
                  <div className="code-grid">
                    <div className="code-block">
                      <div className="code-block-header"><span>{s.title}</span><span className="tag-vuln">❌ RENTAN</span></div>
                      <pre>{s.vuln}</pre>
                    </div>
                    <div className="code-block">
                      <div className="code-block-header"><span>{s.title}</span><span className="tag-safe">✅ AMAN</span></div>
                      <pre>{s.safe}</pre>
                    </div>
                  </div>
                </div>
              ))}
            </>
          )}

          {/* ── TAB: QUIZ ── */}
          {activeTab === 'quiz' && (
            <>
              <div className="section-label" style={{ marginBottom: 20 }}><span className="icon">🧩</span> Quiz Keamanan Web</div>
              <Quiz />
            </>
          )}
        </div>
      </div>

      <footer className="app-footer">
        <div>Demo Keamanan Web · React + Express · Dibuat untuk tujuan edukasi</div>
        <div className="footer-actions">
          <button className="btn btn-green" onClick={handleExport}>📄 Unduh Laporan Sesi</button>
          <button className="btn btn-outline" onClick={handleClearLog}>🔄 Reset Statistik</button>
        </div>
      </footer>
    </div>
  );
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
