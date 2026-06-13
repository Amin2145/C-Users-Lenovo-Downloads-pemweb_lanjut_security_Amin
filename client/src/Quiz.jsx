import React, { useState } from 'react';

const QUESTIONS = [
  {
    id: 1,
    q: 'Apa kepanjangan dari XSS?',
    options: ['Cross-Site Scripting', 'Cross-Server Security', 'Cross-Site Session', 'Extra Security Script'],
    answer: 0,
    explanation: 'XSS (Cross-Site Scripting) adalah serangan di mana penyerang menyuntikkan skrip berbahaya ke halaman web yang dilihat pengguna lain.',
  },
  {
    id: 2,
    q: 'Alat apa yang digunakan di aplikasi ini untuk mencegah XSS?',
    options: ['axios', 'express', 'DOMPurify', 'sqlite3'],
    answer: 2,
    explanation: 'DOMPurify adalah library yang membersihkan HTML dari tag dan atribut berbahaya sebelum dirender ke DOM.',
  },
  {
    id: 3,
    q: 'Apa yang dimaksud dengan CSRF?',
    options: [
      'Cross-Site Request Forgery',
      'Client-Side Request Filtering',
      'Cross-Server Resource Fetch',
      'Cookie Session Request Fix',
    ],
    answer: 0,
    explanation: 'CSRF (Cross-Site Request Forgery) adalah serangan yang mengelabui pengguna terautentikasi agar mengirimkan permintaan yang tidak mereka inginkan ke server.',
  },
  {
    id: 4,
    q: 'Mengapa parameterized query mencegah SQL Injection?',
    options: [
      'Karena ia mengenkripsi data sebelum disimpan',
      'Karena ia memisahkan kode SQL dari data input pengguna',
      'Karena ia memblokir semua karakter spesial',
      'Karena ia menggunakan HTTPS',
    ],
    answer: 1,
    explanation: 'Parameterized query memisahkan perintah SQL dari data pengguna. Database memperlakukan input sebagai teks biasa, bukan sebagai bagian dari perintah SQL.',
  },
  {
    id: 5,
    q: 'Apa yang dilakukan kebijakan CORS pada browser?',
    options: [
      'Mengenkripsi semua data yang dikirim',
      'Memblokir permintaan ke server yang sama',
      'Membatasi halaman web agar tidak dapat meminta resource dari domain lain yang tidak diizinkan',
      'Menyimpan sesi login pengguna',
    ],
    answer: 2,
    explanation: 'CORS (Cross-Origin Resource Sharing) adalah mekanisme browser yang membatasi permintaan HTTP ke domain lain. Server harus secara eksplisit mengizinkan origin tertentu.',
  },
];

export default function Quiz() {
  const [current, setCurrent]   = useState(0);
  const [selected, setSelected] = useState(null);
  const [answers, setAnswers]   = useState([]);
  const [finished, setFinished] = useState(false);

  const q = QUESTIONS[current];

  const handleSelect = (idx) => {
    if (selected !== null) return; // sudah dijawab
    setSelected(idx);
  };

  const handleNext = () => {
    const newAnswers = [...answers, { questionId: q.id, selected, correct: selected === q.answer }];
    setAnswers(newAnswers);

    if (current + 1 >= QUESTIONS.length) {
      setFinished(true);
    } else {
      setCurrent(current + 1);
      setSelected(null);
    }
  };

  const handleReset = () => {
    setCurrent(0);
    setSelected(null);
    setAnswers([]);
    setFinished(false);
  };

  const score = answers.filter(a => a.correct).length;

  if (finished) {
    const pct = Math.round((score / QUESTIONS.length) * 100);
    let verdict = '';
    let cls     = '';
    if (pct === 100)      { verdict = '🏆 Sempurna! Anda ahli keamanan web!'; cls = 'success'; }
    else if (pct >= 60)   { verdict = '👍 Bagus! Anda cukup memahami konsep keamanan web.'; cls = 'info'; }
    else                  { verdict = '📚 Coba lagi! Pelajari lebih lanjut tentang keamanan web.'; cls = 'warning'; }

    return (
      <div className="quiz-wrapper">
        <div className={`result-card ${cls}`} style={{ marginBottom: 24 }}>
          <strong>Skor Anda: {score} / {QUESTIONS.length} ({pct}%)</strong><br />
          {verdict}
        </div>

        <div className="quiz-review">
          {QUESTIONS.map((qs, i) => {
            const ans = answers[i];
            const correct = ans.selected === qs.answer;
            return (
              <div key={qs.id} className={`quiz-review-item ${correct ? 'correct' : 'wrong'}`}>
                <p className="quiz-review-q"><strong>Q{i + 1}:</strong> {qs.q}</p>
                <p className="quiz-review-a">
                  Jawaban Anda: <strong>{qs.options[ans.selected]}</strong> {correct ? '✅' : '❌'}<br />
                  {!correct && <>Jawaban Benar: <strong>{qs.options[qs.answer]}</strong><br /></>}
                  <span className="quiz-explanation">💡 {qs.explanation}</span>
                </p>
              </div>
            );
          })}
        </div>

        <button className="btn btn-blue" style={{ marginTop: 20 }} onClick={handleReset}>
          🔄 Ulangi Quiz
        </button>
      </div>
    );
  }

  return (
    <div className="quiz-wrapper">
      <div className="quiz-progress-bar">
        <div className="quiz-progress-fill" style={{ width: `${((current) / QUESTIONS.length) * 100}%` }} />
      </div>
      <p className="quiz-counter">Pertanyaan {current + 1} dari {QUESTIONS.length}</p>

      <p className="quiz-question">{q.q}</p>

      <div className="quiz-options">
        {q.options.map((opt, idx) => {
          let cls = 'quiz-option';
          if (selected !== null) {
            if (idx === q.answer)  cls += ' correct';
            else if (idx === selected) cls += ' wrong';
          }
          return (
            <button key={idx} className={cls} onClick={() => handleSelect(idx)}>
              <span className="quiz-option-letter">{String.fromCharCode(65 + idx)}</span>
              {opt}
            </button>
          );
        })}
      </div>

      {selected !== null && (
        <div className={`result-card ${selected === q.answer ? 'success' : 'danger'}`} style={{ marginTop: 16 }}>
          {selected === q.answer ? '✅ Benar!' : `❌ Salah. Jawaban yang benar: ${q.options[q.answer]}`}<br />
          <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>💡 {q.explanation}</span>
        </div>
      )}

      {selected !== null && (
        <button className="btn btn-blue" style={{ marginTop: 16 }} onClick={handleNext}>
          {current + 1 >= QUESTIONS.length ? '🏁 Lihat Hasil' : 'Soal Berikutnya →'}
        </button>
      )}
    </div>
  );
}
