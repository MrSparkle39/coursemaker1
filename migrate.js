// migrate.js — adds slides.slide_type if it doesn't exist
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = path.join(__dirname, 'coursemaker.db');
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) { console.error('DB open error:', err); process.exit(1); }
});

db.all(`PRAGMA table_info(slides);`, [], (err, rows) => {
  if (err) { console.error('PRAGMA error:', err); process.exit(1); }
  const hasColumn = rows.some(r => r.name === 'slide_type');
  if (hasColumn) {
    console.log('OK: slides.slide_type already exists.');
    db.close(); process.exit(0);
  }
  db.run(`ALTER TABLE slides ADD COLUMN slide_type TEXT NOT NULL DEFAULT 'standard';`, [], (err2) => {
    if (err2) { console.error('ALTER error:', err2); process.exit(1); }
    console.log('Done: added slides.slide_type (default "standard").');
    db.close(); process.exit(0);
  });
});
