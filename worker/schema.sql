CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cfg_key TEXT NOT NULL,
  ts INTEGER NOT NULL,
  ok INTEGER NOT NULL,
  ping_ms INTEGER,
  speed_mbps REAL,
  cc TEXT,
  transport TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_key_ts ON history (cfg_key, ts);
