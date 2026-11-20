PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS targets (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  token      TEXT UNIQUE NOT NULL,
  label      TEXT,
  created_at TEXT NOT NULL,
  notes      TEXT
);

CREATE TABLE IF NOT EXISTS hits (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  token    TEXT NOT NULL,
  stage    TEXT NOT NULL,        -- fingerprint | gps | refine | denied | timeout | nogeo
  ip       TEXT,
  ip_json  TEXT,
  ua       TEXT,
  lat      REAL,
  lon      REAL,
  acc      REAL,
  place    TEXT,
  payload  TEXT,
  ts       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hits_token ON hits(token, id DESC);
