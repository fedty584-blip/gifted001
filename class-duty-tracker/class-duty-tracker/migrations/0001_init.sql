PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1))
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  roll_number TEXT NOT NULL,
  full_name TEXT NOT NULL,
  class_name TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_students_active ON students(active, roll_number);

CREATE TABLE IF NOT EXISTS school_days (
  day_date TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('holiday','school_day')),
  title TEXT NOT NULL,
  updated_by INTEGER REFERENCES admins(id),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS daily_records (
  day_date TEXT PRIMARY KEY,
  saved_by INTEGER NOT NULL REFERENCES admins(id),
  saved_at TEXT NOT NULL DEFAULT (datetime('now')),
  confirmed INTEGER NOT NULL DEFAULT 0 CHECK (confirmed IN (0,1))
);

CREATE TABLE IF NOT EXISTS duty_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  day_date TEXT NOT NULL REFERENCES daily_records(day_date) ON DELETE CASCADE,
  student_id INTEGER NOT NULL REFERENCES students(id),
  status TEXT NOT NULL CHECK(status IN ('done','not_done','excused')),
  note TEXT NOT NULL DEFAULT '',
  updated_by INTEGER NOT NULL REFERENCES admins(id),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(day_date, student_id)
);
CREATE INDEX IF NOT EXISTS idx_duty_entries_date ON duty_entries(day_date);
CREATE INDEX IF NOT EXISTS idx_duty_entries_student ON duty_entries(student_id, day_date);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER REFERENCES admins(id),
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  before_json TEXT,
  after_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO settings(key, value) VALUES ('class_label', 'ห้องเรียนของฉัน');
