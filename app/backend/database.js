// ============================================================
//  ToolVault — Database Setup
// ============================================================
//
//  Uses SQLite via better-sqlite3. The database is a single file
//  (toolvault.sqlite) that gets created automatically when the
//  server starts for the first time. Delete it to start fresh.
//
//  TABLES:
//    users    — Login accounts (admin creates these)
//    settings — Key-value config (GitHub org, tokens, etc.)
//
//  HOW TO ADD A NEW TABLE:
//    1. Add a db.exec(...) block below with your CREATE TABLE
//    2. Use the same pattern: CREATE TABLE IF NOT EXISTS
//    3. The table will be created on next server restart
//
//    Example for a future "scan_results" table:
//      db.exec(`
//        CREATE TABLE IF NOT EXISTS scan_results (
//          id INTEGER PRIMARY KEY AUTOINCREMENT,
//          tool_name TEXT NOT NULL,
//          repo_name TEXT NOT NULL,
//          severity TEXT,
//          finding TEXT,
//          created_at TEXT DEFAULT (datetime('now'))
//        )
//      `)
//
// ============================================================

import Database from 'better-sqlite3'
import bcrypt from 'bcryptjs'

// --- Open (or create) the database file ---
const db = new Database('toolvault.sqlite')
db.pragma('journal_mode = WAL') // Better performance for concurrent reads

// --- Users table ---
// Stores login accounts. Each user has a role: "admin" or "user".
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    created_at    TEXT DEFAULT (datetime('now'))
  )
`)

// --- Settings table ---
// Key-value store for runtime configuration. Admins can change
// these from the Integrations page without editing .env files.
// Keys follow the pattern: "integration_field" (e.g. "github_org").
db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  )
`)

// --- Seed default settings from .env ---
// On first run, copies values from .env into the settings table.
// After that, the DB values take priority (so admins can override
// them from the UI without touching .env).
const seedSetting = db.prepare(`
  INSERT INTO settings (key, value) VALUES (?, ?)
  ON CONFLICT(key) DO NOTHING
`)

const defaultSettings = {
  github_org:      process.env.GITHUB_ORG      || '',
  github_token:    process.env.GITHUB_TOKEN    || '',
  // When adding a new integration, seed its defaults here too.
  // Example: defectdojo_url: process.env.DEFECTDOJO_URL || '',
}

for (const [key, value] of Object.entries(defaultSettings)) {
  seedSetting.run(key, value)
}

// --- Seed default admin account ---
// Only runs if the users table is empty (first startup).
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get()
if (userCount.count === 0) {
  // Hash with 12 salt rounds (OWASP recommended minimum for production)
  const hash = bcrypt.hashSync('admin123', 12)
  db.prepare(
    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)'
  ).run('admin', hash, 'admin')
  console.log('  Default admin account created: admin / admin123')
  console.log('  ⚠  Change the default password after first login!')
}

export default db
