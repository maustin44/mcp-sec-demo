// ============================================================
//  ToolVault — Database Setup
// ============================================================

import Database from 'better-sqlite3'
import bcrypt from 'bcryptjs'

const db = new Database('toolvault.sqlite')
db.pragma('journal_mode = WAL')

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    created_at    TEXT DEFAULT (datetime('now'))
  )
`)

db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  )
`)

const seedSetting = db.prepare(`
  INSERT INTO settings (key, value) VALUES (?, ?)
  ON CONFLICT(key) DO NOTHING
`)

const defaultSettings = {
  github_org:         process.env.GITHUB_ORG          || '',
  github_token:       process.env.GITHUB_TOKEN        || '',
  defectdojo_url:     process.env.DEFECTDOJO_URL      || 'http://mcp-sec-demo-dev-alb-1744594438.us-east-1.elb.amazonaws.com',
  defectdojo_api_key: process.env.DEFECTDOJO_API_KEY  || '',
}

for (const [key, value] of Object.entries(defaultSettings)) {
  seedSetting.run(key, value)
}

const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get()
if (userCount.count === 0) {
  const hash = bcrypt.hashSync('admin123', 12)
  db.prepare(
    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)'
  ).run('admin', hash, 'admin')
  console.log('  Default admin account created: admin / admin123')
  console.log('  Change the default password after first login!')
}

export default db
