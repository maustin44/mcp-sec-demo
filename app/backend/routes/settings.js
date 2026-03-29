// ============================================================
//  ToolVault — Settings Routes (Admin Only)
// ============================================================
//
//  These routes let admins manage integration settings from
//  the Integrations page (no .env editing or server restarts).
//
//  ENDPOINTS:
//    GET  /api/settings/integrations       — Get current config
//    PUT  /api/settings/integrations       — Save new config
//    POST /api/settings/integrations/test  — Test a GitHub connection
//
//  HOW SETTINGS WORK:
//    Settings are stored in the "settings" table as key-value pairs.
//    On first startup, defaults are seeded from .env (see database.js).
//    After that, the DB values take priority. This means admins can
//    change settings from the UI and they persist across restarts.
//
//  SECURITY:
//    - API tokens are encrypted with AES-256-GCM before storage
//    - Tokens are decrypted only when needed for API calls
//    - The GET endpoint only returns a masked preview, never the full token
//    - All settings endpoints require admin authentication
//
//  HOW TO ADD SETTINGS FOR A NEW INTEGRATION:
//    1. Add default values in database.js (defaultSettings object)
//    2. Add a getSetting() call for each new key
//    3. Add fields to the GET and PUT handlers below
//    4. Optionally add a /test endpoint for connection testing
//    5. Use encrypt()/decrypt() for any secret values (API keys, tokens)
//
//  EXPORTED HELPERS (used by other route files):
//    getSetting(key)  — Read a setting value from the DB (auto-decrypts secrets)
//
// ============================================================

import { Router } from 'express'
import { requireAuth, requireAdmin } from '../middleware/auth.js'
import { encrypt, decrypt } from '../utils/crypto.js'
import db from '../database.js'

const router = Router()

// ============================================================
//  Configuration: which settings keys contain secrets
// ============================================================
//
//  Add any key that stores a password, API token, or other
//  sensitive value here. These will be encrypted before storage
//  and decrypted when read via getSetting().

const SECRET_KEYS = [
  'github_token',
  // When adding a new integration, add its secret keys here:
  // 'defectdojo_api_key',
  // 'zap_api_key',
]

// ============================================================
//  Shared helpers — used by this file AND other route files
//  (e.g. github.js imports getSetting to read the current org)
// ============================================================

/**
 * getSetting(key) — Read a single setting from the database.
 * Returns the value as a string, or '' if not found.
 * Secret values (listed in SECRET_KEYS) are automatically decrypted.
 *
 * Example: const org = getSetting('github_org')
 * Example: const token = getSetting('github_token') // auto-decrypted
 */
export function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key)
  if (!row) return ''

  // Automatically decrypt secret values
  if (SECRET_KEYS.includes(key)) {
    return decrypt(row.value)
  }

  return row.value
}

/**
 * setSetting(key, value) — Write a setting to the database.
 * Creates the key if it doesn't exist, updates it if it does.
 * Secret values (listed in SECRET_KEYS) are automatically encrypted.
 */
function setSetting(key, value) {
  // Encrypt secret values before storing
  const storedValue = SECRET_KEYS.includes(key) ? encrypt(value) : value

  db.prepare(`
    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')
  `).run(key, storedValue, storedValue)
}

// ============================================================
//  Routes
// ============================================================

// ----- GET /integrations -----
// Returns the current integration configuration.
// Tokens are masked — never send full secrets to the frontend.
router.get('/integrations', requireAuth, requireAdmin, (req, res) => {
  const githubOrg    = getSetting('github_org')
  const githubToken  = getSetting('github_token')

  res.json({
    github: {
      org: githubOrg,
      hasToken: !!githubToken,
      // Show just enough of the token so the admin knows which one is set.
      // NEVER send the full token to the frontend.
      tokenPreview: githubToken
        ? githubToken.slice(0, 8) + '...' + githubToken.slice(-4)
        : '',
    },
    // When adding a new integration, add its config here too.
    // Example:
    // defectdojo: {
    //   url: getSetting('defectdojo_url'),
    //   hasApiKey: !!getSetting('defectdojo_api_key'),
    // },
  })
})

// ----- PUT /integrations -----
// Saves updated integration settings.
// Only updates fields that are present in the request body.
router.put('/integrations', requireAuth, requireAdmin, (req, res) => {
  const { github_org, github_token } = req.body

  // --- Input validation ---
  if (github_org !== undefined) {
    const trimmed = github_org.trim()
    if (trimmed.length > 100) {
      return res.status(400).json({ error: 'Organization name is too long.' })
    }
    if (trimmed && !/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
      return res.status(400).json({ error: 'Organization name can only contain letters, numbers, hyphens, and underscores.' })
    }
    setSetting('github_org', trimmed)
    // Also update runtime env so github routes pick it up immediately
    process.env.GITHUB_ORG = trimmed
  }

  if (github_token !== undefined) {
    const trimmed = github_token.trim()
    if (trimmed.length > 500) {
      return res.status(400).json({ error: 'Token is too long.' })
    }
    setSetting('github_token', trimmed) // setSetting auto-encrypts
    process.env.GITHUB_TOKEN = trimmed  // runtime env stays plaintext (in memory only)
  }

  // When adding a new integration, handle its fields here too.
  // Example:
  // const { defectdojo_url, defectdojo_api_key } = req.body
  // if (defectdojo_url !== undefined) setSetting('defectdojo_url', defectdojo_url.trim())
  // if (defectdojo_api_key !== undefined) setSetting('defectdojo_api_key', defectdojo_api_key.trim())

  res.json({ message: 'Settings updated successfully.' })
})

// ----- POST /integrations/test -----
// Tests the current GitHub connection by calling the GitHub API.
// Tries as an org first; if that 404s, tries as a personal user.
router.post('/integrations/test', requireAuth, requireAdmin, async (req, res) => {
  const owner = getSetting('github_org')
  const token = getSetting('github_token') // auto-decrypted by getSetting

  if (!owner) {
    return res.json({ success: false, error: 'No GitHub organization or username configured.' })
  }

  try {
    const headers = {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'ToolVault-Backend',
    }
    if (token) {
      headers['Authorization'] = `token ${token}`
    }

    // Try org endpoint first
    let response = await fetch(`https://api.github.com/orgs/${owner}`, { headers })

    // If not found as an org, try as a personal user account
    if (response.status === 404) {
      response = await fetch(`https://api.github.com/users/${owner}`, { headers })
    }

    if (!response.ok) {
      const status = response.status
      if (status === 401) return res.json({ success: false, error: 'Token is invalid or expired.' })
      if (status === 403) return res.json({ success: false, error: 'Rate limit exceeded. Try again later.' })
      if (status === 404) return res.json({ success: false, error: `"${owner}" not found on GitHub as an org or user.` })
      return res.json({ success: false, error: `GitHub returned HTTP ${status}.` })
    }

    const data = await response.json()
    res.json({
      success: true,
      org: {
        name: data.login,
        description: data.description || data.bio || '',
        publicRepos: data.public_repos,
        avatarUrl: data.avatar_url,
      },
    })
  } catch (err) {
    res.json({ success: false, error: 'Could not reach GitHub. Check your network connection.' })
  }
})

export default router
