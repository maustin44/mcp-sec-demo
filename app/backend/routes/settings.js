// ============================================================
//  ToolVault — Settings Routes (Admin Only)
// ============================================================

import { Router } from 'express'
import { requireAuth, requireAdmin } from '../middleware/auth.js'
import { encrypt, decrypt } from '../utils/crypto.js'
import db from '../database.js'

const router = Router()

const SECRET_KEYS = [
  'github_token',
  'defectdojo_api_key',
]

export function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key)
  if (!row) return ''
  if (SECRET_KEYS.includes(key)) {
    return decrypt(row.value)
  }
  return row.value
}

function setSetting(key, value) {
  const storedValue = SECRET_KEYS.includes(key) ? encrypt(value) : value
  db.prepare(`
    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')
  `).run(key, storedValue, storedValue)
}

// GET /integrations
router.get('/integrations', requireAuth, requireAdmin, (req, res) => {
  const githubOrg       = getSetting('github_org')
  const githubToken     = getSetting('github_token')
  const defectdojoUrl   = getSetting('defectdojo_url')
  const defectdojoKey   = getSetting('defectdojo_api_key')

  res.json({
    github: {
      org: githubOrg,
      hasToken: !!githubToken,
      tokenPreview: githubToken
        ? githubToken.slice(0, 8) + '...' + githubToken.slice(-4)
        : '',
    },
    defectdojo: {
      url: defectdojoUrl,
      hasApiKey: !!defectdojoKey,
      apiKeyPreview: defectdojoKey
        ? defectdojoKey.slice(0, 8) + '...' + defectdojoKey.slice(-4)
        : '',
    },
  })
})

// PUT /integrations
router.put('/integrations', requireAuth, requireAdmin, (req, res) => {
  const { github_org, github_token, defectdojo_url, defectdojo_api_key } = req.body

  if (github_org !== undefined) {
    const trimmed = github_org.trim()
    if (trimmed.length > 100) return res.status(400).json({ error: 'Organization name is too long.' })
    if (trimmed && !/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
      return res.status(400).json({ error: 'Organization name can only contain letters, numbers, hyphens, and underscores.' })
    }
    setSetting('github_org', trimmed)
    process.env.GITHUB_ORG = trimmed
  }

  if (github_token !== undefined) {
    const trimmed = github_token.trim()
    if (trimmed.length > 500) return res.status(400).json({ error: 'Token is too long.' })
    setSetting('github_token', trimmed)
    process.env.GITHUB_TOKEN = trimmed
  }

  if (defectdojo_url !== undefined) {
    const trimmed = defectdojo_url.trim().replace(/\/$/, '')
    setSetting('defectdojo_url', trimmed)
  }

  if (defectdojo_api_key !== undefined) {
    const trimmed = defectdojo_api_key.trim()
    setSetting('defectdojo_api_key', trimmed)
  }

  res.json({ message: 'Settings updated successfully.' })
})

// POST /integrations/test
router.post('/integrations/test', requireAuth, requireAdmin, async (req, res) => {
  const owner = getSetting('github_org')
  const token = getSetting('github_token')

  if (!owner) {
    return res.json({ success: false, error: 'No GitHub organization or username configured.' })
  }

  try {
    const headers = {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'ToolVault-Backend',
    }
    if (token) headers['Authorization'] = `token ${token}`

    let response = await fetch(`https://api.github.com/orgs/${owner}`, { headers })
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
