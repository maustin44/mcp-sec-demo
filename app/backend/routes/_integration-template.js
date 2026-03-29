// ============================================================
//  ToolVault — Integration Template
// ============================================================
//
//  COPY THIS FILE to create a new integration. For example,
//  to add DefectDojo support:
//
//    1. Copy this file → routes/defectdojo.js
//    2. Find-and-replace these placeholders:
//         TOOL_NAME       → DefectDojo
//         tool_name       → defectdojo
//         TOOL_API_BASE   → https://your-defectdojo-instance.com/api/v2
//         toolFetch       → defectdojoFetch
//         normalizeItem   → normalizeFinding
//         /items          → /findings
//
//    3. Add settings keys in database.js:
//         defectdojo_url: process.env.DEFECTDOJO_URL || '',
//         defectdojo_api_key: process.env.DEFECTDOJO_API_KEY || '',
//
//    4. Add the secret key to SECRET_KEYS in routes/settings.js:
//         'defectdojo_api_key',
//
//    5. Register routes in server.js:
//         import defectdojoRoutes from './routes/defectdojo.js'
//         app.use('/api/defectdojo', defectdojoRoutes)
//
//    6. Add settings fields to routes/settings.js GET/PUT handlers
//
//    7. Build the frontend:
//         - services/defectdojo.js (API calls)
//         - pages/DefectDojoPage.jsx (UI)
//         - Add route in App.jsx
//         - Add nav link in Navbar.jsx
//
//  SECURITY REMINDERS:
//    - Never expose API keys to the frontend
//    - Use getSetting() which auto-decrypts secrets
//    - Use requireAuth (or requireAdmin) on all routes
//    - Validate and sanitize all user input
//    - Return consistent error shapes: { error: "message" }
//
// ============================================================

import { Router } from 'express'
import { requireAuth } from '../middleware/auth.js'
import { getSetting } from './settings.js'

const router = Router()

// ============================================================
//  Configuration
// ============================================================

// The base URL of the external tool's API.
// Read from settings DB (admins can change this from the UI).
function getApiBase() {
  return getSetting('tool_name_url') || process.env.TOOL_NAME_URL || ''
}

// ============================================================
//  Helper: call the external tool's API
// ============================================================

/**
 * toolFetch(endpoint) — Make an authenticated request to TOOL_NAME.
 *
 * Reads the API key from the settings DB (auto-decrypted).
 * Throws a descriptive error if the request fails.
 *
 * Example: const items = await toolFetch('/api/v2/findings/')
 */
async function toolFetch(endpoint) {
  const baseUrl = getApiBase()
  const apiKey  = getSetting('tool_name_api_key')

  if (!baseUrl) {
    throw new Error('TOOL_NAME URL not configured. Go to Integrations to set one.')
  }

  const headers = {
    'Accept': 'application/json',
    'User-Agent': 'ToolVault-Backend',
  }

  // --- Authentication ---
  // Change this to match your tool's auth method:
  //   Bearer token:  headers['Authorization'] = `Bearer ${apiKey}`
  //   API key header: headers['X-API-Key'] = apiKey
  //   Basic auth:    headers['Authorization'] = `Basic ${btoa(user + ':' + pass)}`
  if (apiKey) {
    headers['Authorization'] = `Token ${apiKey}`
  }

  const url = `${baseUrl}${endpoint}`
  const response = await fetch(url, { headers })

  if (!response.ok) {
    const status = response.status
    console.error(`TOOL_NAME API error: ${status} ${endpoint}`)

    if (status === 401) throw new Error('TOOL_NAME API key is invalid or expired.')
    if (status === 403) throw new Error('TOOL_NAME access denied. Check permissions.')
    if (status === 404) throw new Error('TOOL_NAME endpoint not found. Check the URL.')
    throw new Error(`TOOL_NAME API error (HTTP ${status}).`)
  }

  return response.json()
}

// ============================================================
//  Helper: normalize external data into our standard shape
// ============================================================

/**
 * normalizeItem(rawItem) — Converts raw API data into the format
 * our frontend expects. This keeps the frontend decoupled from
 * the external API's shape.
 *
 * Customize the fields below to match what your tool returns
 * and what your frontend page needs to display.
 */
function normalizeItem(item) {
  return {
    id:          item.id,
    title:       item.title || item.name || 'Untitled',
    description: item.description || '',
    severity:    item.severity || 'Unknown',
    status:      item.status || item.active ? 'Active' : 'Resolved',
    createdAt:   item.created || item.created_at,
    updatedAt:   item.updated || item.updated_at,
    // Add more fields as needed by your frontend page
  }
}

// ============================================================
//  Route handlers
// ============================================================

// ----- GET /items -----
// Returns all items from TOOL_NAME.
// Rename this to something meaningful (e.g. /findings, /scans, /results).
router.get('/items', requireAuth, async (req, res) => {
  try {
    const data = await toolFetch('/api/v2/items/?limit=100')

    // Some APIs return { results: [...] }, others return [...] directly.
    // Adjust based on your tool's response shape.
    const items = Array.isArray(data) ? data : (data.results || [])

    res.json({ items: items.map(normalizeItem) })
  } catch (err) {
    res.status(502).json({ error: err.message })
  }
})

// ----- GET /items/search?q=keyword -----
// Search items by keyword (if the external API supports it).
router.get('/items/search', requireAuth, async (req, res) => {
  try {
    const query = req.query.q || ''

    if (!query.trim()) {
      // No search term — return all items
      const data = await toolFetch('/api/v2/items/?limit=100')
      const items = Array.isArray(data) ? data : (data.results || [])
      return res.json({ items: items.map(normalizeItem) })
    }

    // Search via the external API (adjust the query parameter name)
    const encoded = encodeURIComponent(query)
    const data = await toolFetch(`/api/v2/items/?search=${encoded}&limit=30`)
    const items = Array.isArray(data) ? data : (data.results || [])
    res.json({ items: items.map(normalizeItem) })
  } catch (err) {
    res.status(502).json({ error: err.message })
  }
})

// ----- GET /stats -----
// Returns summary statistics for the dashboard.
// Customize based on what makes sense for your tool.
router.get('/stats', requireAuth, async (req, res) => {
  try {
    const data = await toolFetch('/api/v2/items/?limit=500')
    const items = Array.isArray(data) ? data : (data.results || [])

    // Calculate summary stats
    const stats = {
      total: items.length,
      // Add tool-specific stats here, for example:
      // critical: items.filter(i => i.severity === 'Critical').length,
      // high:     items.filter(i => i.severity === 'High').length,
      // medium:   items.filter(i => i.severity === 'Medium').length,
      // low:      items.filter(i => i.severity === 'Low').length,
    }

    res.json({ stats })
  } catch (err) {
    res.status(502).json({ error: err.message })
  }
})

export default router
