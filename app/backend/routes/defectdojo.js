// ============================================================
//  ToolVault — DefectDojo Integration Routes
// ============================================================

import { Router } from 'express'
import { requireAuth } from '../middleware/auth.js'
import { getSetting } from './settings.js'

const router = Router()

function getDefectDojoConfig() {
  // Read from DB first (set via Integrations page), fall back to env vars
  // This makes it work both locally (via .env) and in production (via ECS env)
  const url    = getSetting('defectdojo_url')     || process.env.DEFECTDOJO_URL     || ''
  const apiKey = getSetting('defectdojo_api_key') || process.env.DEFECTDOJO_API_KEY || ''
  return { url: url.replace(/\/$/, ''), apiKey }
}

async function ddFetch(endpoint) {
  const { url, apiKey } = getDefectDojoConfig()

  if (!url)    throw new Error('DefectDojo URL not configured. Go to Integrations to set it.')
  if (!apiKey) throw new Error('DefectDojo API key not configured. Go to Integrations to set it.')

  const response = await fetch(`${url}/api/v2${endpoint}`, {
    headers: {
      'Authorization': `Token ${apiKey}`,
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
  })

  if (!response.ok) {
    const status = response.status
    if (status === 401) throw new Error('DefectDojo API key is invalid or expired.')
    if (status === 403) throw new Error('DefectDojo API key lacks permission.')
    if (status === 404) throw new Error('DefectDojo endpoint not found. Check the URL.')
    throw new Error(`DefectDojo returned HTTP ${status}.`)
  }

  return response.json()
}

function normalizeFinding(f) {
  return {
    id:            f.id,
    title:         f.title,
    severity:      (f.severity || 'Info').toLowerCase(),
    description:   f.description || '',
    file:          f.file_path || '',
    line:          f.line || null,
    scanner:       f.test?.test_type?.name || 'Unknown',
    status:        f.active ? 'active' : 'closed',
    falsePositive: f.false_p || false,
    cwe:           f.cwe || null,
    url:           f.url || '',
    notesCount:    f.notes?.length || 0,
    foundDate:     f.date || '',
    engagement:    f.test?.engagement?.name || '',
  }
}

// GET /api/defectdojo/status
router.get('/status', requireAuth, async (req, res) => {
  try {
    await ddFetch('/users/?limit=1')
    res.json({ connected: true, message: 'DefectDojo connection successful.' })
  } catch (err) {
    res.json({ connected: false, message: err.message })
  }
})

// GET /api/defectdojo/findings
router.get('/findings', requireAuth, async (req, res) => {
  try {
    const limit      = parseInt(req.query.limit) || 50
    const severity   = req.query.severity || ''
    const engagement = req.query.engagement || ''

    let endpoint = `/findings/?active=true&false_p=false&limit=${limit}&ordering=-severity`
    if (severity)   endpoint += `&severity=${severity}`
    if (engagement) endpoint += `&test__engagement=${engagement}`

    const data = await ddFetch(endpoint)
    const findings = (data.results || []).map(normalizeFinding)
    res.json({ findings, total: data.count || findings.length })
  } catch (err) {
    console.error('[DefectDojo] Error fetching findings:', err.message)
    res.status(502).json({ error: err.message })
  }
})

// GET /api/defectdojo/findings/summary
router.get('/findings/summary', requireAuth, async (req, res) => {
  try {
    const data = await ddFetch('/findings/?active=true&false_p=false&limit=200&ordering=-severity')
    const findings = data.results || []

    const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }
    for (const f of findings) {
      const sev = (f.severity || 'Info').toLowerCase()
      if (sev in summary) summary[sev]++
      else summary.info++
      summary.total++
    }

    let riskLevel = 'clean'
    if (summary.critical > 0)    riskLevel = 'critical'
    else if (summary.high > 0)   riskLevel = 'high'
    else if (summary.medium > 0) riskLevel = 'medium'
    else if (summary.low > 0)    riskLevel = 'low'
    else if (summary.total > 0)  riskLevel = 'info'

    res.json({ summary, riskLevel })
  } catch (err) {
    console.error('[DefectDojo] Error fetching summary:', err.message)
    res.status(502).json({ error: err.message })
  }
})

export default router
