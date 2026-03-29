// ============================================================
//  ToolVault — Security Scan Routes
// ============================================================
//
//  These routes handle security scanning of GitHub repositories
//  and AI-powered fix recommendations via Claude.
//
//  THE TWO-STAGE FLOW:
//
//    STAGE 1 — SCAN (vulnerability detection)
//      The actual security scanning is handled by the MCP agent
//      (ai-agent/ folder). Right now we use a lightweight built-in
//      static analysis pass as a placeholder. When the MCP agent
//      is ready, swap in a call to its API (see INTEGRATION POINT).
//
//    STAGE 2 — FIX RECOMMENDATIONS (Claude AI)
//      After findings are collected, Claude reads the source code
//      + findings and recommends specific code fixes. This is what
//      the Anthropic API key is used for — NOT the scanning itself.
//
//  ENDPOINTS:
//    POST /api/scans              — Start a new scan for a repo
//    GET  /api/scans/:id          — Get scan status and results
//    GET  /api/scans              — List all scans (most recent first)
//    GET  /api/scans/repo/:name   — Get latest scan for a specific repo
//
// ============================================================

import { Router } from 'express'
import { requireAuth } from '../middleware/auth.js'
import { getSetting } from './settings.js'
import db from '../database.js'

const router = Router()

const GITHUB_API_BASE = 'https://api.github.com'

// Max files to pull per scan (keeps token usage and scan time reasonable)
const MAX_FILES_PER_SCAN = 20
// Max file size in bytes (skip large files like bundles)
const MAX_FILE_SIZE = 50000

// File extensions we care about for security analysis
const SCANNABLE_EXTENSIONS = [
  '.js', '.jsx', '.ts', '.tsx', '.py', '.rb', '.go', '.java',
  '.php', '.cs', '.rs', '.c', '.cpp', '.h', '.sql', '.sh',
  '.yml', '.yaml', '.json', '.toml', '.env', '.tf', '.hcl',
  '.dockerfile', '.xml', '.conf', '.cfg', '.ini',
]

// Files to always skip (even if the extension matches)
const SKIP_FILES = [
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'composer.lock', 'Gemfile.lock', 'Cargo.lock',
]

// ============================================================
//  Helper: authenticated GitHub API call
// ============================================================

async function githubFetch(endpoint) {
  const token = getSetting('github_token') || process.env.GITHUB_TOKEN

  const headers = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'ToolVault-Backend',
  }
  if (token) {
    headers['Authorization'] = `token ${token}`
  }

  const response = await fetch(`${GITHUB_API_BASE}${endpoint}`, { headers })

  if (!response.ok) {
    throw new Error(`GitHub API error (HTTP ${response.status})`)
  }

  return response.json()
}

// ============================================================
//  Helper: fetch a repo's file tree from GitHub
// ============================================================

async function fetchRepoTree(owner, repoName, branch) {
  const tree = await githubFetch(
    `/repos/${owner}/${repoName}/git/trees/${branch}?recursive=1`
  )

  const files = tree.tree
    .filter((item) => item.type === 'blob')
    .filter((item) => {
      const name = item.path.split('/').pop().toLowerCase()
      if (SKIP_FILES.includes(name)) return false
      const ext = '.' + name.split('.').pop()
      return SCANNABLE_EXTENSIONS.includes(ext) ||
        name === 'dockerfile' ||
        name === 'makefile'
    })
    .filter((item) => item.size <= MAX_FILE_SIZE)
    .sort((a, b) => a.size - b.size)
    .slice(0, MAX_FILES_PER_SCAN)

  return files
}

// ============================================================
//  Helper: fetch file contents from GitHub
// ============================================================

async function fetchFileContent(owner, repoName, filePath, branch) {
  try {
    const data = await githubFetch(
      `/repos/${owner}/${repoName}/contents/${filePath}?ref=${branch}`
    )
    if (data.content && data.encoding === 'base64') {
      return Buffer.from(data.content, 'base64').toString('utf-8')
    }
    return null
  } catch {
    return null
  }
}

// ============================================================
//  STAGE 1: Built-in static analysis (placeholder for MCP agent)
// ============================================================
//
//  INTEGRATION POINT — When the MCP agent (ai-agent/) is deployed to AWS:
//
//    Replace this function with a call to the MCP agent's API on AWS:
//
//      async function runSecurityScan(repoName, filesWithContent) {
//        const mcpUrl = getSetting('mcp_agent_url') || process.env.MCP_AGENT_URL
//        const response = await fetch(`${mcpUrl}/analyze`, {
//          method: 'POST',
//          headers: { 'Content-Type': 'application/json' },
//          body: JSON.stringify({ repo: repoName, files: filesWithContent }),
//        })
//        return response.json() // { findings: [...], summary, riskLevel }
//      }
//
//    You'll also need to:
//      1. Add MCP_AGENT_URL to .env.example and database.js defaultSettings
//      2. Add 'mcp_agent_api_key' to SECRET_KEYS in settings.js (if the
//         AWS endpoint requires auth)
//      3. Add the URL field to the Integrations page UI
//
//  The MCP agent (hosted on AWS) runs the actual scanner (SAST tools,
//  pattern matching, dependency checks, etc.) and returns structured
//  findings. The SPA backend then passes those findings to Claude
//  for fix recommendations.
//
//  This placeholder does basic pattern matching to demonstrate the
//  flow. It is NOT a real security scanner.
//
// ============================================================

function runStaticAnalysis(filesWithContent) {
  const findings = []

  // Patterns a real scanner would catch — this is just a demo
  const patterns = [
    {
      regex: /eval\s*\(/g,
      title: 'Use of eval()',
      severity: 'high',
      description: 'eval() executes arbitrary code and is a common injection vector. An attacker who controls the input can execute arbitrary JavaScript.',
      cwe: 'CWE-95',
    },
    {
      regex: /innerHTML\s*=/g,
      title: 'Direct innerHTML assignment',
      severity: 'medium',
      description: 'Setting innerHTML with user-controlled data can lead to Cross-Site Scripting (XSS) attacks.',
      cwe: 'CWE-79',
    },
    {
      regex: /(?:password|secret|api_key|apikey|token)\s*[:=]\s*['"][^'"]{3,}['"]/gi,
      title: 'Possible hardcoded secret',
      severity: 'high',
      description: 'A credential or secret value appears to be hardcoded in the source code. If committed to version control, it could be exposed.',
      cwe: 'CWE-798',
    },
    {
      regex: /cors\(\s*\)/g,
      title: 'Permissive CORS configuration',
      severity: 'medium',
      description: 'Calling cors() with no arguments allows any origin, which can enable cross-site request forgery or data exfiltration.',
      cwe: 'CWE-942',
    },
    {
      regex: /exec\s*\(\s*[`'"].*\$\{/g,
      title: 'Potential command injection via template literal',
      severity: 'critical',
      description: 'String interpolation in a shell exec call can allow command injection if user input reaches the template.',
      cwe: 'CWE-78',
    },
    {
      regex: /\.query\s*\(\s*['"`].*\+\s*(?:req\.|input|user|param)/gi,
      title: 'Potential SQL injection',
      severity: 'critical',
      description: 'String concatenation in a database query with user-controlled input is a classic SQL injection vector.',
      cwe: 'CWE-89',
    },
    {
      regex: /console\.\s*log\s*\(.*(?:password|token|secret|key)/gi,
      title: 'Logging sensitive data',
      severity: 'medium',
      description: 'Sensitive values (passwords, tokens, keys) appear to be logged, which could expose them in log files or monitoring systems.',
      cwe: 'CWE-532',
    },
    {
      regex: /(?:http:\/\/)/g,
      title: 'Insecure HTTP URL',
      severity: 'low',
      description: 'An HTTP (non-HTTPS) URL was found. Data sent over HTTP is transmitted in plain text and can be intercepted.',
      cwe: 'CWE-319',
    },
    {
      regex: /TODO.*(?:security|auth|hack|fix|vuln)/gi,
      title: 'Security-related TODO comment',
      severity: 'info',
      description: 'A TODO comment mentions a security-related topic, suggesting unfinished security work.',
      cwe: null,
    },
    {
      regex: /(?:disable|no).*(?:csrf|xss|auth|ssl|tls|verify)/gi,
      title: 'Security feature possibly disabled',
      severity: 'high',
      description: 'Code appears to disable a security feature (CSRF protection, SSL verification, authentication, etc.).',
      cwe: 'CWE-693',
    },
  ]

  for (const file of filesWithContent) {
    const lines = file.content.split('\n')

    for (const pattern of patterns) {
      // Reset regex state (global flag)
      pattern.regex.lastIndex = 0
      let match
      while ((match = pattern.regex.exec(file.content)) !== null) {
        // Figure out which line the match is on
        const upToMatch = file.content.slice(0, match.index)
        const lineNum = (upToMatch.match(/\n/g) || []).length + 1

        // Skip http:// findings in comments or well-known dev URLs
        if (pattern.cwe === 'CWE-319') {
          const matchedText = match[0] + file.content.slice(match.index, match.index + 60)
          if (matchedText.includes('localhost') || matchedText.includes('127.0.0.1') || matchedText.includes('example.com')) {
            continue
          }
        }

        findings.push({
          severity: pattern.severity,
          title: pattern.title,
          file: file.path,
          line: lineNum,
          description: pattern.description,
          recommendation: '', // Claude will fill this in
          cwe: pattern.cwe,
        })
      }
    }
  }

  // Determine overall risk level
  const hasCritical = findings.some((f) => f.severity === 'critical')
  const hasHigh = findings.some((f) => f.severity === 'high')
  const hasMedium = findings.some((f) => f.severity === 'medium')

  let riskLevel = 'clean'
  if (hasCritical) riskLevel = 'critical'
  else if (hasHigh) riskLevel = 'high'
  else if (hasMedium) riskLevel = 'medium'
  else if (findings.length > 0) riskLevel = 'low'

  return { findings, riskLevel }
}

// ============================================================
//  STAGE 2: Claude recommends fixes for scanner findings
// ============================================================
//
//  This is the AI layer. It takes the scanner's findings plus
//  the actual source code and asks Claude to recommend specific
//  code fixes. Claude does NOT do the scanning — it reads what
//  the scanner found and explains how to fix each issue.
//

async function getFixRecommendations(repoName, findings, filesWithContent) {
  const apiKey = getSetting('anthropic_key')

  if (!apiKey) {
    // No API key — return findings without fix recommendations.
    // The scan results are still useful; they just won't have AI fixes.
    console.log('[Scan] No Anthropic key configured — skipping fix recommendations')
    return {
      findings,
      summary: `Static analysis found ${findings.length} potential issue(s). Configure an Anthropic API key in Integrations to get AI-powered fix recommendations.`,
    }
  }

  // Build context: the findings + relevant file snippets
  const findingsByFile = {}
  for (const f of findings) {
    if (!findingsByFile[f.file]) findingsByFile[f.file] = []
    findingsByFile[f.file].push(f)
  }

  // Only include files that have findings (keeps token usage down)
  const relevantFiles = filesWithContent.filter((f) => findingsByFile[f.path])

  const fileBlocks = relevantFiles.map((f) =>
    `--- FILE: ${f.path} ---\n${f.content}\n--- END FILE ---`
  ).join('\n\n')

  const findingsJson = JSON.stringify(findings, null, 2)

  const systemPrompt = `You are a senior application security engineer. A security scanner has analyzed a codebase and produced findings. Your job is to:

1. Review each finding against the actual source code
2. Confirm whether the finding is a true positive or false positive
3. For true positives, recommend a specific code fix
4. Write a 2-3 sentence executive summary of the repo's security posture

Respond ONLY with valid JSON in this exact format:
{
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "title": "Short title (max 80 chars)",
      "file": "path/to/file.js",
      "line": 42,
      "description": "What the vulnerability is and why it matters",
      "recommendation": "Specific code fix — show the before/after or exact change to make",
      "cwe": "CWE-XXX or null",
      "falsePositive": false
    }
  ],
  "summary": "2-3 sentence executive summary"
}

Rules:
- Keep all true positive findings from the scanner. You may adjust severity if warranted.
- Mark false positives with "falsePositive": true and explain why in the description.
- The "recommendation" field is the most important part — be specific. Show the exact code change, not generic advice like "sanitize inputs". Show what the fixed code should look like.
- If a finding has no meaningful fix (e.g. an informational note), set recommendation to a brief explanation.`

  const userPrompt = `Here are the security scanner findings for repository "${repoName}":\n\n${findingsJson}\n\nHere is the source code for the affected files:\n\n${fileBlocks}\n\nPlease review each finding, confirm or reject it, and provide specific fix recommendations.`

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4096,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPrompt }],
    }),
  })

  if (!response.ok) {
    const status = response.status
    const body = await response.text()
    console.error(`Anthropic API error: ${status}`, body)

    if (status === 401) throw new Error('Anthropic API key is invalid. Check Integrations settings.')
    if (status === 429) throw new Error('Anthropic rate limit exceeded. Try again in a few minutes.')
    if (status === 400) throw new Error('Anthropic request error. The repository may have too many findings to process.')
    throw new Error(`Anthropic API error (HTTP ${status}).`)
  }

  const result = await response.json()

  const textBlock = result.content.find((b) => b.type === 'text')
  if (!textBlock) throw new Error('No response from Claude.')

  // Parse JSON from Claude's response (handle markdown code blocks)
  let jsonText = textBlock.text.trim()
  if (jsonText.startsWith('```')) {
    jsonText = jsonText.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '')
  }

  try {
    const parsed = JSON.parse(jsonText)
    // Filter out false positives — keep them in the data but flag them
    return {
      findings: parsed.findings || findings,
      summary: parsed.summary || '',
    }
  } catch {
    console.error('Failed to parse Claude response as JSON:', jsonText.slice(0, 200))
    // Fall back to original findings without recommendations
    return {
      findings,
      summary: `Analysis complete. ${findings.length} finding(s) detected but Claude's response could not be parsed.`,
    }
  }
}

// ============================================================
//  Route handlers
// ============================================================

// ----- POST / -----
// Start a new security scan for a repository.
// Body: { repoName, repoUrl, owner, defaultBranch }
router.post('/', requireAuth, async (req, res) => {
  const { repoName, repoUrl, owner, defaultBranch } = req.body

  if (!repoName || !owner) {
    return res.status(400).json({ error: 'repoName and owner are required.' })
  }

  const branch = defaultBranch || 'main'

  // Create the scan record
  const insert = db.prepare(`
    INSERT INTO scans (repo_name, repo_url, status, requested_by)
    VALUES (?, ?, 'scanning', ?)
  `)
  const result = insert.run(repoName, repoUrl || '', req.user.id)
  const scanId = result.lastInsertRowid

  // Return immediately so the frontend can show a loading state
  res.json({ scanId, status: 'scanning' })

  // Run the scan asynchronously
  runScan(scanId, owner, repoName, branch).catch((err) => {
    console.error(`Scan ${scanId} failed:`, err.message)
    db.prepare(`
      UPDATE scans SET status = 'error', summary = ?, completed_at = datetime('now')
      WHERE id = ?
    `).run(err.message, scanId)
  })
})

async function runScan(scanId, owner, repoName, branch) {
  console.log(`[Scan ${scanId}] Starting scan of ${owner}/${repoName} (${branch})...`)

  // ── Step 1: Fetch files from GitHub ──
  const files = await fetchRepoTree(owner, repoName, branch)
  console.log(`[Scan ${scanId}] Found ${files.length} scannable files`)

  if (files.length === 0) {
    db.prepare(`
      UPDATE scans SET status = 'complete', summary = 'No scannable source files found in this repository.', risk_level = 'clean', file_count = 0, completed_at = datetime('now')
      WHERE id = ?
    `).run(scanId)
    return
  }

  const filesWithContent = []
  for (const file of files) {
    const content = await fetchFileContent(owner, repoName, file.path, branch)
    if (content) {
      filesWithContent.push({ path: file.path, content })
    }
  }

  console.log(`[Scan ${scanId}] Fetched content for ${filesWithContent.length} files`)

  db.prepare('UPDATE scans SET file_count = ? WHERE id = ?')
    .run(filesWithContent.length, scanId)

  // ── Step 2: Run the security scanner ──
  // This is where the MCP agent plugs in. Right now it's a
  // built-in static analysis placeholder.
  const scanResults = runStaticAnalysis(filesWithContent)
  console.log(`[Scan ${scanId}] Scanner found ${scanResults.findings.length} potential issues`)

  if (scanResults.findings.length === 0) {
    db.prepare(`
      UPDATE scans SET status = 'complete', findings = '[]', summary = 'No security issues detected by static analysis.', risk_level = 'clean', completed_at = datetime('now')
      WHERE id = ?
    `).run(scanId)
    return
  }

  // ── Step 3: Ask Claude for fix recommendations ──
  // Claude reviews the scanner's findings + source code and
  // recommends specific code changes to fix each issue.
  const withFixes = await getFixRecommendations(repoName, scanResults.findings, filesWithContent)

  // ── Step 4: Store results ──
  db.prepare(`
    UPDATE scans
    SET status = 'complete',
        findings = ?,
        summary = ?,
        risk_level = ?,
        completed_at = datetime('now')
    WHERE id = ?
  `).run(
    JSON.stringify(withFixes.findings || []),
    withFixes.summary || '',
    scanResults.riskLevel || 'unknown',
    scanId
  )

  const truePositives = (withFixes.findings || []).filter((f) => !f.falsePositive).length
  console.log(`[Scan ${scanId}] Complete — ${truePositives} confirmed findings, risk: ${scanResults.riskLevel}`)
}

// ----- GET / -----
// List all scans (most recent first).
router.get('/', requireAuth, (req, res) => {
  const scans = db.prepare(`
    SELECT s.*, u.username as requested_by_name
    FROM scans s
    LEFT JOIN users u ON s.requested_by = u.id
    ORDER BY s.started_at DESC
    LIMIT 50
  `).all()

  const formatted = scans.map((s) => ({
    ...s,
    findings: s.findings ? JSON.parse(s.findings) : [],
  }))

  res.json({ scans: formatted })
})

// ----- GET /repo/:name -----
// Get the latest scan for a specific repo.
router.get('/repo/:name', requireAuth, (req, res) => {
  const scan = db.prepare(`
    SELECT s.*, u.username as requested_by_name
    FROM scans s
    LEFT JOIN users u ON s.requested_by = u.id
    WHERE s.repo_name = ?
    ORDER BY s.started_at DESC
    LIMIT 1
  `).get(req.params.name)

  if (!scan) {
    return res.json({ scan: null })
  }

  res.json({
    scan: {
      ...scan,
      findings: scan.findings ? JSON.parse(scan.findings) : [],
    },
  })
})

// ----- GET /:id -----
// Get a specific scan by ID (used for polling during a scan).
router.get('/:id', requireAuth, (req, res) => {
  const scanId = parseInt(req.params.id, 10)
  if (isNaN(scanId)) {
    return res.status(400).json({ error: 'Invalid scan ID.' })
  }

  const scan = db.prepare(`
    SELECT s.*, u.username as requested_by_name
    FROM scans s
    LEFT JOIN users u ON s.requested_by = u.id
    WHERE s.id = ?
  `).get(scanId)

  if (!scan) {
    return res.status(404).json({ error: 'Scan not found.' })
  }

  res.json({
    scan: {
      ...scan,
      findings: scan.findings ? JSON.parse(scan.findings) : [],
    },
  })
})

export default router
