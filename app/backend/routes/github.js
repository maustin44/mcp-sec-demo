// ============================================================
//  ToolVault — GitHub Integration Routes
// ============================================================
//
//  These routes act as a proxy between the frontend and GitHub's
//  API. The GitHub token stays on the server — the browser never
//  sees it. This is the pattern to follow for other integrations.
//
//  ENDPOINTS:
//    GET /api/github/repos         — List all repos in the org
//    GET /api/github/repos/search  — Search repos by keyword
//
//  HOW THIS FILE IS STRUCTURED (use as a template):
//    1. Import helpers (auth middleware, getSetting)
//    2. Define a helper to call the external API (githubFetch)
//    3. Define a normalizer to shape the response (normalizeRepo)
//    4. Define route handlers that use the helper + normalizer
//
//  TO ADD A NEW INTEGRATION (e.g. DefectDojo):
//    1. Copy this file as routes/defectdojo.js
//    2. Replace githubFetch with defectdojoFetch
//    3. Replace normalizeRepo with normalizeFinding (or similar)
//    4. Define your endpoints
//    5. Register the routes in server.js
//
// ============================================================

import { Router } from 'express'
import { requireAuth } from '../middleware/auth.js'
import { getSetting } from './settings.js'

const router = Router()

const GITHUB_API_BASE = 'https://api.github.com'

// ============================================================
//  Helper: call the GitHub API with the stored token
// ============================================================

/**
 * githubFetch(endpoint) — Make an authenticated request to GitHub.
 *
 * Reads the token from the settings DB. Throws a descriptive
 * error if the request fails (the route handler catches it).
 *
 * Example: const repos = await githubFetch('/orgs/google/repos')
 */
async function githubFetch(endpoint) {
  const token = getSetting('github_token') || process.env.GITHUB_TOKEN

  const headers = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'ToolVault-Backend',
  }
  if (token) {
    headers['Authorization'] = `token ${token}`
  }

  console.log(`[GitHub API] ${token ? 'Authenticated' : 'Unauthenticated'} request: ${endpoint}`)

  const response = await fetch(`${GITHUB_API_BASE}${endpoint}`, { headers })

  if (!response.ok) {
    const status = response.status
    const body = await response.text()
    console.error(`[GitHub API] Error ${status} on ${endpoint}`)
    console.error(`[GitHub API] Response: ${body.slice(0, 300)}`)

    if (status === 401) throw new Error('GitHub token is invalid or expired.')
    if (status === 403) {
      // Check if it's an SSO authorization issue
      if (body.includes('SSO') || body.includes('saml')) {
        throw new Error('Token needs SSO authorization for this organization. Go to github.com/settings/tokens, find this token, and click "Authorize" next to the org.')
      }
      throw new Error('GitHub rate limit exceeded or token lacks permissions. Try again later.')
    }
    if (status === 404) throw new Error('NOT_FOUND')
    throw new Error(`GitHub API error (HTTP ${status}).`)
  }

  return response.json()
}

// ============================================================
//  Helper: fetch repos for an org OR a personal user account
// ============================================================

/**
 * fetchReposForOwner(owner) — Tries /orgs/{owner}/repos first.
 * If that 404s (meaning it's a personal account, not an org),
 * falls back to /users/{owner}/repos automatically.
 *
 * This lets admins enter either "google" (org) or "mmill210-lang"
 * (personal username) on the Integrations page and it just works.
 */
async function fetchReposForOwner(owner) {
  const token = getSetting('github_token') || process.env.GITHUB_TOKEN

  console.log(`[GitHub] fetchReposForOwner("${owner}") — token: ${token ? 'yes (' + token.slice(0, 6) + '...)' : 'none'}`)

  // ---------- Try 1: Organization endpoint ----------
  // Works for GitHub orgs. Returns repos the token can see.
  try {
    const orgRepos = await githubFetch(`/orgs/${owner}/repos?per_page=100&sort=updated&type=all`)
    console.log(`[GitHub] Org endpoint returned ${orgRepos.length} repos`)

    // If the org exists but returned 0 repos, the token might not
    // have access. Fall through and try other methods.
    if (orgRepos.length > 0) {
      return orgRepos
    }
    console.log(`[GitHub] Org "${owner}" returned 0 repos — token may lack org access, trying other methods...`)
  } catch (err) {
    if (err.message !== 'NOT_FOUND') throw err
    console.log(`[GitHub] "${owner}" is not an org — trying as a user account...`)
  }

  // ---------- Try 2: Authenticated user repos ----------
  // /user/repos returns ALL repos the token has access to (including
  // private repos across orgs they belong to). We filter to repos
  // owned by or belonging to the configured owner.
  if (token) {
    try {
      // type=all gets owned, collaborated, and org member repos
      const allRepos = await githubFetch(`/user/repos?per_page=100&sort=updated&type=all`)
      console.log(`[GitHub] /user/repos returned ${allRepos.length} total repos`)

      // Filter to repos that belong to the configured owner
      // (matches both org-owned repos and personal repos)
      const filtered = allRepos.filter(
        (repo) => repo.owner.login.toLowerCase() === owner.toLowerCase()
      )
      console.log(`[GitHub] After filtering for "${owner}": ${filtered.length} repos`)

      if (filtered.length > 0) {
        return filtered
      }
      console.log(`[GitHub] No repos matched owner "${owner}" — trying public endpoint...`)
    } catch (err) {
      console.error(`[GitHub] /user/repos failed:`, err.message)
    }
  }

  // ---------- Try 3: Public user/org repos (no auth needed) ----------
  // Last resort — returns only public repos but always works
  // if the username/org exists.
  console.log(`[GitHub] Falling back to public /users/${owner}/repos endpoint`)
  return await githubFetch(`/users/${owner}/repos?per_page=100&sort=updated`)
}

// ============================================================
//  Helper: normalize a GitHub repo into our standard shape
// ============================================================

/**
 * normalizeRepo(githubRepoObject) — Converts a raw GitHub API
 * repo object into the simplified format our frontend expects.
 *
 * This keeps the frontend decoupled from GitHub's API shape.
 * If GitHub changes their API, we only fix this one function.
 */
function normalizeRepo(repo) {
  return {
    id:          repo.id,
    name:        repo.name,
    description: repo.description || 'No description provided.',
    language:    repo.language || 'Unknown',
    stars:       repo.stargazers_count,
    forks:       repo.forks_count,
    updatedAt:   repo.updated_at,
    url:         repo.html_url,
    topics:      repo.topics || [],
    openIssues:  repo.open_issues_count,
    visibility:  repo.visibility || (repo.private ? 'private' : 'public'),
    defaultBranch: repo.default_branch || 'main',
  }
}

// ============================================================
//  Route handlers
// ============================================================

// ----- GET /repos -----
// Returns all repositories for the configured GitHub org or user.
// Tries the /orgs/ endpoint first; if it 404s, falls back to /users/.
// This lets admins enter either an org name or a personal username.
router.get('/repos', requireAuth, async (req, res) => {
  try {
    const owner = getSetting('github_org') || process.env.GITHUB_ORG
    if (!owner) {
      return res.status(500).json({
        error: 'No GitHub organization or username configured. Go to Integrations to set one.',
      })
    }

    console.log(`[GitHub] Fetching repos for "${owner}"...`)
    const repos = await fetchReposForOwner(owner)
    console.log(`[GitHub] Returning ${repos.length} repos`)
    res.json({ repos: repos.map(normalizeRepo) })
  } catch (err) {
    console.error(`[GitHub] Error fetching repos:`, err.message)
    res.status(502).json({ error: err.message })
  }
})

// ----- GET /repos/search?q=keyword -----
// Searches repos by name/description/topic.
// If no query is provided, returns all repos (same as /repos).
router.get('/repos/search', requireAuth, async (req, res) => {
  try {
    const owner = getSetting('github_org') || process.env.GITHUB_ORG
    const query = req.query.q || ''

    if (!owner) {
      return res.status(500).json({
        error: 'No GitHub organization or username configured. Go to Integrations to set one.',
      })
    }

    // No search term → return all repos
    if (!query.trim()) {
      const repos = await fetchReposForOwner(owner)
      return res.json({ repos: repos.map(normalizeRepo) })
    }

    // Search within the org/user using GitHub's search API
    // "user:" works for both orgs and personal accounts in GitHub search
    const encoded = encodeURIComponent(`${query} user:${owner}`)
    const data = await githubFetch(`/search/repositories?q=${encoded}&per_page=30`)
    res.json({ repos: data.items.map(normalizeRepo) })
  } catch (err) {
    res.status(502).json({ error: err.message })
  }
})

// ----- GET /pipeline -----
// Returns recent GitHub Actions workflow runs for the configured org/user.
// This connects the CI/CD pipeline (built by teammates) into the SPA dashboard,
// showing build status, scan results, and deployment history.
router.get('/pipeline', requireAuth, async (req, res) => {
  try {
    const owner = getSetting('github_org') || process.env.GITHUB_ORG
    if (!owner) {
      return res.status(500).json({
        error: 'No GitHub organization or username configured. Go to Integrations to set one.',
      })
    }

    // Try to find the main repo (same name as the org/user, or the first repo with workflows)
    const repoName = req.query.repo || ''

    // If a specific repo is provided, fetch its workflow runs directly
    if (repoName) {
      const runs = await githubFetch(`/repos/${owner}/${repoName}/actions/runs?per_page=10`)
      return res.json({
        runs: (runs.workflow_runs || []).map(normalizeRun),
        repo: repoName,
        owner,
      })
    }

    // Otherwise, find repos that have workflow runs
    // First get the repos, then try the most recently updated one
    const repos = await fetchReposForOwner(owner)
    const repoNames = repos.map((r) => r.name).slice(0, 5) // Check top 5 most recent repos

    let allRuns = []
    let foundRepo = null

    for (const name of repoNames) {
      try {
        const data = await githubFetch(`/repos/${owner}/${name}/actions/runs?per_page=10`)
        if (data.workflow_runs && data.workflow_runs.length > 0) {
          allRuns = data.workflow_runs
          foundRepo = name
          break
        }
      } catch (err) {
        // Skip repos where we can't access actions (permissions, etc.)
        continue
      }
    }

    res.json({
      runs: allRuns.map(normalizeRun),
      repo: foundRepo,
      owner,
    })
  } catch (err) {
    console.error(`[GitHub] Error fetching pipeline runs:`, err.message)
    res.status(502).json({ error: err.message })
  }
})

/**
 * normalizeRun(githubRunObject) — Converts a raw GitHub Actions
 * workflow run into the simplified format our frontend expects.
 */
function normalizeRun(run) {
  return {
    id:          run.id,
    name:        run.name || run.workflow_id,
    status:      run.status,          // queued, in_progress, completed
    conclusion:  run.conclusion,      // success, failure, cancelled, skipped, null
    branch:      run.head_branch,
    commit:      run.head_sha?.slice(0, 7),
    commitMsg:   run.head_commit?.message?.split('\n')[0] || '',
    event:       run.event,           // push, pull_request, schedule
    createdAt:   run.created_at,
    updatedAt:   run.updated_at,
    url:         run.html_url,
    actor:       run.actor?.login || 'unknown',
    runNumber:   run.run_number,
  }
}

export default router
