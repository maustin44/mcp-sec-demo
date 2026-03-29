// ============================================================
//  ToolVault — GitHub Service
// ============================================================
//
//  Frontend helper functions for working with GitHub data.
//  All API calls go through the backend (the token never
//  touches the browser). This file just shapes the data for
//  the UI components.
//
//  REPO OBJECT SHAPE (returned by the backend):
//    {
//      id:          number,
//      name:        string,    // e.g. "react"
//      description: string,
//      language:    string,    // e.g. "JavaScript"
//      stars:       number,
//      forks:       number,
//      updatedAt:   string,    // ISO date
//      url:         string,    // GitHub URL
//      topics:      string[],
//      openIssues:  number,
//      visibility:  string,    // "public" or "private"
//    }
//
//  HOW TO ADD A NEW SERVICE FILE (for a new integration):
//    1. Create a file like services/defectdojo.js
//    2. Import apiFetch from './api.js'
//    3. Export functions that call your backend endpoints
//    4. Import those functions in your page component
//
// ============================================================

import { apiFetch } from './api.js'

// --- API calls ---

/** Fetch all repos from the configured GitHub organization. */
export async function getAllRepos() {
  const data = await apiFetch('/github/repos')
  return data.repos
}

/** Search repos by keyword. Returns all repos if query is empty. */
export async function searchRepos(query) {
  if (!query.trim()) {
    return getAllRepos()
  }
  const encoded = encodeURIComponent(query)
  const data = await apiFetch(`/github/repos/search?q=${encoded}`)
  return data.repos
}

/** Fetch recent CI/CD pipeline runs from GitHub Actions. */
export async function getPipelineRuns(repo) {
  const query = repo ? `?repo=${encodeURIComponent(repo)}` : ''
  const data = await apiFetch(`/github/pipeline${query}`)
  return data
}

// --- Client-side filters and stats ---
// These functions work on the repo array after it's been fetched.
// They don't make any API calls.

/** Filter repos by programming language. Pass 'All' to skip filtering. */
export function filterByLanguage(repos, language) {
  if (!language || language === 'All') return repos
  return repos.filter((repo) => repo.language === language)
}

/** Get a sorted list of unique languages from a repo array. */
export function getLanguages(repos) {
  const languages = [...new Set(repos.map((repo) => repo.language))]
  return ['All', ...languages.sort()]
}

/**
 * Calculate security-focused dashboard stats from a repo array.
 * This provides the data for the main dashboard KPIs, the
 * recently updated table, language breakdown, and security overview.
 */
export function getStats(repos) {
  const totalStars  = repos.reduce((sum, repo) => sum + repo.stars, 0)
  const totalForks  = repos.reduce((sum, repo) => sum + repo.forks, 0)
  const totalIssues = repos.reduce((sum, repo) => sum + repo.openIssues, 0)

  // Count repos per language (for the language breakdown chart)
  const languageCounts = {}
  repos.forEach((repo) => {
    languageCounts[repo.language] = (languageCounts[repo.language] || 0) + 1
  })

  // Get the 5 most recently updated repos (for the "Recent Activity" table)
  const recentRepos = [...repos]
    .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))
    .slice(0, 5)

  // --- Security-relevant stats ---

  // Repos with open issues may indicate unresolved vulnerabilities
  const reposWithIssues = repos.filter((repo) => repo.openIssues > 0)

  // Repos that have security-related topics (common in security tooling)
  const securityTopicKeywords = ['security', 'vulnerability', 'cve', 'scanner', 'sast', 'dast', 'devsecops', 'owasp', 'pentest', 'audit']
  const securityRepos = repos.filter((repo) =>
    repo.topics.some((topic) =>
      securityTopicKeywords.some((keyword) => topic.toLowerCase().includes(keyword))
    )
  )

  // Infrastructure-as-code repos (Terraform, Docker, CloudFormation)
  const iacLanguages = ['HCL', 'Dockerfile']
  const iacTopicKeywords = ['terraform', 'docker', 'kubernetes', 'k8s', 'aws', 'cloudformation', 'infrastructure', 'iac', 'helm']
  const iacRepos = repos.filter((repo) =>
    iacLanguages.includes(repo.language) ||
    repo.topics.some((topic) =>
      iacTopicKeywords.some((keyword) => topic.toLowerCase().includes(keyword))
    )
  )

  // CI/CD related repos
  const cicdTopicKeywords = ['ci', 'cd', 'cicd', 'pipeline', 'github-actions', 'jenkins', 'deployment']
  const cicdRepos = repos.filter((repo) =>
    repo.topics.some((topic) =>
      cicdTopicKeywords.some((keyword) => topic.toLowerCase().includes(keyword))
    )
  )

  // Repos not updated in over 90 days (may have stale dependencies)
  const ninetyDaysAgo = new Date()
  ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90)
  const staleRepos = repos.filter((repo) => new Date(repo.updatedAt) < ninetyDaysAgo)

  // Visibility breakdown
  const publicRepos = repos.filter((repo) => repo.visibility === 'public')
  const privateRepos = repos.filter((repo) => repo.visibility === 'private')

  return {
    totalRepos: repos.length,
    totalStars,
    totalForks,
    totalIssues,
    languageCounts,
    recentRepos,
    // Security-focused stats
    reposWithIssues,
    securityRepos,
    iacRepos,
    cicdRepos,
    staleRepos,
    publicRepos,
    privateRepos,
  }
}
