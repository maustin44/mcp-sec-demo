// ============================================================
//  ToolVault — Scan Service
// ============================================================
//
//  Frontend API client for the security scanning feature.
//  Handles starting scans, polling for results, and fetching
//  scan history.
//
//  USAGE:
//    import { startScan, getScan, getRepoScan } from '../services/scans'
//
//    // Start a scan
//    const { scanId } = await startScan({ repoName, repoUrl, owner, defaultBranch })
//
//    // Poll for results
//    const { scan } = await getScan(scanId)
//    if (scan.status === 'complete') { ... }
//
// ============================================================

import { apiFetch } from './api.js'

/**
 * Start a security scan for a repository.
 * Returns immediately with { scanId, status: 'scanning' }.
 * Use getScan(scanId) to poll for results.
 */
export async function startScan({ repoName, repoUrl, owner, defaultBranch }) {
  const data = await apiFetch('/scans', {
    method: 'POST',
    body: JSON.stringify({ repoName, repoUrl, owner, defaultBranch }),
  })
  return data
}

/**
 * Get a specific scan by ID.
 * Returns { scan: { id, repo_name, status, findings, summary, risk_level, ... } }
 */
export async function getScan(scanId) {
  const data = await apiFetch(`/scans/${scanId}`)
  return data
}

/**
 * Get the latest scan for a specific repo by name.
 * Returns { scan: {...} } or { scan: null } if never scanned.
 */
export async function getRepoScan(repoName) {
  const data = await apiFetch(`/scans/repo/${encodeURIComponent(repoName)}`)
  return data
}

/**
 * Get all scans (most recent first).
 * Returns { scans: [...] }
 */
export async function getAllScans() {
  const data = await apiFetch('/scans')
  return data
}

/**
 * Poll a scan until it completes or errors.
 * Calls onUpdate(scan) on each poll with the latest state.
 * Returns the final scan object.
 */
export async function pollScan(scanId, onUpdate, intervalMs = 2000) {
  return new Promise((resolve, reject) => {
    const poll = async () => {
      try {
        const { scan } = await getScan(scanId)
        if (onUpdate) onUpdate(scan)

        if (scan.status === 'complete' || scan.status === 'error') {
          resolve(scan)
        } else {
          setTimeout(poll, intervalMs)
        }
      } catch (err) {
        reject(err)
      }
    }
    poll()
  })
}

// Severity color and label helpers

export const SEVERITY_CONFIG = {
  critical: { color: '#dc2626', bg: '#fef2f2', label: 'Critical' },
  high:     { color: '#ea580c', bg: '#fff7ed', label: 'High' },
  medium:   { color: '#d97706', bg: '#fffbeb', label: 'Medium' },
  low:      { color: '#2563eb', bg: '#eff6ff', label: 'Low' },
  info:     { color: '#6b7280', bg: '#f9fafb', label: 'Info' },
}

export const RISK_CONFIG = {
  critical: { color: '#dc2626', bg: '#fef2f2', label: 'Critical Risk' },
  high:     { color: '#ea580c', bg: '#fff7ed', label: 'High Risk' },
  medium:   { color: '#d97706', bg: '#fffbeb', label: 'Medium Risk' },
  low:      { color: '#2563eb', bg: '#eff6ff', label: 'Low Risk' },
  clean:    { color: '#16a34a', bg: '#f0fdf4', label: 'Clean' },
  unknown:  { color: '#6b7280', bg: '#f9fafb', label: 'Unknown' },
}
