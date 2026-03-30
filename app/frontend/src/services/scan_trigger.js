// ============================================================
//  ToolVault — Scan Trigger Service
// ============================================================

import { apiFetch } from './api.js'

/**
 * Trigger a security scan via GitHub Actions workflow_dispatch.
 * Returns { success, message, runId, runUrl, status }
 */
export async function triggerScan({ targetRepo = '', targetUrl = '' } = {}) {
  return apiFetch('/scan/trigger', {
    method: 'POST',
    body: JSON.stringify({ targetRepo, targetUrl }),
  })
}

/**
 * Poll the status of a specific workflow run.
 * Returns { runId, status, conclusion, url, jobs }
 */
export async function getScanStatus(runId) {
  return apiFetch(`/scan/status?runId=${runId}`)
}

/**
 * Get the most recent scan runs.
 * Returns { runs: [...] }
 */
export async function getLatestScans() {
  return apiFetch('/scan/latest')
}

/**
 * Poll a run until it completes.
 * Calls onUpdate(status) on each poll.
 */
export async function pollScanUntilDone(runId, onUpdate, intervalMs = 5000) {
  return new Promise((resolve, reject) => {
    const poll = async () => {
      try {
        const data = await getScanStatus(runId)
        if (onUpdate) onUpdate(data)
        if (data.status === 'completed') {
          resolve(data)
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

// Status display helpers
export const RUN_STATUS = {
  queued:      { label: 'Queued',      color: '#6b7280', dot: '#6b7280' },
  in_progress: { label: 'Running',     color: '#2563eb', dot: '#2563eb' },
  completed:   { label: 'Completed',   color: '#16a34a', dot: '#16a34a' },
}

export const RUN_CONCLUSION = {
  success:   { label: 'Success',   color: '#16a34a' },
  failure:   { label: 'Failed',    color: '#dc2626' },
  cancelled: { label: 'Cancelled', color: '#6b7280' },
  skipped:   { label: 'Skipped',   color: '#6b7280' },
}
