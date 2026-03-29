// ============================================================
//  ToolVault — DefectDojo Service
// ============================================================
//
//  Frontend API client for DefectDojo findings.
//  All calls proxy through the backend so credentials stay server-side.
//
// ============================================================

import { apiFetch } from './api.js'

/**
 * Test the DefectDojo connection.
 * Returns { connected: bool, message: string }
 */
export async function testDefectDojoConnection() {
  return apiFetch('/defectdojo/status')
}

/**
 * Get all active findings from DefectDojo.
 * Returns { findings: [...], total: number }
 */
export async function getFindings({ limit = 50, severity = '', engagement = '' } = {}) {
  const params = new URLSearchParams()
  if (limit)      params.set('limit', limit)
  if (severity)   params.set('severity', severity)
  if (engagement) params.set('engagement', engagement)
  const qs = params.toString() ? `?${params}` : ''
  return apiFetch(`/defectdojo/findings${qs}`)
}

/**
 * Get a severity summary for the dashboard.
 * Returns { summary: { critical, high, medium, low, info, total }, riskLevel }
 */
export async function getFindingsSummary() {
  return apiFetch('/defectdojo/findings/summary')
}

// Severity colour helpers
export const SEVERITY_COLORS = {
  critical: { text: '#dc2626', bg: '#fef2f2', border: '#fca5a5', label: 'Critical' },
  high:     { text: '#ea580c', bg: '#fff7ed', border: '#fdba74', label: 'High' },
  medium:   { text: '#d97706', bg: '#fffbeb', border: '#fcd34d', label: 'Medium' },
  low:      { text: '#2563eb', bg: '#eff6ff', border: '#93c5fd', label: 'Low' },
  info:     { text: '#6b7280', bg: '#f9fafb', border: '#e5e7eb', label: 'Info' },
}

export const RISK_COLORS = {
  critical: { text: '#dc2626', label: 'Critical Risk' },
  high:     { text: '#ea580c', label: 'High Risk' },
  medium:   { text: '#d97706', label: 'Medium Risk' },
  low:      { text: '#2563eb', label: 'Low Risk' },
  info:     { text: '#6b7280', label: 'Info Only' },
  clean:    { text: '#16a34a', label: 'Clean' },
}
