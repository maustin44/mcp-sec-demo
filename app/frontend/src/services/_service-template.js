// ============================================================
//  ToolVault — Service Template
// ============================================================
//
//  COPY THIS FILE to create a new frontend service. For example:
//    services/defectdojo.js
//
//  Then find-and-replace:
//    TOOL_NAME → defectdojo
//    /tool_name → /defectdojo
//    Item → Finding (or whatever makes sense)
//
//  WHAT THIS FILE DOES:
//    - Provides functions that call your backend API endpoints
//    - Shapes the data for your page components
//    - Keeps API logic out of your React components
//
//  USAGE IN A PAGE COMPONENT:
//    import { getAllItems, getItemStats } from '../services/defectdojo'
//
//    const items = await getAllItems()
//    const stats = getItemStats(items)
//
// ============================================================

import { apiFetch } from './api.js'

// --- API calls ---

/** Fetch all items from the backend. */
export async function getAllItems() {
  const data = await apiFetch('/tool_name/items')
  return data.items
}

/** Search items by keyword. Returns all items if query is empty. */
export async function searchItems(query) {
  if (!query.trim()) {
    return getAllItems()
  }
  const encoded = encodeURIComponent(query)
  const data = await apiFetch(`/tool_name/items/search?q=${encoded}`)
  return data.items
}

/** Fetch summary stats from the backend. */
export async function getBackendStats() {
  const data = await apiFetch('/tool_name/stats')
  return data.stats
}

// --- Client-side helpers ---
// These functions work on the items array after it's been fetched.
// They don't make any API calls.

/**
 * Calculate summary stats from an items array.
 * Customize for your tool's data shape.
 */
export function getItemStats(items) {
  return {
    total: items.length,
    // Add tool-specific stats here:
    // critical: items.filter(i => i.severity === 'Critical').length,
    // active: items.filter(i => i.status === 'Active').length,
    // resolved: items.filter(i => i.status === 'Resolved').length,
  }
}

/** Filter items by a specific field value. */
export function filterItems(items, field, value) {
  if (!value || value === 'All') return items
  return items.filter((item) => item[field] === value)
}

/** Get unique values for a field (useful for filter dropdowns). */
export function getUniqueValues(items, field) {
  const values = [...new Set(items.map((item) => item[field]).filter(Boolean))]
  return ['All', ...values.sort()]
}
