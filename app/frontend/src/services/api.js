// ============================================================
//  ToolVault — API Client
// ============================================================
//
//  This file handles all communication between the frontend and
//  the backend server. Every API call goes through apiFetch(),
//  which automatically attaches the auth token.
//
//  HOW TO MAKE A NEW API CALL:
//    import { apiFetch } from '../services/api'
//
//    // GET request:
//    const data = await apiFetch('/github/repos')
//
//    // POST request with body:
//    const data = await apiFetch('/auth/login', {
//      method: 'POST',
//      body: JSON.stringify({ username, password }),
//    })
//
//  SESSION STORAGE KEYS:
//    tv_token — The JWT auth token (cleared when tab closes)
//    tv_user  — The logged-in user's info as JSON
//
// ============================================================

const API_BASE = 'http://localhost:3001/api'

// --- Token management ---
// We use sessionStorage (not localStorage) so the session clears
// when the browser tab is closed. Safer for demo/prototype use.

export function getToken() {
  return sessionStorage.getItem('tv_token')
}

export function setToken(token) {
  sessionStorage.setItem('tv_token', token)
}

export function clearToken() {
  sessionStorage.removeItem('tv_token')
  sessionStorage.removeItem('tv_user')
}

// --- User info ---

export function getStoredUser() {
  const raw = sessionStorage.getItem('tv_user')
  if (!raw) return null
  try { return JSON.parse(raw) } catch { return null }
}

export function setStoredUser(user) {
  sessionStorage.setItem('tv_user', JSON.stringify(user))
}

// --- API request helper ---

/**
 * apiFetch(endpoint, options) — Make a request to the backend.
 *
 * Automatically attaches the auth token (if logged in) and
 * parses the JSON response. Throws an error with a user-friendly
 * message if the request fails.
 *
 * @param {string} endpoint  — The API path (e.g. '/github/repos')
 * @param {object} options   — Standard fetch options (method, body, etc.)
 * @returns {object}         — The parsed JSON response
 */
export async function apiFetch(endpoint, options = {}) {
  const token = getToken()
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  let response
  try {
    response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    })
  } catch (err) {
    throw new Error('Cannot reach the server. Is the backend running?')
  }

  const data = await response.json()

  if (!response.ok) {
    throw new Error(data.error || `Request failed (HTTP ${response.status})`)
  }

  return data
}
