// ============================================================
//  ToolVault — Auth Middleware
// ============================================================
//
//  Two middleware functions that protect routes:
//
//    requireAuth   — Checks the request has a valid JWT token.
//                    If valid, attaches the user info to req.user
//                    so route handlers know who's making the request.
//
//    requireAdmin  — Must come AFTER requireAuth. Checks that
//                    req.user.role === 'admin'.
//
//  USAGE IN A ROUTE FILE:
//    import { requireAuth, requireAdmin } from '../middleware/auth.js'
//
//    router.get('/public-data',   requireAuth, handler)
//    router.post('/admin-action', requireAuth, requireAdmin, handler)
//
// ============================================================

import jwt from 'jsonwebtoken'

/**
 * requireAuth — Rejects the request if the user is not logged in.
 *
 * Expects an Authorization header like: "Bearer <token>"
 * On success, sets req.user = { id, username, role }
 */
export function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not logged in. Please sign in first.' })
  }

  const token = authHeader.split(' ')[1]

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.user = decoded // { id, username, role }
    next()
  } catch (err) {
    return res.status(401).json({ error: 'Session expired. Please sign in again.' })
  }
}

/**
 * requireAdmin — Rejects the request if the user is not an admin.
 *
 * Must be used AFTER requireAuth (it reads req.user).
 */
export function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' })
  }
  next()
}
