// ============================================================
//  ToolVault — Auth Routes
// ============================================================
//
//  These routes handle user authentication and account management.
//  All endpoints are prefixed with /api/auth (set in server.js).
//
//  ENDPOINTS:
//    POST   /api/auth/login      — Sign in with username & password
//    POST   /api/auth/register   — Create a new account (admin only)
//    GET    /api/auth/me         — Get the currently logged-in user
//    GET    /api/auth/users      — List all user accounts (admin only)
//    DELETE /api/auth/users/:id  — Delete a user account (admin only)
//
//  SECURITY FEATURES:
//    - Passwords hashed with bcrypt (12 salt rounds)
//    - Login endpoint rate-limited (5 attempts per 15 min per IP)
//    - JWT tokens expire after 8 hours
//    - Same error message for wrong username AND wrong password
//      (prevents username enumeration)
//    - Password minimum length enforced (8 characters)
//
// ============================================================

import { Router } from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import db from '../database.js'
import { requireAuth, requireAdmin } from '../middleware/auth.js'
import { loginLimiter } from '../middleware/rateLimiter.js'

const router = Router()

// Bcrypt salt rounds — 12 is the recommended minimum for production.
// Higher = slower but harder to brute-force. Don't go below 10.
const SALT_ROUNDS = 12

// Minimum password length — OWASP recommends at least 8 characters.
const MIN_PASSWORD_LENGTH = 8

// ----- POST /login -----
// Accepts { username, password } and returns a JWT token + user info.
// Rate-limited to 5 attempts per 15 minutes per IP address.
router.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' })
  }

  // Look up the user in the database
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username)
  if (!user) {
    // Use the same error message as wrong password to prevent
    // attackers from discovering which usernames exist.
    return res.status(401).json({ error: 'Invalid username or password.' })
  }

  // Verify the password against the stored hash
  const passwordMatch = bcrypt.compareSync(password, user.password_hash)
  if (!passwordMatch) {
    return res.status(401).json({ error: 'Invalid username or password.' })
  }

  // Create a signed JWT token (expires in 8 hours)
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '8h' }
  )

  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role },
  })
})

// ----- POST /register (admin only) -----
// Accepts { username, password, role } and creates a new account.
router.post('/register', requireAuth, requireAdmin, (req, res) => {
  const { username, password, role } = req.body

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' })
  }

  // --- Input validation ---
  if (username.length < 3 || username.length > 50) {
    return res.status(400).json({ error: 'Username must be 3–50 characters.' })
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
    return res.status(400).json({ error: 'Username can only contain letters, numbers, hyphens, and underscores.' })
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` })
  }
  if (password.length > 128) {
    return res.status(400).json({ error: 'Password cannot exceed 128 characters.' })
  }

  // Only allow "user" or "admin" roles (reject anything else)
  const validRoles = ['user', 'admin']
  const assignedRole = validRoles.includes(role) ? role : 'user'

  // Check if username already exists
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username)
  if (existing) {
    return res.status(409).json({ error: 'Username already taken.' })
  }

  // Hash the password with bcrypt (12 salt rounds)
  const hash = bcrypt.hashSync(password, SALT_ROUNDS)
  const result = db.prepare(
    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)'
  ).run(username, hash, assignedRole)

  res.status(201).json({
    message: `Account "${username}" created successfully.`,
    user: { id: result.lastInsertRowid, username, role: assignedRole },
  })
})

// ----- GET /me -----
// Returns the currently logged-in user's info (from their token).
// Also checks if the user is still using the default admin password
// so the frontend can prompt them to change it.
router.get('/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)

  let mustChangePassword = false
  if (user) {
    // Check if user is still using the default admin password
    mustChangePassword = bcrypt.compareSync('admin123', user.password_hash)
  }

  res.json({
    user: req.user,
    mustChangePassword,
  })
})

// ----- PUT /me/password -----
// Change the currently logged-in user's password.
// Requires the current password for verification.
router.put('/me/password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required.' })
  }

  if (newPassword.length < MIN_PASSWORD_LENGTH) {
    return res.status(400).json({ error: `New password must be at least ${MIN_PASSWORD_LENGTH} characters.` })
  }

  if (newPassword.length > 128) {
    return res.status(400).json({ error: 'Password cannot exceed 128 characters.' })
  }

  // Verify the current password
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)
  if (!user) {
    return res.status(404).json({ error: 'User not found.' })
  }

  const passwordMatch = bcrypt.compareSync(currentPassword, user.password_hash)
  if (!passwordMatch) {
    return res.status(401).json({ error: 'Current password is incorrect.' })
  }

  // Hash and save the new password
  const hash = bcrypt.hashSync(newPassword, SALT_ROUNDS)
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id)

  res.json({ message: 'Password changed successfully.' })
})

// ----- GET /users (admin only) -----
// Returns a list of all user accounts.
// Never returns password hashes — only safe fields.
router.get('/users', requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare(
    'SELECT id, username, role, created_at FROM users ORDER BY created_at DESC'
  ).all()
  res.json({ users })
})

// ----- DELETE /users/:id (admin only) -----
// Deletes a user account. Admins cannot delete themselves.
router.delete('/users/:id', requireAuth, requireAdmin, (req, res) => {
  const userId = parseInt(req.params.id)

  // Validate the ID is a number (prevent injection)
  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID.' })
  }

  // Safety check: don't let admins delete their own account
  if (userId === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account.' })
  }

  const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(userId)
  if (!user) {
    return res.status(404).json({ error: 'User not found.' })
  }

  db.prepare('DELETE FROM users WHERE id = ?').run(userId)
  res.json({ message: `User "${user.username}" deleted.` })
})

export default router
