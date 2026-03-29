// ============================================================
//  ToolVault — Backend Server (Entry Point)
// ============================================================
//
//  This file starts the Express server and wires up all routes.
//
//  FOLDER STRUCTURE:
//    backend/
//      server.js             ← You are here. Registers all routes.
//      database.js           ← Creates the SQLite DB and tables.
//      middleware/
//        auth.js             ← Login/role checks (requireAuth, requireAdmin)
//        rateLimiter.js      ← Brute-force and API abuse protection
//        securityHeaders.js  ← HTTP security headers (XSS, clickjacking)
//      utils/
//        crypto.js           ← AES-256-GCM encryption for stored secrets
//      routes/
//        auth.js             ← Login, register, user management
//        github.js           ← GitHub API proxy (list & search repos)
//        settings.js         ← Admin settings (change org, token, etc.)
//
//  HOW TO ADD A NEW ROUTE FILE:
//    1. Create a file in routes/ (e.g. routes/scanners.js)
//    2. Import it here:        import scannerRoutes from './routes/scanners.js'
//    3. Register it below:     app.use('/api/scanners', scannerRoutes)
//    4. That's it — the frontend can now call /api/scanners/*
//
//  DEFAULT ADMIN LOGIN:
//    Username: admin
//    Password: admin123
//
// ============================================================

import 'dotenv/config'
import express from 'express'
import cors from 'cors'

// --- Security middleware ---
import { securityHeaders } from './middleware/securityHeaders.js'
import { apiLimiter } from './middleware/rateLimiter.js'

// --- Route imports ---
import authRoutes     from './routes/auth.js'
import githubRoutes   from './routes/github.js'
import settingsRoutes from './routes/settings.js'
// To add more integrations, import new route files here.
// Example: import scannerRoutes from './routes/scanners.js'

// ============================================================
//  Startup validation
// ============================================================
//  Make sure critical environment variables are set before
//  the server starts. Fail fast with a clear message.

if (!process.env.JWT_SECRET) {
  console.error('\n  ERROR: JWT_SECRET is not set in .env')
  console.error('  Copy .env.example to .env and fill in a random string.\n')
  process.exit(1)
}

if (process.env.JWT_SECRET.length < 16) {
  console.error('\n  WARNING: JWT_SECRET is very short (less than 16 characters).')
  console.error('  Use a long random string for better security.\n')
}

const app = express()
const PORT = process.env.PORT || 3001

// ============================================================
//  Global middleware (applied to every request)
// ============================================================

// Security headers — XSS, clickjacking, MIME sniffing protection
app.use(securityHeaders)

// Remove Express fingerprint (also done in securityHeaders, belt & suspenders)
app.disable('x-powered-by')

// Allow the React frontend (Vite dev server) to talk to this server.
// In production, replace these with your actual deployed frontend URL.
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:5174'],
  credentials: true,
}))

// Parse JSON request bodies (all our API endpoints expect JSON).
// Limit body size to 1MB to prevent abuse.
app.use(express.json({ limit: '1mb' }))

// Rate limiting — prevents brute-force and API abuse.
// 100 requests per minute per IP across all /api/* endpoints.
// Login has its own stricter limiter (see routes/auth.js).
app.use('/api', apiLimiter)

// ============================================================
//  API Routes
// ============================================================
//  Each route file handles a group of related endpoints.
//  The prefix (e.g. '/api/auth') is set here, so routes inside
//  the file only need to define the sub-path (e.g. '/login').

app.use('/api/auth',     authRoutes)      // Login, register, user list
app.use('/api/github',   githubRoutes)    // GitHub repo proxy
app.use('/api/settings', settingsRoutes)  // Admin integration settings
// To add more integrations, register new route files here.
// Example: app.use('/api/scanners', scannerRoutes)

// Health check — useful for monitoring and verifying the server is up
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'ToolVault backend is running.',
    timestamp: new Date().toISOString(),
  })
})

// ============================================================
//  Error handling
// ============================================================
//  This catches any unhandled errors in route handlers and always
//  returns JSON (never HTML). Without this, Express defaults to an
//  HTML error page which breaks the frontend's JSON parsing.

app.use((err, req, res, next) => {
  // Log the full error server-side, but only send a generic
  // message to the client (don't leak stack traces or internals)
  console.error('Unhandled server error:', err.message)
  res.status(500).json({ error: 'Internal server error.' })
})

// ============================================================
//  Start the server
// ============================================================

app.listen(PORT, () => {
  console.log('')
  console.log('  ToolVault Backend')
  console.log(`  Running on http://localhost:${PORT}`)
  console.log(`  Health check: http://localhost:${PORT}/api/health`)
  console.log('')
})
