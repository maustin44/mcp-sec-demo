// ============================================================
//  ToolVault — Backend Server (Entry Point)
// ============================================================

import 'dotenv/config'
import express from 'express'
import cors from 'cors'

import { securityHeaders } from './middleware/securityHeaders.js'
import { apiLimiter } from './middleware/rateLimiter.js'

import authRoutes     from './routes/auth.js'
import githubRoutes   from './routes/github.js'
import settingsRoutes from './routes/settings.js'

// ============================================================
//  Startup validation
// ============================================================

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
//  CORS — allow frontend origins
// ============================================================
//  In production CORS_ORIGIN is set via ECS environment variable
//  to the CloudFront URL. In local dev it falls back to Vite defaults.

const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',')
  : ['http://localhost:5173', 'http://localhost:5174']

app.use(cors({
  origin: allowedOrigins,
  credentials: true,
}))

// ============================================================
//  Global middleware
// ============================================================

app.use(securityHeaders)
app.disable('x-powered-by')
app.use(express.json({ limit: '1mb' }))
app.use('/api', apiLimiter)

// ============================================================
//  API Routes
// ============================================================

app.use('/api/auth',     authRoutes)
app.use('/api/github',   githubRoutes)
app.use('/api/settings', settingsRoutes)

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

app.use((err, req, res, next) => {
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
  console.log(`  Allowed origins: ${allowedOrigins.join(', ')}`)
  console.log('')
})
