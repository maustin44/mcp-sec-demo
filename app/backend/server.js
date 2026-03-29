// ============================================================
//  ToolVault — Backend Server
// ============================================================

import 'dotenv/config'
import express from 'express'
import cors from 'cors'

import { securityHeaders } from './middleware/securityHeaders.js'
import { apiLimiter } from './middleware/rateLimiter.js'

import authRoutes        from './routes/auth.js'
import githubRoutes      from './routes/github.js'
import settingsRoutes    from './routes/settings.js'
import defectdojoRoutes  from './routes/defectdojo.js'

if (!process.env.JWT_SECRET) {
  console.error('\n  ERROR: JWT_SECRET is not set in .env')
  process.exit(1)
}

const app = express()
const PORT = process.env.PORT || 3001

const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',')
  : ['http://localhost:5173', 'http://localhost:5174']

app.use(cors({ origin: allowedOrigins, credentials: true }))
app.use(securityHeaders)
app.disable('x-powered-by')
app.use(express.json({ limit: '1mb' }))
app.use('/api', apiLimiter)

app.use('/api/auth',        authRoutes)
app.use('/api/github',      githubRoutes)
app.use('/api/settings',    settingsRoutes)
app.use('/api/defectdojo',  defectdojoRoutes)

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'ToolVault backend is running.', timestamp: new Date().toISOString() })
})

app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err.message)
  res.status(500).json({ error: 'Internal server error.' })
})

app.listen(PORT, () => {
  console.log('')
  console.log('  ToolVault Backend')
  console.log(`  Running on http://localhost:${PORT}`)
  console.log(`  Allowed origins: ${allowedOrigins.join(', ')}`)
  console.log('')
})
