// ============================================================
//  ToolVault — Rate Limiter Middleware
// ============================================================
//
//  Simple in-memory rate limiter to prevent brute-force attacks
//  on the login endpoint and excessive API usage.
//
//  No external packages needed — uses a Map with automatic cleanup.
//
//  USAGE:
//    import { loginLimiter, apiLimiter } from '../middleware/rateLimiter.js'
//
//    router.post('/login', loginLimiter, handler)
//    app.use('/api', apiLimiter)
//
//  HOW IT WORKS:
//    Tracks request counts per IP address in a Map. Each entry
//    auto-expires after the configured window. If a client exceeds
//    the limit, they get a 429 (Too Many Requests) response.
//
// ============================================================

/**
 * createRateLimiter(options) — Creates a rate limiter middleware.
 *
 * @param {number} options.windowMs   — Time window in milliseconds
 * @param {number} options.maxRequests — Max requests per window per IP
 * @param {string} options.message    — Error message when limit is hit
 */
function createRateLimiter({ windowMs, maxRequests, message }) {
  // Map of IP → { count, resetTime }
  const clients = new Map()

  // Clean up expired entries every minute to prevent memory leaks
  setInterval(() => {
    const now = Date.now()
    for (const [ip, data] of clients) {
      if (now > data.resetTime) {
        clients.delete(ip)
      }
    }
  }, 60000)

  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown'
    const now = Date.now()

    let client = clients.get(ip)

    // If no record or window expired, start a new window
    if (!client || now > client.resetTime) {
      client = { count: 0, resetTime: now + windowMs }
      clients.set(ip, client)
    }

    client.count++

    // Add rate limit headers so the client knows their status
    res.set('X-RateLimit-Limit', String(maxRequests))
    res.set('X-RateLimit-Remaining', String(Math.max(0, maxRequests - client.count)))
    res.set('X-RateLimit-Reset', String(Math.ceil(client.resetTime / 1000)))

    if (client.count > maxRequests) {
      return res.status(429).json({
        error: message || 'Too many requests. Please try again later.',
      })
    }

    next()
  }
}

// --- Pre-configured limiters ---

/**
 * loginLimiter — Strict rate limit for login attempts.
 * Allows 5 login attempts per 15 minutes per IP.
 * This prevents brute-force password attacks.
 */
export const loginLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 5,
  message: 'Too many login attempts. Please wait 15 minutes before trying again.',
})

/**
 * apiLimiter — General rate limit for all API endpoints.
 * Allows 100 requests per minute per IP.
 * This prevents API abuse while allowing normal usage.
 */
export const apiLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 100,
  message: 'Too many requests. Please slow down.',
})
