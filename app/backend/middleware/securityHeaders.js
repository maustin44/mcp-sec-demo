// ============================================================
//  ToolVault — Security Headers Middleware
// ============================================================
//
//  Sets HTTP security headers on every response to protect
//  against common web attacks (XSS, clickjacking, MIME sniffing).
//
//  This is a lightweight alternative to the "helmet" npm package.
//  If you install helmet later, you can replace this middleware
//  with: app.use(helmet())
//
//  USAGE:
//    import { securityHeaders } from '../middleware/securityHeaders.js'
//    app.use(securityHeaders)
//
// ============================================================

export function securityHeaders(req, res, next) {
  // Prevent the browser from MIME-sniffing a response away from
  // the declared content-type (blocks drive-by downloads)
  res.setHeader('X-Content-Type-Options', 'nosniff')

  // Prevent this site from being embedded in iframes (stops clickjacking)
  res.setHeader('X-Frame-Options', 'DENY')

  // Enable browser's built-in XSS filter
  res.setHeader('X-XSS-Protection', '1; mode=block')

  // Don't send the Referer header when navigating away from HTTPS to HTTP
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')

  // Prevent the browser from caching API responses that may contain
  // sensitive data (tokens, user info, etc.)
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
  res.setHeader('Pragma', 'no-cache')

  // Remove the X-Powered-By header that reveals we're using Express
  // (attackers use this to identify known vulnerabilities)
  res.removeHeader('X-Powered-By')

  next()
}
