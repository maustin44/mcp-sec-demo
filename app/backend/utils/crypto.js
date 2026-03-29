// ============================================================
//  ToolVault — Crypto Utilities
// ============================================================
//
//  Helper functions for encrypting and decrypting sensitive
//  values (like API tokens) before storing them in the database.
//
//  WHY THIS EXISTS:
//    Storing API keys in plaintext in SQLite means anyone who
//    gets the database file can read all your tokens. This module
//    encrypts them using AES-256-GCM so they're protected at rest.
//    The encryption key is derived from JWT_SECRET.
//
//  USAGE:
//    import { encrypt, decrypt } from '../utils/crypto.js'
//
//    const encrypted = encrypt('ghp_abc123...')
//    // → "iv:authTag:ciphertext" (safe to store in DB)
//
//    const original = decrypt(encrypted)
//    // → "ghp_abc123..."
//
// ============================================================

import crypto from 'crypto'

const ALGORITHM = 'aes-256-gcm'

/**
 * Derive a consistent 32-byte encryption key from JWT_SECRET.
 * Uses PBKDF2 with a fixed salt so the same secret always
 * produces the same key (needed to decrypt previously stored values).
 */
function getEncryptionKey() {
  const secret = process.env.JWT_SECRET
  if (!secret) {
    throw new Error('JWT_SECRET is required for encryption. Check your .env file.')
  }
  // Fixed salt — this is OK because the entropy comes from JWT_SECRET.
  // In production, you'd use a per-deployment salt stored separately.
  const salt = 'toolvault-encryption-salt'
  return crypto.pbkdf2Sync(secret, salt, 100000, 32, 'sha256')
}

/**
 * encrypt(plaintext) — Encrypts a string using AES-256-GCM.
 *
 * Returns a string in the format "iv:authTag:ciphertext" which
 * is safe to store in the database. Returns empty string for
 * empty input (so empty settings don't get encrypted).
 */
export function encrypt(plaintext) {
  if (!plaintext) return ''

  const key = getEncryptionKey()
  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv)

  let encrypted = cipher.update(plaintext, 'utf8', 'hex')
  encrypted += cipher.final('hex')

  const authTag = cipher.getAuthTag().toString('hex')

  // Format: iv:authTag:ciphertext
  return `${iv.toString('hex')}:${authTag}:${encrypted}`
}

/**
 * decrypt(encryptedString) — Decrypts a string that was encrypted
 * with the encrypt() function above.
 *
 * Expects the "iv:authTag:ciphertext" format. Returns empty string
 * for empty input. If decryption fails (wrong key, corrupted data),
 * returns the original string as-is (graceful fallback for
 * values that were stored before encryption was added).
 */
export function decrypt(encryptedString) {
  if (!encryptedString) return ''

  // If the string doesn't look encrypted (no colons), return as-is.
  // This handles legacy plaintext values stored before encryption.
  const parts = encryptedString.split(':')
  if (parts.length !== 3) {
    return encryptedString
  }

  try {
    const [ivHex, authTagHex, ciphertext] = parts
    const key = getEncryptionKey()
    const iv = Buffer.from(ivHex, 'hex')
    const authTag = Buffer.from(authTagHex, 'hex')

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv)
    decipher.setAuthTag(authTag)

    let decrypted = decipher.update(ciphertext, 'hex', 'utf8')
    decrypted += decipher.final('utf8')

    return decrypted
  } catch (err) {
    // If decryption fails, the value was probably stored in plaintext
    // before encryption was added. Return it as-is.
    console.warn('Could not decrypt value — returning as plaintext (may be a legacy value).')
    return encryptedString
  }
}

/**
 * isEncrypted(value) — Checks if a string looks like it was
 * encrypted by our encrypt() function.
 */
export function isEncrypted(value) {
  if (!value) return false
  const parts = value.split(':')
  return parts.length === 3 && parts[0].length === 32 // 16 bytes = 32 hex chars
}
