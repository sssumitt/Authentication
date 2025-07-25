// services/refreshTokenService.js
import jwt from 'jsonwebtoken'
import { sql } from '../db.js'

/**
 * Stores a refresh token in the `tokens` table.
 * Uses PostgreSQL's ON CONFLICT to skip duplicates.
 */
export async function saveRefreshToken(token, userId) {
  // Decode without verifying, to read exp claim
  const decoded = jwt.decode(token)
  if (!decoded || typeof decoded.exp !== 'number') {
    throw new Error('Invalid token – no exp claim')
  }
  const expiresAt = new Date(decoded.exp * 1000).toISOString()

  try {
    await sql`
      INSERT INTO tokens (token, user_id, expires_at)
      VALUES (${token}, ${userId}, ${expiresAt})
      ON CONFLICT (token) DO NOTHING
    `
  } catch (err) {
    console.error('Error saving refresh token:', err)
    throw err
  }
}
