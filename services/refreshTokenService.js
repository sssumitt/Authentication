// services/refreshTokenService.js
import jwt from 'jsonwebtoken';
import { sql } from '../db.js';

/* ──────────────────────────────────────────────────────────────── */
/* saveRefreshToken                                                 */
/* ──────────────────────────────────────────────────────────────── */
export async function saveRefreshToken(token, userId) {
  /* 1) Decode w/out verifying – just to read exp */
  const decoded = jwt.decode(token);
  if (!decoded || typeof decoded.exp !== 'number') {
    throw new Error('Invalid token – no exp claim');
  }
  const expiresAt = new Date(decoded.exp * 1000).toISOString();

  /* 2) Insert; ignore duplicates (ON CONFLICT) */
  try {
    await sql`
      INSERT INTO tokens (token, user_id, expires_at)
      VALUES (${token}, ${userId}, ${expiresAt})
      ON CONFLICT (token) DO NOTHING
    `;
  } catch (err) {
    console.error('Error saving refresh token:', err);
    throw err;
  }
}

/* ──────────────────────────────────────────────────────────────── */
/* deleteRefreshToken                                               */
/* ──────────────────────────────────────────────────────────────── */
export async function deleteRefreshToken(token) {
  try {
    await sql`DELETE FROM tokens WHERE token = ${token}`;
  } catch (err) {
    console.error('Error deleting refresh token:', err);
    // don’t throw – logout should still succeed even if DB clean‑up fails
  }
}

/* ──────────────────────────────────────────────────────────────── */
/* pruneExpiredTokens  (optional; call from a daily cron)          */
/* ──────────────────────────────────────────────────────────────── */
export async function pruneExpiredTokens() {
  try {
    await sql`
      DELETE FROM tokens
      WHERE expires_at < NOW()
    `;
  } catch (err) {
    console.error('Error pruning tokens:', err);
  }
}
