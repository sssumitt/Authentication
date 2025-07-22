import jwt from 'jsonwebtoken';
import { pool } from '../db.js';


export async function saveRefreshToken(token, userId) {
  try {
    const decoded = jwt.decode(token);
    const expiresAt = new Date(decoded.exp * 1000);

    await pool.execute(
      'INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)',
      [token, userId, expiresAt]
    );
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      console.warn('Duplicate refresh token – skipping insert.');
    } else {
      throw err; 
    }
  }
}
