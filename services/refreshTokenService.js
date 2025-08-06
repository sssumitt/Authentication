import jwt from 'jsonwebtoken';
import { sql } from '../db.js';


export async function saveRefreshToken(token, userId) {
  try {
    const decoded = jwt.decode(token);
    const expiresAt = new Date(decoded.exp * 1000);
  
  

   await sql`
      INSERT INTO tokens (token, user_id, expires_at)
      VALUES (${token}, ${userId}, ${expiresAt})
    `;
  } catch (err) {
    if (err.code === '23505') {
      console.warn('Duplicate refresh token – skipping insert.');
    } else {
      throw err; 
    }
  }
}
