// controllers/authController.js

import jwt     from 'jsonwebtoken'
import bcrypt  from 'bcrypt'
import { sql } from '../db.js'
import config  from '../config/config.js'
import { issueTokens } from '../services/tokenService.js'
import { saveRefreshToken } from '../services/refreshTokenService.js'
import { getGoogleAuthURL, getGoogleUser } from '../services/googleOAuthService.js'

/** GET CSRF token */
export const getCsrfToken = (req, res) => {
  res.json({ csrfToken: req.csrfToken() })
}

/** REGISTER */
export const registerUser = async (req, res) => {
  const { username, password } = req.body
  try {
    const existing = await sql`SELECT id FROM users WHERE username = ${username}`
    if (existing.length) {
      return res.status(409).json({ error: 'Username already taken' })
    }
    const passwordHash = await bcrypt.hash(password, 10)
    await sql`
      INSERT INTO users (username, password_hash)
      VALUES (${username}, ${passwordHash})
    `
    res.status(201).json({ message: 'User registered' })
  } catch (err) {
    console.error('Register error:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
}

/** LOGIN */
export const loginUser = async (req, res) => {
  const { username, password } = req.body
  try {
    const users = await sql`
      SELECT id, username, password_hash
      FROM users
      WHERE username = ${username}
    `
    const user = users[0]
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    const { accessToken, refreshToken } = issueTokens(res, { username })
    await saveRefreshToken(refreshToken, user.id)
    res.json({ csrfToken: req.csrfToken() })
  } catch (err) {
    console.error('Login error:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
}

/** REFRESH */
export const refreshToken = async (req, res) => {
  const oldToken = req.cookies.refresh_token
  if (!oldToken) {
    return res.status(401).json({ error: 'Missing refresh token' })
  }
  try {
    const rows = await sql`
      SELECT user_id
      FROM tokens
      WHERE token = ${oldToken}
    `
    if (!rows.length) {
      return res.status(401).json({ error: 'Invalid refresh token' })
    }
    const userId = rows[0].user_id

    let payload
    try {
      payload = jwt.verify(oldToken, config.publicKey, { algorithms: ['RS256'] })
    } catch {
      // malformed or expired → delete and bail
      await sql`DELETE FROM tokens WHERE token = ${oldToken}`
      return res.status(401).json({ error: 'Expired or malformed token' })
    }

    // remove the old refresh token
    await sql`DELETE FROM tokens WHERE token = ${oldToken}`

    // issue new tokens
    const { accessToken, refreshToken: newRefresh } =
      issueTokens(res, { username: payload.username })
    await saveRefreshToken(newRefresh, userId)

    res.json({ csrfToken: req.csrfToken() })
  } catch (err) {
    console.error('Refresh error:', err)
    res.status(500).json({ error: 'Internal server error' })
  }
}

/** LOGOUT */
export const logoutUser = async (req, res) => {
  const token = req.cookies.refresh_token
  if (token) {
    try {
      await sql`DELETE FROM tokens WHERE token = ${token}`
    } catch (err) {
      console.error('Logout DB error:', err)
    }
  } else {
    console.warn('No refresh token cookie found on logout')
  }
  res.clearCookie('access_token')
  res.clearCookie('refresh_token', { path: '/auth/refresh' })
  res.json({ message: 'Logged out' })
}

/** GOOGLE OAUTH: redirect */
export const googleAuth = (req, res) => {
  res.redirect(getGoogleAuthURL())
}

/** GOOGLE OAUTH: callback */
/** GOOGLE OAUTH: callback */
export const googleCallback = async (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.status(400).send('Missing code from Google');
  }

  try {
    const { email, sub } = await getGoogleUser(code);

    // find or create user
    const byGoogle = await sql`SELECT id FROM users WHERE google_id = ${sub}`;
    let userId;
    if (byGoogle.length) {
      userId = byGoogle[0].id;
    } else {
      const byEmail = await sql`SELECT id FROM users WHERE username = ${email}`;
      if (byEmail.length) {
        userId = byEmail[0].id;
        await sql`UPDATE users SET google_id = ${sub} WHERE id = ${userId}`;
      } else {
        const insert = await sql`
          INSERT INTO users (username, google_id)
          VALUES (${email}, ${sub})
          RETURNING id
        `;
        userId = insert[0].id;
      }
    }

    // issue tokens (sets cookies)
    const { accessToken, refreshToken } = issueTokens(res, { username: email });
    await saveRefreshToken(refreshToken, userId);

    // redirect to frontend dashboard
    const frontend = (process.env.FRONTEND_UR).replace(/\/+$/, '');
    res.redirect(`${frontend}/dashboard`);
  } catch (err) {
    console.error('Google callback error:', err);
    res.status(500).send('Authentication failed.');
  }
};
