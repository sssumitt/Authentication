// controllers/authController.js
import jwt        from 'jsonwebtoken';
import bcrypt     from 'bcrypt';
import { sql }    from '../db.js';
import config     from '../config/config.js';
import { saveRefreshToken, deleteRefreshToken } from '../services/refreshTokenService.js';
import { getGoogleAuthURL, getGoogleUser } from '../services/googleOAuthService.js';
import { issueTokensJSON } from '../services/tokenService.js';

/* ─────────────────── CSRF ─────────────────── */
export const getCsrfToken = (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
};

/* ─────────────────── REGISTER ─────────────────── */
export const registerUser = async (req, res) => {
  const { username, password } = req.body;
  try {
    const existing = await sql`SELECT id FROM users WHERE username = ${username}`;
    if (existing.length) {
      return res.status(409).json({ error: 'Username already taken' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    await sql`
      INSERT INTO users (username, password_hash)
      VALUES (${username}, ${passwordHash})
    `;
    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/* ─────────────────── LOGIN ─────────────────── */
export const loginUser = async (req, res) => {
  const { username, password } = req.body;
  try {
    const rows = await sql`
      SELECT id, password_hash
      FROM users
      WHERE username = ${username}
    `;
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { accessToken, refreshToken } = issueTokensJSON(res, { username });
    await saveRefreshToken(refreshToken, user.id);

    res.json({ accessToken });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/* ─────────────────── REFRESH ─────────────────── */
export const refreshToken = async (req, res) => {
  const oldToken = req.cookies.refresh_token;
  if (!oldToken) {
    return res.status(401).json({ error: 'Missing refresh token' });
  }

  try {
    /* 1) Make sure we issued this token */
    const rows = await sql`
      SELECT user_id FROM tokens WHERE token = ${oldToken}
    `;
    if (!rows.length) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    /* 2) Verify signature / expiry */
    let payload;
    try {
      payload = jwt.verify(oldToken, config.publicKey, { algorithms: ['RS256'] });
    } catch {
      await deleteRefreshToken(oldToken);
      return res.status(401).json({ error: 'Expired or malformed token' });
    }

    /* 3) Rotate: delete old, issue new */
    await deleteRefreshToken(oldToken);

    const { accessToken, refreshToken } = issueTokensJSON(res, { username: payload.username });
    await saveRefreshToken(refreshToken, rows[0].user_id);

    res.json({ accessToken });
  } catch (err) {
    console.error('Refresh error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/* ─────────────────── LOGOUT ─────────────────── */
export const logoutUser = async (req, res) => {
  const rt = req.cookies.refresh_token;
  if (rt) {
    await deleteRefreshToken(rt);
  }
  res.clearCookie('refresh_token', { path: '/auth/refresh' });
  res.json({ message: 'Logged out' });
};

/* ─────────────────── GOOGLE OAUTH ─────────────────── */
export const googleAuth = (_req, res) => {
  res.redirect(getGoogleAuthURL());
};

export const googleCallback = async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('Missing code from Google');

  try {
    const { email, sub } = await getGoogleUser(code);

    /* find or create user */
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

    /* issue tokens */
    const { accessToken, refreshToken } = issueTokensJSON(res, { username: email });
    await saveRefreshToken(refreshToken, userId);

    /* redirect to front‑end */
    const frontend = process.env.FRONTEND_URL.replace(/\/+$/, '');
    res.redirect(`${frontend}/dashboard?token=${accessToken}`); // or handle via memory on SPA load
  } catch (err) {
    console.error('Google callback error:', err);
    res.status(500).send('Authentication failed.');
  }
};
