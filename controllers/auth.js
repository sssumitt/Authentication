import jwt from 'jsonwebtoken';
import bcrypt, { compareSync } from 'bcrypt';
import { sql  } from '../db.js';
import config from '../config/config.js';
import { issueTokens } from '../services/tokenService.js';
import { saveRefreshToken } from '../services/refreshTokenService.js';
import { getGoogleAuthURL, getGoogleUser } from '../services/googleOAuthService.js';


/**
 * GET CSRF token
 * Sends a JSON response with the CSRF token for the client to use in subsequent requests.
 */
export const getCsrfToken = (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
};

/**
 * Register a new user
 */
export const registerUser = async (req, res) => {
  const { username, password } = req.body;

  try {
    const existing = await sql`
    SELECT id FROM users WHERE username = ${username}
    `;

    if (existing.length > 0) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    
    await sql`
      INSERT INTO users (username, password_hash) VALUES (${username}, ${passwordHash})
    `;

    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    console.error('Register DB error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Log in an existing user
 * After successful login, issues tokens and returns a fresh CSRF token.
 */
export const loginUser = async (req, res) => {
  const { username, password } = req.body;


  try {
    const rows = await sql`
      SELECT id, username, password_hash FROM users WHERE username = ${username}
    `;
    const user = rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { accessToken, refreshToken } = issueTokens(res, { username });
    console.log('Access token:', accessToken);
    console.log('Refresh token:', refreshToken);
    await saveRefreshToken(refreshToken, user.id);

    res.json({ csrfToken: req.csrfToken() });
  } catch (err) {
    console.error('Login DB error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Refresh JWT tokens and rotate the refresh token
 */

export const refreshToken = async (req, res) => {
  const oldToken = req.cookies.refresh_token;
  console.log('Refresh token:', oldToken);
  if (!oldToken) {
    return res.status(401).json({ error: 'Missing refresh token' });
  }

  try {
    const rows = await sql`
      SELECT user_id FROM refresh_tokens WHERE token = ${oldToken}
    `;
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    const userId = rows[0].user_id;

    let payload;
    try {
      payload = jwt.verify(oldToken, config.publicKey, { algorithms: ['RS256'] });
    } catch {
      await sql`DELETE FROM refresh_tokens WHERE token = ${oldToken}`;
      return res.status(401).json({ error: 'Expired or malformed token' });
    }

    await sql`DELETE FROM refresh_tokens WHERE token = ${oldToken}`;

    const { accessToken, refreshToken: newRefresh } = issueTokens(res, { username: payload.username });

    await saveRefreshToken(newRefresh, userId);

    res.json({ csrfToken: req.csrfToken() });
  } catch (err) {
    console.error('Refresh error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Log out the user by removing the refresh token and clearing cookies
 */
export const logoutUser = async (req, res) => {
  const token = req.cookies.refresh_token;
  console.log('Logout token:', token);

  if (token) {
    try {
      await sql`DELETE FROM refresh_tokens WHERE token = ${token}`;
    } catch (err) {
      console.error('Logout DB error:', err);
    }
  } else {
    console.warn('No refresh token found in cookies.');
  }

  res.clearCookie('access_token');
  res.clearCookie('refresh_token', { path: '/auth/refresh' });
  res.json({ message: 'Logged out' });
};



/**
 * Redirect to Google OAuth consent page
 */

export const googleAuth = (req, res) => {
  res.redirect(getGoogleAuthURL());    
}


export const googleCallback = async (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.status(400).send('Missing ?code query param from Google');
  }

  try {
    console.log('Exchanging code for tokens...');
    const { email, sub } = await getGoogleUser(code);
    console.log('Google user:', { email, sub });

    // check user or insert
  let userId;

  try {
      // Try finding by Google ID first
      const byGoogleId = await sql`
        SELECT id FROM users WHERE google_id = ${sub}
      `;

      if (byGoogleId.length > 0) {
        userId = byGoogleId[0].id;
      } else {
        // Check if user already exists by email (e.g., registered with password)
        const byUsername = await sql`
          SELECT id FROM users WHERE username = ${email}
        `;

        if (byUsername.length > 0) {
          // User exists, link Google ID to existing account
          userId = byUsername[0].id;
          await sql`
            UPDATE users SET google_id = ${sub} WHERE id = ${userId}
          `;
        } else {
          // User doesn't exist — create new one
          const result = await sql`
            INSERT INTO users (username, google_id) VALUES (${email}, ${sub})
            RETURNING id
          `;
          userId = result[0].id;
        }
      }
    } catch (err) {
      console.error('DB error during Google login:', err);
      throw new Error('Database error during Google user lookup/insert');
    }

    // issue JWTs and cookies
    const { accessToken, refreshToken } = issueTokens(res, { username: email });
    await saveRefreshToken(refreshToken, userId);

    console.log('User authenticated. Redirecting...');
    res.redirect(`${process.env.FRONTEND_URL}/?oauth=success`);
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.status(500).send('Authentication failed.');
  }
};
